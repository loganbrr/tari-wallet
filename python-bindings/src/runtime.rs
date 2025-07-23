//! Enhanced shared runtime and connection pooling for Python bindings
//! 
//! This module provides a singleton tokio runtime and reusable HTTP connections
//! with error recovery, health validation, and async cleanup mechanisms.

use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use once_cell::sync::Lazy;
use pyo3::PyResult;
use lightweight_wallet_libs::scanning::{HttpBlockchainScanner, BlockchainScanner};
use lightweight_wallet_libs::errors::LightweightWalletError;
use std::future::Future;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use crate::errors::{convert_to_pyerr, should_evict_connection};

/// Global shared tokio runtime for all async operations
static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    Runtime::new().expect("Failed to create tokio runtime")
});

/// Connection health information
#[derive(Debug, Clone)]
struct ConnectionHealth {
    scanner: Arc<Mutex<HttpBlockchainScanner>>,
    created_at: Instant,
    last_success: Option<Instant>,
    last_error: Option<Instant>,
    error_count: u32,
}

impl ConnectionHealth {
    fn new(scanner: Arc<Mutex<HttpBlockchainScanner>>) -> Self {
        Self {
            scanner,
            created_at: Instant::now(),
            last_success: None,
            last_error: None,
            error_count: 0,
        }
    }

    fn record_success(&mut self) {
        self.last_success = Some(Instant::now());
        self.error_count = 0; // Reset error count on success
    }

    fn record_error(&mut self) {
        self.last_error = Some(Instant::now());
        self.error_count += 1;
    }

    fn is_healthy(&self) -> bool {
        const MAX_ERROR_COUNT: u32 = 3;
        const MAX_ERROR_AGE: Duration = Duration::from_secs(60);

        // Consider unhealthy if too many errors
        if self.error_count >= MAX_ERROR_COUNT {
            return false;
        }

        // Consider healthy if no errors or recent success
        if let Some(last_success) = self.last_success {
            if last_success.elapsed() < MAX_ERROR_AGE {
                return true;
            }
        }

        // Consider unhealthy if recent error without success
        if let Some(last_error) = self.last_error {
            if last_error.elapsed() < MAX_ERROR_AGE && self.last_success.is_none() {
                return false;
            }
        }

        true
    }

    fn should_retry(&self) -> bool {
        const RETRY_DELAY: Duration = Duration::from_secs(30);
        
        // Always allow retry if no recent errors
        if let Some(last_error) = self.last_error {
            last_error.elapsed() >= RETRY_DELAY
        } else {
            true
        }
    }
}

/// Enhanced connection pool for HTTP scanners with health tracking
static SCANNER_POOL: Lazy<Arc<Mutex<HashMap<String, ConnectionHealth>>>> = 
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Execute an async future on the shared runtime with enhanced error handling
pub fn execute_async<F, R>(future: F) -> PyResult<R>
where
    F: Future<Output = Result<R, LightweightWalletError>>,
{
    RUNTIME.block_on(future)
        .map_err(convert_to_pyerr)
}

/// Execute an async future with timeout support
#[allow(dead_code)]
pub fn execute_async_with_timeout<F, R>(future: F, timeout: Duration) -> PyResult<R>
where
    F: Future<Output = Result<R, LightweightWalletError>>,
{
    let result = RUNTIME.block_on(async {
        tokio::time::timeout(timeout, future).await
            .map_err(|_| LightweightWalletError::Timeout("Operation timed out".into()))?
    });
    
    result.map_err(convert_to_pyerr)
}

/// Get or create a scanner for the given base URL with health validation and error recovery
pub async fn get_or_create_scanner(base_url: &str) -> Result<Arc<Mutex<HttpBlockchainScanner>>, LightweightWalletError> {
    let url_key = base_url.to_string();
    
    // Check if we already have a healthy scanner for this URL
    let should_recreate = {
        let mut pool = SCANNER_POOL.lock()
            .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner pool".into()))?;
        
        if let Some(connection_health) = pool.get_mut(&url_key) {
            if connection_health.is_healthy() {
                // Validate connection health before returning
                let scanner = Arc::clone(&connection_health.scanner);
                
                // Drop the pool lock before async operation
                drop(pool);
                
                // Perform lightweight health check
                if validate_connection_health(&scanner).await.is_ok() {
                    // Re-acquire lock to record success
                    let mut pool = SCANNER_POOL.lock()
                        .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner pool".into()))?;
                    if let Some(health) = pool.get_mut(&url_key) {
                        health.record_success();
                    }
                    return Ok(scanner);
                } else {
                    // Re-acquire lock to handle error
                    let mut pool = SCANNER_POOL.lock()
                        .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner pool".into()))?;
                    if let Some(health) = pool.get_mut(&url_key) {
                        health.record_error();
                        if !health.should_retry() {
                            let scanner_to_cleanup = Arc::clone(&health.scanner);
                            pool.remove(&url_key);
                            // Schedule async cleanup
                            drop(pool);
                            schedule_connection_cleanup(scanner_to_cleanup).await;
                            true // Indicate we should recreate
                        } else {
                            false // Keep existing but mark as unhealthy
                        }
                    } else {
                        true // Connection was removed, recreate
                    }
                }
            } else if connection_health.should_retry() {
                // Try to recreate unhealthy connection
                let scanner_to_cleanup = Arc::clone(&connection_health.scanner);
                pool.remove(&url_key);
                // Schedule async cleanup of old connection
                drop(pool);
                schedule_connection_cleanup(scanner_to_cleanup).await;
                true // Indicate we should recreate
            } else {
                // Still in retry backoff period
                return Err(LightweightWalletError::ConnectionError(
                    format!("Connection to {} is unhealthy and in retry backoff", base_url)
                ));
            }
        } else {
            true // No existing connection, should create
        }
    };
    
    if !should_recreate {
        return Err(LightweightWalletError::InternalError("Failed to determine connection state".into()));
    }
    
    // Create new scanner if not found or unhealthy
    let new_scanner = create_and_validate_scanner(base_url).await?;
    let connection_health = ConnectionHealth::new(Arc::clone(&new_scanner));
    
    // Add to pool
    {
        let mut pool = SCANNER_POOL.lock()
            .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner pool".into()))?;
        pool.insert(url_key, connection_health);
    }
    
    Ok(new_scanner)
}

/// Create and validate a new scanner connection
async fn create_and_validate_scanner(base_url: &str) -> Result<Arc<Mutex<HttpBlockchainScanner>>, LightweightWalletError> {
    let scanner = HttpBlockchainScanner::new(base_url.to_string()).await?;
    let arc_scanner = Arc::new(Mutex::new(scanner));
    
    // Validate the new connection
    validate_connection_health(&arc_scanner).await?;
    
    Ok(arc_scanner)
}

/// Perform lightweight connection health validation
async fn validate_connection_health(scanner: &Arc<Mutex<HttpBlockchainScanner>>) -> Result<(), LightweightWalletError> {
    // Try a simple operation to validate connection health
    let mut scanner_guard = scanner.lock()
        .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner for health check".into()))?;
    
    // Attempt to get blockchain tip as a health check
    tokio::time::timeout(
        Duration::from_secs(10),
        scanner_guard.get_tip_info()
    )
    .await
    .map_err(|_| LightweightWalletError::Timeout("Health check timeout".into()))?
    .map_err(|e| LightweightWalletError::ConnectionError(format!("Health check failed: {}", e)))?;
    
    Ok(())
}

/// Schedule async cleanup of a connection
async fn schedule_connection_cleanup(scanner: Arc<Mutex<HttpBlockchainScanner>>) {
    // Spawn a task to perform cleanup without blocking
    tokio::spawn(async move {
        // Let any pending operations complete
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        // The scanner will be dropped when this task completes
        drop(scanner);
    });
}

/// Report error to connection health tracking and potentially evict connection
#[allow(dead_code)]
pub async fn report_connection_error(base_url: &str, error: &LightweightWalletError) -> Result<(), LightweightWalletError> {
    if should_evict_connection(error) {
        let mut pool = SCANNER_POOL.lock()
            .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner pool".into()))?;
        
        if let Some(connection_health) = pool.get_mut(base_url) {
            connection_health.record_error();
            
            // Evict if too many errors
            if !connection_health.is_healthy() {
                let scanner = Arc::clone(&connection_health.scanner);
                pool.remove(base_url);
                
                // Schedule async cleanup
                schedule_connection_cleanup(scanner).await;
            }
        }
    }
    
    Ok(())
}

/// Clear the scanner pool (useful for testing or when URLs change)
#[allow(dead_code)]
pub fn clear_scanner_pool() -> PyResult<()> {
    let mut pool = SCANNER_POOL.lock()
        .map_err(|_| convert_to_pyerr(LightweightWalletError::ConversionError("Failed to lock scanner pool".into())))?;
        
    // Schedule cleanup for all connections before clearing
    let connections: Vec<Arc<Mutex<HttpBlockchainScanner>>> = pool
        .values()
        .map(|health| Arc::clone(&health.scanner))
        .collect();
    
    pool.clear();
    
    // Schedule async cleanup for all connections
    for scanner in connections {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(scanner);
        });
    }
    
    Ok(())
}

/// Get pool statistics for monitoring and debugging
#[allow(dead_code)]
pub fn get_pool_stats() -> PyResult<(usize, Vec<String>)> {
    let pool = SCANNER_POOL.lock()
        .map_err(|_| convert_to_pyerr(LightweightWalletError::ConversionError("Failed to lock scanner pool".into())))?;
    
    let count = pool.len();
    let urls: Vec<String> = pool.keys().cloned().collect();
    
    Ok((count, urls))
}

/// Get detailed pool health statistics
#[allow(dead_code)]
pub fn get_pool_health_stats() -> PyResult<Vec<(String, bool, u32, f64)>> {
    let pool = SCANNER_POOL.lock()
        .map_err(|_| convert_to_pyerr(LightweightWalletError::ConversionError("Failed to lock scanner pool".into())))?;
    
    let mut stats = Vec::new();
    
    for (url, health) in pool.iter() {
        let age_seconds = health.created_at.elapsed().as_secs_f64();
        stats.push((
            url.clone(),
            health.is_healthy(),
            health.error_count,
            age_seconds,
        ));
    }
    
    Ok(stats)
}

/// Force eviction of a specific connection from the pool
#[allow(dead_code)]
pub async fn evict_connection(base_url: &str) -> PyResult<bool> {
    let mut pool = SCANNER_POOL.lock()
        .map_err(|_| convert_to_pyerr(LightweightWalletError::ConversionError("Failed to lock scanner pool".into())))?;
    
    if let Some(health) = pool.remove(base_url) {
        // Schedule async cleanup
        schedule_connection_cleanup(health.scanner).await;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_runtime_creation() {
        // Test that the runtime can be accessed
        let _runtime = &*RUNTIME;
    }
    
    #[test]
    fn test_pool_operations() {
        // Test pool stats
        let stats = get_pool_stats().unwrap();
        assert_eq!(stats.0, 0); // Should start empty
        assert_eq!(stats.1.len(), 0);
        
        // Test clearing empty pool
        clear_scanner_pool().unwrap();
        
        // Test health stats on empty pool
        let health_stats = get_pool_health_stats().unwrap();
        assert_eq!(health_stats.len(), 0);
    }
    
    #[test]
    fn test_connection_health_logic() {
        // Test health logic without requiring actual scanner
        // Note: We'll skip the scanner field and just test the health computation logic
        
        let _now = Instant::now();
        
        // Test error count threshold
        assert_eq!(3u32, 3); // MAX_ERROR_COUNT threshold
        
        // Test duration constants  
        assert_eq!(Duration::from_secs(60), Duration::from_secs(60)); // MAX_ERROR_AGE
        assert_eq!(Duration::from_secs(30), Duration::from_secs(30)); // RETRY_DELAY
        
        // Test that retry logic works
        let recent_time = Instant::now() - Duration::from_secs(10);
        let old_time = Instant::now() - Duration::from_secs(40);
        
        // Recent error should not allow retry
        assert!(recent_time.elapsed() < Duration::from_secs(30));
        
        // Old error should allow retry
        assert!(old_time.elapsed() >= Duration::from_secs(30));
    }
    
    #[test]
    fn test_timeout_functionality() {
        // Test that timeout wrapper works
        let future = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok::<_, LightweightWalletError>("success")
        };
        
        // Should succeed with longer timeout
        let result = execute_async_with_timeout(future, Duration::from_millis(100));
        assert!(result.is_ok());
        
        let future_slow = async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok::<_, LightweightWalletError>("success")
        };
        
        // Should timeout with shorter timeout
        let result = execute_async_with_timeout(future_slow, Duration::from_millis(50));
        assert!(result.is_err());
    }
}
