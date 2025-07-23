//! Shared runtime and connection pooling for Python bindings
//! 
//! This module provides a singleton tokio runtime and reusable HTTP connections
//! to eliminate the overhead of creating new threads and connections for each operation.

use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use once_cell::sync::Lazy;
use pyo3::exceptions::PyRuntimeError;
use pyo3::PyResult;
use lightweight_wallet_libs::scanning::HttpBlockchainScanner;
use lightweight_wallet_libs::errors::LightweightWalletError;
use std::future::Future;
use std::collections::HashMap;

/// Global shared tokio runtime for all async operations
static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    Runtime::new().expect("Failed to create tokio runtime")
});

/// Connection pool for HTTP scanners keyed by base URL
static SCANNER_POOL: Lazy<Arc<Mutex<HashMap<String, Arc<Mutex<HttpBlockchainScanner>>>>>> = 
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Execute an async future on the shared runtime
pub fn execute_async<F, R>(future: F) -> PyResult<R>
where
    F: Future<Output = Result<R, LightweightWalletError>>,
{
    RUNTIME.block_on(future)
        .map_err(|e| PyRuntimeError::new_err(format!("Runtime error: {}", e)))
}

/// Get or create a scanner for the given base URL
pub async fn get_or_create_scanner(base_url: &str) -> Result<Arc<Mutex<HttpBlockchainScanner>>, LightweightWalletError> {
    let url_key = base_url.to_string();
    
    // Check if we already have a scanner for this URL
    {
        let pool = SCANNER_POOL.lock()
            .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner pool".into()))?;
        
        if let Some(scanner) = pool.get(&url_key) {
            return Ok(Arc::clone(scanner));
        }
    }
    
    // Create new scanner if not found
    let new_scanner = HttpBlockchainScanner::new(url_key.clone()).await?;
    let arc_scanner = Arc::new(Mutex::new(new_scanner));
    
    // Add to pool
    {
        let mut pool = SCANNER_POOL.lock()
            .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner pool".into()))?;
        pool.insert(url_key, Arc::clone(&arc_scanner));
    }
    
    Ok(arc_scanner)
}

/// Clear the scanner pool (useful for testing or when URLs change)
#[allow(dead_code)]
pub fn clear_scanner_pool() -> PyResult<()> {
    let mut pool = SCANNER_POOL.lock()
        .map_err(|_| PyRuntimeError::new_err("Failed to lock scanner pool"))?;
    pool.clear();
    Ok(())
}

/// Get pool statistics for monitoring
#[allow(dead_code)]
pub fn get_pool_stats() -> PyResult<(usize, Vec<String>)> {
    let pool = SCANNER_POOL.lock()
        .map_err(|_| PyRuntimeError::new_err("Failed to lock scanner pool"))?;
    
    let count = pool.len();
    let urls: Vec<String> = pool.keys().cloned().collect();
    
    Ok((count, urls))
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
    }
}
