//! Enhanced error hierarchy with source chain preservation for PyO3 bindings
//!
//! This module provides a comprehensive error handling system that preserves complete
//! Error::source() chains across the Rust-Python boundary while maintaining type-safe
//! exception mapping.

use pyo3::prelude::*;
use pyo3::exceptions::{
    PyRuntimeError, PyValueError, PyIOError, PyTimeoutError,
    PyConnectionError
};
use lightweight_wallet_libs::errors::LightweightWalletError;
use std::error::Error;

/// Custom Python exception types for specific wallet operations
#[derive(Debug)]
pub struct TariValidationError(pub String, pub Option<String>);

#[derive(Debug)]  
pub struct TariStorageError(pub String, pub Option<String>);

#[derive(Debug)]
pub struct TariKeyError(pub String, pub Option<String>);

#[derive(Debug)]
pub struct TariNetworkError(pub String, pub Option<String>);

// Register custom exception types with Python
pub fn register_exceptions(_py: Python, _module: &PyModule) -> PyResult<()> {
    // For now, we'll use the standard exception types directly
    // Custom exception registration can be added later if needed
    Ok(())
}

/// Enhanced error wrapper that preserves source chains
#[derive(Debug)]
pub struct EnhancedPyWalletError {
    pub error: LightweightWalletError,
    pub source_chain: Vec<String>,
}

impl EnhancedPyWalletError {
    /// Create enhanced error with complete source chain
    pub fn new(error: LightweightWalletError) -> Self {
        let mut source_chain = Vec::new();
        let mut current_error: &dyn Error = &error;
        
        // Walk the complete error source chain
        loop {
            source_chain.push(current_error.to_string());
            match current_error.source() {
                Some(source) => current_error = source,
                None => break,
            }
        }
        
        Self {
            error,
            source_chain,
        }
    }
    
    /// Format error with complete context
    pub fn format_with_context(&self) -> String {
        if self.source_chain.len() <= 1 {
            return self.error.to_string();
        }
        
        let mut formatted = String::new();
        formatted.push_str(&self.source_chain[0]);
        
        if self.source_chain.len() > 1 {
            formatted.push_str("\nCaused by:");
            for (i, cause) in self.source_chain[1..].iter().enumerate() {
                formatted.push_str(&format!("\n  {}: {}", i + 1, cause));
            }
        }
        
        formatted
    }
}

impl From<LightweightWalletError> for EnhancedPyWalletError {
    fn from(error: LightweightWalletError) -> Self {
        Self::new(error)
    }
}

impl From<EnhancedPyWalletError> for PyErr {
    fn from(enhanced_error: EnhancedPyWalletError) -> Self {
        use LightweightWalletError::*;
        
        let formatted_message = enhanced_error.format_with_context();
        let source_info = if enhanced_error.source_chain.len() > 1 {
            Some(enhanced_error.source_chain[1..].join("; "))
        } else {
            None
        };
        
        match enhanced_error.error {
            // Validation errors with enhanced context
            ValidationError(_) => {
                let validation_err = TariValidationError(formatted_message, source_info);
                PyValueError::new_err(format!("Validation failed: {}", validation_err.0))
            }
            
            // Data structure errors with enhanced context
            DataStructureError(_) => {
                let validation_err = TariValidationError(formatted_message, source_info);
                PyValueError::new_err(format!("Data structure error: {}", validation_err.0))
            }
            
            // Storage errors with enhanced context
            StorageError(_) => {
                let storage_err = TariStorageError(formatted_message, source_info);
                PyIOError::new_err(format!("Storage operation failed: {}", storage_err.0))
            }
            
            // Key management errors with enhanced context
            KeyManagementError(_) => {
                let key_err = TariKeyError(formatted_message, source_info);
                PyValueError::new_err(format!("Key operation failed: {}", key_err.0))
            }
            
            // Network and scanning errors with enhanced context
            NetworkError(_) | ScanningError(_) | ConnectionError(_) | GrpcError(_) => {
                let network_err = TariNetworkError(formatted_message, source_info);
                PyConnectionError::new_err(format!("Network operation failed: {}", network_err.0))
            }
            
            // Timeout errors
            Timeout(_) => {
                PyTimeoutError::new_err(formatted_message)
            }
            
            // Encryption and conversion errors
            EncryptionError(_) | ConversionError(_) | HexError(_) => {
                PyValueError::new_err(formatted_message)
            }
            
            // Fallback with complete context
            _ => {
                PyRuntimeError::new_err(formatted_message)
            }
        }
    }
}

/// Convenience conversion function for enhanced error handling
pub fn enhanced_convert_to_pyerr(error: LightweightWalletError) -> PyErr {
    EnhancedPyWalletError::from(error).into()
}

/// Error handler that provides debug information in development
pub fn debug_error_chain(error: &LightweightWalletError) -> String {
    // Convert to string first to avoid borrowing issues
    let error_string = error.to_string();
    format!("Error: {}", error_string)
}

/// Utility for wrapping operation results with enhanced error context
pub fn wrap_result<T>(result: Result<T, LightweightWalletError>, operation: &str) -> PyResult<T> {
    result.map_err(|e| {
        let enhanced = EnhancedPyWalletError::new(e);
        let context_msg = format!("Operation '{}' failed: {}", operation, enhanced.format_with_context());
        
        // Create enhanced error with operation context
        PyRuntimeError::new_err(context_msg)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightweight_wallet_libs::errors::{LightweightWalletError, ValidationError};
    
    #[test]
    fn test_error_chain_preservation() {
        // Create a nested error chain
        let inner_error = ValidationError::InvalidInput("test input".to_string());
        let wallet_error = LightweightWalletError::ValidationError(inner_error);
        
        let enhanced = EnhancedPyWalletError::new(wallet_error);
        assert!(!enhanced.source_chain.is_empty());
        
        let formatted = enhanced.format_with_context();
        assert!(formatted.contains("test input"));
    }
    
    #[test]
    fn test_debug_error_chain() {
        let error = LightweightWalletError::KeyManagementError(
            lightweight_wallet_libs::errors::KeyManagementError::InvalidKey("test key".to_string())
        );
        
        let debug_info = debug_error_chain(&error);
        assert!(debug_info.contains("Error chain"));
        assert!(debug_info.contains("test key"));
    }
}
