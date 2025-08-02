//! Error handling for Python bindings
//!
//! This module provides both legacy error handling for backward compatibility
//! and enhanced error handling with source chain preservation.

use pyo3::prelude::*;
use pyo3::exceptions::{
    PyRuntimeError, PyValueError, PyIOError, PyTimeoutError,
    PyConnectionError
};
use lightweight_wallet_libs::errors::LightweightWalletError;
use std::sync::PoisonError;

// Re-export enhanced error handling
pub use crate::error_hierarchy::{
    EnhancedPyWalletError, TariValidationError, TariStorageError, 
    TariKeyError, TariNetworkError, enhanced_convert_to_pyerr,
    debug_error_chain, wrap_result, register_exceptions
};

/// PyO3 best practice error wrapper to circumvent orphan rules
/// 
/// This newtype wrapper allows us to implement From<PyWalletError> for PyErr
/// while avoiding orphan rule violations. It preserves error context and
/// provides appropriate Python exception type mapping.
#[derive(Debug)]
pub struct PyWalletError(pub LightweightWalletError);

impl From<LightweightWalletError> for PyWalletError {
    fn from(err: LightweightWalletError) -> Self {
        PyWalletError(err)
    }
}

impl From<PyWalletError> for PyErr {
    fn from(err: PyWalletError) -> Self {
        use LightweightWalletError::*;
        
        match err.0 {
            // Data structure errors -> ValueError
            DataStructureError(ref e) => {
                PyValueError::new_err(format!("Data structure error: {}", e))
            }
            
            // Validation errors -> ValueError  
            ValidationError(ref e) => {
                PyValueError::new_err(format!("Validation error: {}", e))
            }
            
            // Storage errors -> IOError
            StorageError(ref e) => {
                PyIOError::new_err(format!("Storage error: {}", e))
            }
            
            // Scanning errors -> ConnectionError
            ScanningError(ref e) => {
                PyConnectionError::new_err(format!("Scanning error: {}", e))
            }
            
            // Key management errors -> ValueError (sensitive data handling)
            KeyManagementError(ref e) => {
                PyValueError::new_err(format!("Key management error: {}", e))
            }
            
            // Encryption errors -> ValueError
            EncryptionError(ref e) => {
                PyValueError::new_err(format!("Encryption error: {}", e))
            }
            
            // Network errors -> ConnectionError
            NetworkError(ref e) => {
                PyConnectionError::new_err(format!("Network error: {}", e))
            }
            
            // Timeout errors -> TimeoutError
            Timeout(ref e) => {
                PyTimeoutError::new_err(format!("Timeout error: {}", e))
            }
            
            // Conversion errors -> ValueError
            ConversionError(ref e) => {
                PyValueError::new_err(format!("Conversion error: {}", e))
            }
            
            // Connection errors -> ConnectionError
            ConnectionError(ref e) => {
                PyConnectionError::new_err(format!("Connection error: {}", e))
            }
            
            // gRPC errors -> ConnectionError
            GrpcError(ref e) => {
                PyConnectionError::new_err(format!("gRPC error: {}", e))
            }
            
            // Hex errors -> ValueError
            HexError(ref e) => {
                PyValueError::new_err(format!("Hex error: {}", e))
            }
            
            // Fallback for any unhandled variants -> RuntimeError
            _ => {
                PyRuntimeError::new_err(format!("Wallet error: {}", err.0))
            }
        }
    }
}

/// Convenience wrapper for hex decode errors
#[derive(Debug)]
pub struct PyHexError(pub hex::FromHexError);

impl From<hex::FromHexError> for PyHexError {
    fn from(err: hex::FromHexError) -> Self {
        PyHexError(err)
    }
}

impl From<PyHexError> for PyErr {
    fn from(err: PyHexError) -> Self {
        PyValueError::new_err(format!("Hex decode error: {}", err.0))
    }
}

/// Shared utility for mutex lock failures across all modules
pub fn lock_error<T>(operation: &str) -> impl Fn(PoisonError<T>) -> PyErr + '_ {
    move |_| PyRuntimeError::new_err(format!("Failed to lock {}", operation))
}

/// Shared utility for hex decode failures  
pub fn hex_decode_error(context: &str) -> impl Fn(hex::FromHexError) -> PyErr + '_ {
    move |e| PyValueError::new_err(format!("Invalid {} hex: {}", context, e))
}

/// Shared utility for conversion failures
pub fn conversion_error(operation: &str) -> impl Fn(Box<dyn std::error::Error>) -> PyErr + '_ {
    move |e| PyValueError::new_err(format!("{} failed: {}", operation, e))
}

/// Legacy conversion function (maintained for backward compatibility)
pub fn convert_to_pyerr(error: LightweightWalletError) -> PyErr {
    PyWalletError::from(error).into()
}

/// Determine if a connection should be evicted based on error patterns
pub fn should_evict_connection(error_message: &str) -> bool {
    // Network-level errors that indicate connection should be evicted
    let eviction_patterns = [
        "connection refused",
        "connection reset",
        "connection timeout",
        "network unreachable",
        "dns resolution failed",
        "tls handshake",
        "certificate verification failed",
        "connection closed",
        "broken pipe",
        "http2 error",
        "protocol error",
        "invalid response"
    ];
    
    let error_lower = error_message.to_lowercase();
    eviction_patterns.iter().any(|pattern| error_lower.contains(pattern))
}
