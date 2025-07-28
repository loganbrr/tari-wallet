//! Error handling for Python bindings
//!
//! Provides PyO3 best practice error wrapper infrastructure with proper
//! exception mapping and error context preservation.

use pyo3::prelude::*;
use pyo3::exceptions::{
    PyRuntimeError, PyValueError, PyIOError, PyTimeoutError,
    PyConnectionError
};
use lightweight_wallet_libs::errors::LightweightWalletError;

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

/// Legacy conversion function (maintained for backward compatibility)
/// 
/// Note: New code should use PyWalletError wrapper with ? operator instead
pub fn convert_to_pyerr(error: LightweightWalletError) -> PyErr {
    PyWalletError::from(error).into()
}

/// Legacy hex error conversion (maintained for backward compatibility)
///
/// Note: New code should use PyHexError wrapper with ? operator instead  
pub fn hex_to_pyerr(error: hex::FromHexError) -> PyErr {
    PyHexError::from(error).into()
}

/// Stub for connection management (placeholder)
pub fn should_evict_connection(_error: &str) -> bool {
    false // Stub implementation
}

/// Generic error conversion for validation errors
pub fn validation_error(msg: &str) -> PyErr {
    PyValueError::new_err(format!("Validation error: {}", msg))
}

/// Generic error conversion for conversion errors  
pub fn conversion_error(msg: &str) -> PyErr {
    PyValueError::new_err(format!("Conversion error: {}", msg))
}
