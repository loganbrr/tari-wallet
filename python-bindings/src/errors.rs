//! Error handling for Python bindings
//! 
//! This module provides error conversion from Rust errors to Python exceptions

use pyo3::exceptions::PyRuntimeError;
use pyo3::PyErr;
use lightweight_wallet_libs::errors::LightweightWalletError;

/// Convert LightweightWalletError to Python exception
/// 
/// For now, this is a simple conversion that maps all errors to PyRuntimeError.
/// This can be enhanced later to map specific error types to more appropriate
/// Python exceptions (ValueError, ConnectionError, etc.)
#[allow(dead_code)]
pub fn convert_error(err: LightweightWalletError) -> PyErr {
    PyRuntimeError::new_err(format!("Wallet error: {}", err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightweight_wallet_libs::errors::ValidationError;
    
    #[test]
    fn test_error_conversion() {
        let rust_error = LightweightWalletError::ValidationError(
            ValidationError::RangeProofValidationFailed("test".into())
        );
        let _py_error: PyErr = convert_error(rust_error);
    }
}
