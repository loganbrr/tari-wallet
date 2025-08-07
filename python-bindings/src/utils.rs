//! Shared utility functions for Python bindings
//!
//! This module provides common hex conversion and key derivation utilities
//! used across multiple modules to eliminate code duplication.

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

use std::sync::{Arc, Mutex};

/// Lock a mutex with proper error conversion
pub fn lock_with_conversion_error<'a, T>(
    arc_mutex: &'a Arc<Mutex<T>>,
    context: &'static str,
) -> PyResult<std::sync::MutexGuard<'a, T>> {
    arc_mutex.lock().map_err(|e| {
        PyValueError::new_err(format!("Failed to lock {}: {}", context, e)).into()
    })
}

/// Convert hex string to bytes with proper error handling
pub fn hex_to_bytes(hex_str: &str) -> PyResult<Vec<u8>> {
    hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| PyValueError::new_err(format!("Invalid hex string: {}", e)))
}

/// Convert hex string to 32-byte array for commitments
pub fn hex_to_commitment_bytes(hex_str: &str) -> PyResult<[u8; 32]> {
    let bytes = hex_to_bytes(hex_str)?;
    if bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Commitment must be exactly 32 bytes, got {} bytes",
            bytes.len()
        )));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}



/// Utils module for Python
#[pymodule]
pub fn utils_module(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    /// Validate a seed phrase
    #[pyfn(m)]
    fn validate_seed_phrase(seed_phrase: &str) -> bool {
        use lightweight_wallet_libs::key_management::validate_seed_phrase;
        validate_seed_phrase(seed_phrase).is_ok()
    }
    
    /// Generate random entropy for wallet creation
    #[pyfn(m)]
    fn generate_entropy<'py>(py: Python<'py>) -> Bound<'py, pyo3::types::PyBytes> {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        pyo3::types::PyBytes::new(py, &entropy)
    }
    
    Ok(())
}

/// Create batch validation options with default settings
/// 
/// This function provides a convenient way to create batch validation options
/// with common default settings for testing and development.
#[allow(dead_code)]
pub fn create_batch_validation_options(
    continue_on_error: bool,
    validate_range_proofs: bool,
    validate_signatures: bool,
) -> lightweight_wallet_libs::extraction::batch_validation::BatchValidationOptions {
    lightweight_wallet_libs::extraction::batch_validation::BatchValidationOptions {
        continue_on_error,
        max_errors_per_output: 5,
        validate_range_proofs,
        validate_signatures,
        validate_commitments: true,
    }
}

/// Simple async runtime executor for storage operations
/// 
/// This replaces the deleted runtime module functionality
#[allow(dead_code)]
pub fn execute_async<F, R>(future: F) -> PyResult<R>
where
    F: std::future::Future<Output = Result<R, lightweight_wallet_libs::errors::LightweightWalletError>> + Send + 'static,
    R: Send + 'static,
{
    use tokio::runtime::Runtime;
    
    let rt = Runtime::new()
        .map_err(|e| PyValueError::new_err(format!("Failed to create runtime: {}", e)))?;
    
    rt.block_on(future)
        .map_err(|e| PyValueError::new_err(format!("Runtime error: {}", e)).into())
}
