//! Shared utility functions for Python bindings
//!
//! This module provides common hex conversion and key derivation utilities
//! used across multiple modules to eliminate code duplication.

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use lightweight_wallet_libs::crypto::{RistrettoSecretKey, RistrettoPublicKey};
use lightweight_wallet_libs::key_management::key_derivation;
use lightweight_wallet_libs::errors::{LightweightWalletError, KeyManagementError};

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

/// Derive view and spend keys from wallet master key bytes
/// 
/// This consolidates the key derivation logic used across scanner and key_manager modules
pub fn derive_view_spend_keys_from_master_key(master_key_bytes: &[u8]) -> Result<(RistrettoSecretKey, RistrettoSecretKey), LightweightWalletError> {
    let mut entropy = [0u8; 16];
    entropy.copy_from_slice(&master_key_bytes[0..16]);
    key_derivation::derive_view_and_spend_keys_from_entropy(&entropy)
        .map_err(|e: KeyManagementError| LightweightWalletError::KeyManagementError(e))
}

/// Get stealth address info from wallet master key bytes
/// 
/// Returns view and spend key pairs (both private and public)
pub fn get_stealth_info_from_master_key(master_key_bytes: &[u8]) -> Result<(RistrettoSecretKey, RistrettoSecretKey, RistrettoPublicKey, RistrettoPublicKey), LightweightWalletError> {
    let (view_key, spend_key) = derive_view_spend_keys_from_master_key(master_key_bytes)?;
    
    let view_public_key = key_derivation::derive_public_key_from_private(&view_key)
        .map_err(|e: KeyManagementError| LightweightWalletError::KeyManagementError(e))?;
    let spend_public_key = key_derivation::derive_public_key_from_private(&spend_key)
        .map_err(|e: KeyManagementError| LightweightWalletError::KeyManagementError(e))?;
    
    Ok((view_key, spend_key, view_public_key, spend_public_key))
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
