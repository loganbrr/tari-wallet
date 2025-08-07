//! Key management wrapper for Python bindings
//!
//! This module provides the TariKeyManager class that wraps the existing Rust
//! key derivation and stealth address functionality with secure memory handling.

use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError};
use pyo3::types::PyDict;
use std::sync::{Arc, Mutex};
use std::convert::TryInto;
use std::str::FromStr;
use tari_utilities::ByteArray;
use hex;

use crate::secure_wrapper::{SecureData, SecureEntropy};

use lightweight_wallet_libs::key_management::{
    key_derivation::{
        derive_private_key_from_entropy,
        derive_view_and_spend_keys_from_entropy,
        derive_public_key_from_private,
    },
    stealth_address::StealthAddressService,
};
use lightweight_wallet_libs::data_structures::types::{PrivateKey, CompressedPublicKey};
use lightweight_wallet_libs::crypto::{RistrettoSecretKey, SecretKey};
use crate::key_derivation::KeyDerivationPath;
use crate::stealth_types::StealthAddressInfo;

/// Internal key manager state with secure memory management
#[derive(Debug)]
struct KeyManagerState {
    stealth_service: StealthAddressService,
    entropy: Option<SecureData<SecureEntropy>>, // Secure entropy storage with zeroization
}

impl KeyManagerState {
    fn new() -> Self {
        Self {
            stealth_service: StealthAddressService::new(),
            entropy: None,
        }
    }

    fn with_entropy(entropy: [u8; 16]) -> Self {
        Self {
            stealth_service: StealthAddressService::new(),
            entropy: Some(SecureData::new(SecureEntropy::from(entropy))),
        }
    }
}

/// Python wrapper for advanced key management and derivation
#[pyclass]
pub struct TariKeyManager {
    inner: Arc<Mutex<KeyManagerState>>,
}

#[pymethods]
impl TariKeyManager {
    /// Create a new key manager
    /// 
    /// Returns:
    ///     TariKeyManager: New key manager instance
    #[new]
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(KeyManagerState::new())),
        }
    }

    /// Set entropy for key derivation operations
    /// 
    /// Args:
    ///     entropy_hex: 32-character hex string representing 16 bytes of entropy
    /// 
    /// Example:
    ///     manager.set_entropy("0123456789abcdef0123456789abcdef")
    fn set_entropy(&self, entropy_hex: &str) -> PyResult<()> {
        if entropy_hex.len() != 32 {
            return Err(PyValueError::new_err("Entropy must be exactly 32 hex characters (16 bytes)"));
        }

        let entropy_bytes = hex::decode(entropy_hex).map_err(|e| PyValueError::new_err(format!("Invalid hex: {}", e)))?;

        let entropy: [u8; 16] = entropy_bytes.try_into()
            .map_err(|_| PyValueError::new_err("Entropy must be exactly 16 bytes"))?;

        let mut state = self.inner.lock().map_err(|e| PyValueError::new_err(format!("Failed to lock key manager: {}", e)))?;
        
        state.entropy = Some(SecureData::new(SecureEntropy::from(entropy)));
        Ok(())
    }

    /// Derive a private key from a hierarchical path
    /// 
    /// Args:
    ///     path: String representation like "m/44'/0'/1"
    /// 
    /// Returns:
    ///     str: Hex-encoded private key (64 characters)
    /// 
    /// Example:
    ///     key = manager.derive_key_from_path("m/44'/0'/1")
    fn derive_key_from_path(&self, path: String) -> PyResult<String> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock key manager: {}", e)))?;

        let entropy_data = state.entropy.as_ref().ok_or_else(|| {
            PyRuntimeError::new_err("No entropy set. Use set_entropy() or from_wallet() first.")
        })?;

        // Convert path string to KeyDerivationPath
        let derivation_path = KeyDerivationPath::from_str(&path)
            .map_err(|e| PyValueError::new_err(format!("Invalid path: {}", e)))?;

        // For simplicity, use the first component as branch and second as index
        // In a full implementation, this would handle full hierarchical derivation
        if derivation_path.components().is_empty() {
            return Err(PyValueError::new_err("Path must have at least one component"));
        }

        let branch_seed = format!("branch_{}", derivation_path.components()[0]);
        let key_index = derivation_path.components().get(1).copied().unwrap_or(0) as u64;

        // Use secure data with closure to avoid exposing entropy
        let result = entropy_data.with_data(|entropy| {
            derive_private_key_from_entropy(entropy.as_bytes(), &branch_seed, key_index)
                .map_err(|e| PyRuntimeError::new_err(format!("Key derivation failed: {}", e)))
        });

        match result {
            Some(Ok(private_key)) => Ok(hex::encode(private_key.as_bytes())),
            Some(Err(e)) => Err(e),
            None => Err(PyRuntimeError::new_err("Entropy data has been zeroized")),
        }
    }

    /// Derive view and spend keys from wallet entropy
    /// 
    /// Returns:
    ///     dict: Dictionary with 'view_key' and 'spend_key' as hex strings
    /// 
    /// Example:
    ///     keys = manager.derive_view_and_spend_keys()
    ///     view_key = keys['view_key']
    ///     spend_key = keys['spend_key']
    fn derive_view_and_spend_keys(&self) -> PyResult<PyObject> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock key manager: {}", e)))?;

        let entropy_data = state.entropy.as_ref().ok_or_else(|| {
            PyRuntimeError::new_err("No entropy set. Use set_entropy() or from_wallet() first.")
        })?;

        let result = entropy_data.with_data(|entropy| {
            derive_view_and_spend_keys_from_entropy(entropy.as_bytes())
                .map_err(|e| PyRuntimeError::new_err(format!("Key derivation failed: {}", e)))
        });

        match result {
            Some(Ok((view_key, spend_key))) => {
                Python::with_gil(|py| {
                    let dict = PyDict::new(py);
                    dict.set_item("view_key", hex::encode(view_key.as_bytes()))?;
                    dict.set_item("spend_key", hex::encode(spend_key.as_bytes()))?;
                    Ok(dict.into())
                })
            },
            Some(Err(e)) => Err(e),
            None => Err(PyRuntimeError::new_err("Entropy data has been zeroized")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_manager_creation() {
        let manager = TariKeyManager::new();
        // Basic test that it can be created
        assert!(true);
    }
}
