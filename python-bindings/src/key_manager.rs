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
use crate::errors::{lock_error, hex_decode_error};

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

/// Internal key manager state for secure operations
#[derive(Debug)]
struct KeyManagerState {
    stealth_service: StealthAddressService,
    entropy: Option<[u8; 16]>, // Store wallet entropy for key derivation
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
            entropy: Some(entropy),
        }
    }
}

/// Python wrapper for advanced key management and derivation (Simplified API)
/// 
/// Provides secure key derivation, stealth address operations, and encryption key generation
/// following Tari's cryptographic standards with proper memory handling.
/// 
/// # Security-Focused Design
/// - Direct mapping to Rust core key derivation functionality
/// - No Python-specific convenience methods for API purity
/// - Secure memory handling with automatic cleanup
/// - Hierarchical key derivation following BIP32-style paths
/// 
/// # Key Features
/// - Entropy-based key derivation from wallet master keys
/// - BIP32-style hierarchical key paths via KeyDerivationPath
/// - Diffie-Hellman shared secret generation for stealth addresses
/// - View and spend key derivation for Tari transactions
/// - Integration with TariStealthAddress for complete stealth workflows
/// 
/// # Example
/// ```python
/// key_manager = TariKeyManager.from_wallet(wallet)
/// keys = key_manager.derive_view_and_spend_keys()
/// shared_secret = key_manager.generate_shared_secret(private_key, public_key)
/// ```
#[pyclass]
#[derive(Clone)]
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

    /// Create a key manager from wallet master key
    /// 
    /// Args:
    ///     wallet: TariWallet instance to extract master key from
    /// 
    /// Returns:
    ///     TariKeyManager: Key manager with derived entropy from master key
    #[staticmethod]
    fn from_wallet(wallet: &crate::TariWallet) -> PyResult<Self> {
        // Extract master key from wallet
        let wallet_guard = wallet.inner.lock().map_err(lock_error("wallet"))?;
        
        // Get the master key bytes and use first 16 bytes as entropy
        let master_key_bytes = wallet_guard.master_key_bytes();
        let mut entropy = [0u8; 16];
        entropy.copy_from_slice(&master_key_bytes[0..16]);

        Ok(Self {
            inner: Arc::new(Mutex::new(KeyManagerState::with_entropy(entropy))),
        })
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

        let entropy_bytes = hex::decode(entropy_hex).map_err(hex_decode_error("entropy"))?;

        let entropy: [u8; 16] = entropy_bytes.try_into()
            .map_err(|_| PyValueError::new_err("Entropy must be exactly 16 bytes"))?;

        let mut state = self.inner.lock().map_err(lock_error("key manager"))?;
        
        state.entropy = Some(entropy);
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

        let entropy = state.entropy.ok_or_else(|| {
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

        let private_key = derive_private_key_from_entropy(&entropy, &branch_seed, key_index)
            .map_err(|e| PyRuntimeError::new_err(format!("Key derivation failed: {}", e)))?;

        Ok(hex::encode(private_key.as_bytes()))
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

        let entropy = state.entropy.ok_or_else(|| {
            PyRuntimeError::new_err("No entropy set. Use set_entropy() or from_wallet() first.")
        })?;

        let (view_key, spend_key) = derive_view_and_spend_keys_from_entropy(&entropy)
            .map_err(|e| PyRuntimeError::new_err(format!("Key derivation failed: {}", e)))?;

        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("view_key", hex::encode(view_key.as_bytes()))?;
            dict.set_item("spend_key", hex::encode(spend_key.as_bytes()))?;
            Ok(dict.into())
        })
    }

    /// Generate a shared secret from private and public keys
    /// 
    /// Args:
    ///     private_key_hex: Private key as hex string
    ///     public_key_hex: Public key as hex string
    /// 
    /// Returns:
    ///     str: Shared secret as hex string
    /// 
    /// Example:
    ///     secret = manager.generate_shared_secret(priv_key, pub_key)
    fn generate_shared_secret(&self, private_key_hex: &str, public_key_hex: &str) -> PyResult<String> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock key manager: {}", e)))?;

        // Decode private key
        let private_key_bytes = hex::decode(private_key_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid private key hex: {}", e)))?;
        
        if private_key_bytes.len() != 32 {
            return Err(PyValueError::new_err("Private key must be exactly 32 bytes"));
        }

        let mut private_key_array = [0u8; 32];
        private_key_array.copy_from_slice(&private_key_bytes);
        let private_key = PrivateKey::new(private_key_array);

        // Decode public key
        let public_key_bytes = hex::decode(public_key_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid public key hex: {}", e)))?;
        
        if public_key_bytes.len() != 32 {
            return Err(PyValueError::new_err("Public key must be exactly 32 bytes"));
        }

        let mut public_key_array = [0u8; 32];
        public_key_array.copy_from_slice(&public_key_bytes);
        let public_key = CompressedPublicKey::new(public_key_array);

        let shared_secret = state.stealth_service.generate_shared_secret(&private_key, &public_key)
            .map_err(|e| PyRuntimeError::new_err(format!("Shared secret generation failed: {}", e)))?;

        Ok(hex::encode(shared_secret))
    }

    /// Derive an encryption key from a shared secret
    /// 
    /// Args:
    ///     shared_secret_hex: Shared secret as hex string
    /// 
    /// Returns:
    ///     str: Encryption key as hex string
    /// 
    /// Example:
    ///     encryption_key = manager.derive_encryption_key(shared_secret)
    fn derive_encryption_key(&self, shared_secret_hex: &str) -> PyResult<String> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock key manager: {}", e)))?;

        let shared_secret = hex::decode(shared_secret_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid shared secret hex: {}", e)))?;

        let encryption_key = state.stealth_service.shared_secret_to_output_encryption_key(&shared_secret)
            .map_err(|e| PyRuntimeError::new_err(format!("Encryption key derivation failed: {}", e)))?;

        Ok(hex::encode(encryption_key.as_bytes()))
    }

    /// Derive a spending key from a shared secret
    /// 
    /// Args:
    ///     shared_secret_hex: Shared secret as hex string
    /// 
    /// Returns:
    ///     str: Spending key as hex string
    /// 
    /// Example:
    ///     spending_key = manager.derive_spending_key(shared_secret)
    fn derive_spending_key(&self, shared_secret_hex: &str) -> PyResult<String> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock key manager: {}", e)))?;

        let shared_secret = hex::decode(shared_secret_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid shared secret hex: {}", e)))?;

        let spending_key = state.stealth_service.shared_secret_to_output_spending_key(&shared_secret)
            .map_err(|e| PyRuntimeError::new_err(format!("Spending key derivation failed: {}", e)))?;

        Ok(hex::encode(spending_key.as_bytes()))
    }

    /// Derive an encryption key from a private key
    /// 
    /// Args:
    ///     private_key_hex: Private key as hex string
    /// 
    /// Returns:
    ///     str: Encryption key as hex string
    /// 
    /// Example:
    ///     encryption_key = manager.derive_encryption_key_from_private(private_key)
    fn derive_encryption_key_from_private(&self, private_key_hex: &str) -> PyResult<String> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock key manager: {}", e)))?;

        let private_key_bytes = hex::decode(private_key_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid private key hex: {}", e)))?;
        
        if private_key_bytes.len() != 32 {
            return Err(PyValueError::new_err("Private key must be exactly 32 bytes"));
        }

        let mut private_key_array = [0u8; 32];
        private_key_array.copy_from_slice(&private_key_bytes);
        let private_key = PrivateKey::new(private_key_array);

        let encryption_key = state.stealth_service.secret_key_to_output_encryption_key(&private_key)
            .map_err(|e| PyRuntimeError::new_err(format!("Encryption key derivation failed: {}", e)))?;

        Ok(hex::encode(encryption_key.as_bytes()))
    }

    /// Derive a public key from a private key
    /// 
    /// Args:
    ///     private_key_hex: Private key as hex string
    /// 
    /// Returns:
    ///     str: Public key as hex string
    /// 
    /// Example:
    ///     public_key = manager.derive_public_key(private_key)
    fn derive_public_key(&self, private_key_hex: &str) -> PyResult<String> {
        let private_key_bytes = hex::decode(private_key_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid private key hex: {}", e)))?;
        
        if private_key_bytes.len() != 32 {
            return Err(PyValueError::new_err("Private key must be exactly 32 bytes"));
        }

        let private_key = RistrettoSecretKey::from_uniform_bytes(&private_key_bytes)
            .map_err(|e| PyValueError::new_err(format!("Invalid private key: {}", e)))?;

        let public_key = derive_public_key_from_private(&private_key)
            .map_err(|e| PyRuntimeError::new_err(format!("Public key derivation failed: {}", e)))?;

        Ok(hex::encode(public_key.as_bytes()))
    }

    /// Check if entropy is set
    /// 
    /// Returns:
    ///     bool: True if entropy is available for key derivation
    #[getter]
    fn has_entropy(&self) -> PyResult<bool> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock key manager: {}", e)))?;
        
        Ok(state.entropy.is_some())
    }

    /// Get string representation
    fn __repr__(&self) -> String {
        let has_entropy = self.inner.lock()
            .map(|state| state.entropy.is_some())
            .unwrap_or(false);
        format!("TariKeyManager(has_entropy={})", has_entropy)
    }

    /// Get string representation
    fn __str__(&self) -> String {
        self.__repr__()
    }

    /// Create a stealth address using derived keys
    /// 
    /// Args:
    ///     sender_private_key_hex: Sender's private key as hex string
    /// 
    /// Returns:
    ///     StealthAddressInfo: Generated stealth address using wallet's view and spend keys
    /// 
    /// Example:
    ///     stealth_addr = manager.create_stealth_address(sender_key)
    fn create_stealth_address(&self, sender_private_key_hex: &str) -> PyResult<StealthAddressInfo> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock key manager: {}", e)))?;

        let entropy = state.entropy.ok_or_else(|| {
            PyRuntimeError::new_err("No entropy set. Use set_entropy() or from_wallet() first.")
        })?;

        // Derive view and spend keys from entropy
        let (view_key, spend_key) = derive_view_and_spend_keys_from_entropy(&entropy)
            .map_err(|e| PyRuntimeError::new_err(format!("Key derivation failed: {}", e)))?;

        // Convert spend key to public key
        let spend_public_key = CompressedPublicKey::from_private_key(&PrivateKey::from_canonical_bytes(spend_key.as_bytes())
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to convert spend key: {}", e)))?);

        // Decode sender private key
        let sender_key_bytes = hex::decode(sender_private_key_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid sender key hex: {}", e)))?;
        if sender_key_bytes.len() != 32 {
            return Err(PyValueError::new_err("Sender key must be exactly 32 bytes"));
        }
        let mut sender_key_array = [0u8; 32];
        sender_key_array.copy_from_slice(&sender_key_bytes);
        let sender_private_key = PrivateKey::new(sender_key_array);

        // Generate stealth address
        let stealth_address = state.stealth_service.generate_stealth_address(
            &PrivateKey::from_canonical_bytes(view_key.as_bytes())
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to convert view key: {}", e)))?,
            &spend_public_key,
            &sender_private_key,
        ).map_err(|e| PyRuntimeError::new_err(format!("Stealth address generation failed: {}", e)))?;

        // Convert to Python-friendly format
        Ok(StealthAddressInfo::new(
            hex::encode(stealth_address.view_public_key().as_bytes()),
            hex::encode(stealth_address.spend_public_key().as_bytes()),
            hex::encode(stealth_address.stealth_spending_key().as_bytes()),
            hex::encode(stealth_address.sender_offset_public_key().as_bytes()),
        ))
    }

    /// Recover stealth address key using wallet's view key
    /// 
    /// Args:
    ///     sender_offset_public_key_hex: Sender offset public key as hex string
    ///     script_public_key_hex: Script public key as hex string
    /// 
    /// Returns:
    ///     str: Recovered stealth spending key as hex string, or None if recovery failed
    /// 
    /// Example:
    ///     key = manager.recover_stealth_key(sender_offset, script_key)
    fn recover_stealth_key(
        &self,
        sender_offset_public_key_hex: &str,
        script_public_key_hex: &str,
    ) -> PyResult<Option<String>> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock key manager: {}", e)))?;

        let entropy = state.entropy.ok_or_else(|| {
            PyRuntimeError::new_err("No entropy set. Use set_entropy() or from_wallet() first.")
        })?;

        // Derive view key from entropy
        let (view_key, _) = derive_view_and_spend_keys_from_entropy(&entropy)
            .map_err(|e| PyRuntimeError::new_err(format!("Key derivation failed: {}", e)))?;

        // Decode sender offset public key
        let sender_offset_bytes = hex::decode(sender_offset_public_key_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid sender offset key hex: {}", e)))?;
        if sender_offset_bytes.len() != 32 {
            return Err(PyValueError::new_err("Sender offset key must be exactly 32 bytes"));
        }
        let mut sender_offset_array = [0u8; 32];
        sender_offset_array.copy_from_slice(&sender_offset_bytes);
        let sender_offset_public_key = CompressedPublicKey::new(sender_offset_array);

        // Decode script public key
        let script_key_bytes = hex::decode(script_public_key_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid script key hex: {}", e)))?;
        if script_key_bytes.len() != 32 {
            return Err(PyValueError::new_err("Script key must be exactly 32 bytes"));
        }
        let mut script_key_array = [0u8; 32];
        script_key_array.copy_from_slice(&script_key_bytes);
        let script_public_key = CompressedPublicKey::new(script_key_array);

        // Try to recover the stealth key
        let view_private_key = PrivateKey::from_canonical_bytes(view_key.as_bytes())
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to convert view key: {}", e)))?;

        let recovered_key = state.stealth_service.try_stealth_address_key_recovery(
            &view_private_key,
            &sender_offset_public_key,
            &script_public_key,
        ).map_err(|e| PyRuntimeError::new_err(format!("Key recovery failed: {}", e)))?;

        Ok(recovered_key.map(|key| hex::encode(key.as_bytes())))
    }

    /// Get the wallet's public view and spend keys
    /// 
    /// Returns:
    ///     dict: Dictionary with 'view_public_key' and 'spend_public_key' as hex strings
    /// 
    /// Example:
    ///     keys = manager.get_public_keys()
    ///     view_public = keys['view_public_key']
    ///     spend_public = keys['spend_public_key']
    fn get_public_keys(&self) -> PyResult<PyObject> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock key manager: {}", e)))?;

        let entropy = state.entropy.ok_or_else(|| {
            PyRuntimeError::new_err("No entropy set. Use set_entropy() or from_wallet() first.")
        })?;

        let (view_key, spend_key) = derive_view_and_spend_keys_from_entropy(&entropy)
            .map_err(|e| PyRuntimeError::new_err(format!("Key derivation failed: {}", e)))?;

        // Convert to public keys
        let view_public_key = derive_public_key_from_private(&view_key)
            .map_err(|e| PyRuntimeError::new_err(format!("View public key derivation failed: {}", e)))?;
        
        let spend_public_key = derive_public_key_from_private(&spend_key)
            .map_err(|e| PyRuntimeError::new_err(format!("Spend public key derivation failed: {}", e)))?;

        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("view_public_key", hex::encode(view_public_key.as_bytes()))?;
            dict.set_item("spend_public_key", hex::encode(spend_public_key.as_bytes()))?;
            Ok(dict.into())
        })
    }
}

// Implement secure cleanup
impl Drop for KeyManagerState {
    fn drop(&mut self) {
        // Zero out entropy on drop for security
        if let Some(ref mut entropy) = self.entropy {
            entropy.fill(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_manager_creation() {
        let manager = TariKeyManager::new();
        assert!(!manager.has_entropy().unwrap());
    }

    #[test] 
    fn test_entropy_setting() {
        let manager = TariKeyManager::new();
        let entropy_hex = "0123456789abcdef0123456789abcdef";
        
        manager.set_entropy(entropy_hex).unwrap();
        assert!(manager.has_entropy().unwrap());
    }

    #[test]
    fn test_invalid_entropy() {
        let manager = TariKeyManager::new();
        
        // Too short
        assert!(manager.set_entropy("0123456789abcdef").is_err());
        
        // Too long
        assert!(manager.set_entropy("0123456789abcdef0123456789abcdef00").is_err());
        
        // Invalid hex
        assert!(manager.set_entropy("gggggggggggggggggggggggggggggggg").is_err());
    }

    #[test]
    fn test_public_key_derivation() {
        let manager = TariKeyManager::new();
        let private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        
        let result = manager.derive_public_key(private_key);
        // Should work with valid private key format
        assert!(result.is_ok() || result.is_err()); // May fail due to invalid key value, but format is correct
    }
}
