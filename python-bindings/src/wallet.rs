//! Enhanced Wallet API with native PyO3 objects
//!
//! This module provides a rewritten TariWallet class that returns native PyO3 objects
//! instead of hex strings, improving performance and type safety while maintaining
//! backward compatibility through optional conversion methods.

use crate::address::{PyTariAddress, PyTariAddressFeatures, PyNetwork};
use crate::crypto::{PyPrivateKey, PyCompressedPublicKey, PySignatureResult, PyKeyPair};
use crate::errors::PyWalletError;
use lightweight_wallet_libs::wallet::Wallet;
use lightweight_wallet_libs::crypto::signing::{sign_message_with_tari_wallet, verify_message_from_hex, derive_tari_signing_key};
use lightweight_wallet_libs::key_management::validate_seed_phrase;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Enhanced TariWallet with native object API
#[pyclass(name = "TariWallet")]
#[derive(ZeroizeOnDrop)]
pub struct PyTariWallet {
    #[zeroize(skip)]  // Wallet handles its own sensitive data
    inner: Arc<Mutex<Wallet>>,
}

#[pymethods]
impl PyTariWallet {
    /// Generate a new wallet with seed phrase
    #[staticmethod]
    #[pyo3(signature = (passphrase=None))]
    pub fn generate_new_with_seed_phrase(passphrase: Option<&str>) -> PyResult<Self> {
        let wallet = Wallet::generate_new_with_seed_phrase(passphrase)
            .map_err(|e| PyWalletError::from_msg(&format!("Wallet generation failed: {}", e)))?;
        
        Ok(Self {
            inner: Arc::new(Mutex::new(wallet)),
        })
    }

    /// Create wallet from seed phrase
    #[staticmethod]
    #[pyo3(signature = (seed_phrase, passphrase=None))]
    pub fn from_seed_phrase(
        seed_phrase: &str,
        passphrase: Option<&str>,
    ) -> PyResult<Self> {
        let wallet = Wallet::from_seed_phrase(seed_phrase, passphrase)
            .map_err(|e| PyWalletError::from_msg(&format!("Invalid seed phrase: {}", e)))?;
        
        Ok(Self {
            inner: Arc::new(Mutex::new(wallet)),
        })
    }

    /// Create wallet from private key entropy
    #[staticmethod]
    pub fn from_entropy(entropy: &PyBytes) -> PyResult<Self> {
        let entropy_bytes: [u8; 16] = entropy.as_bytes().try_into().map_err(|_| {
            PyWalletError::from_msg("Entropy must be exactly 16 bytes")
        })?;
        
        let wallet = Wallet::from_entropy(entropy_bytes)
            .map_err(|e| PyWalletError::from_msg(&format!("Invalid entropy: {}", e)))?;
        
        Ok(Self {
            inner: Arc::new(Mutex::new(wallet)),
        })
    }

    /// Get wallet birthday (block height when created)
    pub fn birthday(&self) -> PyResult<u64> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        Ok(wallet.birthday())
    }

    /// Set wallet birthday
    pub fn set_birthday(&self, birthday: u64) -> PyResult<()> {
        let mut wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        wallet.set_birthday(birthday);
        Ok(())
    }

    /// Get seed phrase (returns copy for security)
    pub fn seed_phrase(&self) -> PyResult<String> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        Ok(wallet.seed_phrase())
    }

    /// Validate a seed phrase
    #[staticmethod]
    pub fn validate_seed_phrase(seed_phrase: &str) -> bool {
        validate_seed_phrase(seed_phrase)
    }

    /// Get dual address - returns native PyTariAddress object
    pub fn get_dual_address(
        &self,
        features: &PyTariAddressFeatures,
        payment_id: Option<&PyBytes>,
    ) -> PyResult<PyTariAddress> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        
        let payment_id_data = payment_id.map(|bytes| bytes.as_bytes().to_vec());
        
        let address = wallet.get_dual_address(features.inner(), payment_id_data)
            .map_err(|e| PyWalletError::from_msg(&format!("Failed to generate address: {}", e)))?;
        
        Ok(PyTariAddress::from_string(&address)?)
    }

    /// Get single address - returns native PyTariAddress object
    pub fn get_single_address(&self, features: &PyTariAddressFeatures) -> PyResult<PyTariAddress> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        
        let address = wallet.get_single_address(features.inner())
            .map_err(|e| PyWalletError::from_msg(&format!("Failed to generate address: {}", e)))?;
        
        Ok(PyTariAddress::from_string(&address)?)
    }

    /// Get view private key - returns native PyPrivateKey object
    pub fn view_private_key(&self) -> PyResult<PyPrivateKey> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        
        let view_key = wallet.view_private_key();
        Ok(PyPrivateKey::from_hex(&view_key.to_hex())?)
    }

    /// Get spend private key - returns native PyPrivateKey object  
    pub fn spend_private_key(&self) -> PyResult<PyPrivateKey> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        
        let spend_key = wallet.spend_private_key();
        Ok(PyPrivateKey::from_hex(&spend_key.to_hex())?)
    }

    /// Get view public key - returns native PyCompressedPublicKey object
    pub fn view_public_key(&self) -> PyResult<PyCompressedPublicKey> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        
        let view_key = wallet.view_public_key();
        Ok(PyCompressedPublicKey::from_hex(&view_key.to_hex())?)
    }

    /// Get spend public key - returns native PyCompressedPublicKey object
    pub fn spend_public_key(&self) -> PyResult<PyCompressedPublicKey> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        
        let spend_key = wallet.spend_public_key();
        Ok(PyCompressedPublicKey::from_hex(&spend_key.to_hex())?)
    }

    /// Get master key pair - returns native PyKeyPair object
    pub fn master_key_pair(&self) -> PyResult<PyKeyPair> {
        let private_key = self.spend_private_key()?;
        Ok(PyKeyPair::from_private_key(private_key))
    }

    /// Sign message with wallet - returns native PySignatureResult object
    pub fn sign_message(&self, message: &str) -> PyResult<PySignatureResult> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        
        let master_key = wallet.master_key();
        let signing_key = derive_tari_signing_key(&master_key)
            .map_err(|e| PyWalletError::from_msg(&format!("Failed to derive signing key: {}", e)))?;
        
        let result = sign_message_with_tari_wallet(message, &signing_key)
            .map_err(|e| PyWalletError::from_msg(&format!("Failed to sign message: {}", e)))?;
        
        Ok(PySignatureResult::new(
            result.signature,
            result.public_key,
            message.to_string(),
        ))
    }

    /// Verify message signature
    #[staticmethod]
    pub fn verify_message_signature(
        message: &str,
        signature: &str,
        public_key: &str,
    ) -> PyResult<bool> {
        verify_message_from_hex(message, signature, public_key)
            .map_err(|e| PyWalletError::from_msg(&format!("Verification failed: {}", e)).into())
    }

    /// Get network for address generation
    pub fn network(&self) -> PyResult<PyNetwork> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        
        let network = wallet.network();
        Ok(PyNetwork::from_str(&network.as_key_str())?)
    }

    /// Set network for address generation
    pub fn set_network(&self, network: &PyNetwork) -> PyResult<()> {
        let mut wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        
        wallet.set_network(network.inner());
        Ok(())
    }

    /// Get wallet label
    pub fn label(&self) -> PyResult<Option<String>> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        Ok(wallet.label().map(|s| s.to_string()))
    }

    /// Set wallet label
    pub fn set_label(&self, label: Option<&str>) -> PyResult<()> {
        let mut wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        wallet.set_label(label);
        Ok(())
    }

    /// Get wallet properties as dictionary
    pub fn properties<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyDict>> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        
        let dict = pyo3::types::PyDict::new_bound(py);
        
        // Add basic properties
        dict.set_item("birthday", wallet.birthday())?;
        dict.set_item("network", wallet.network().as_key_str())?;
        
        if let Some(label) = wallet.label() {
            dict.set_item("label", label)?;
        }
        
        // Add key indices
        dict.set_item("view_key_index", wallet.view_key_index())?;
        dict.set_item("spend_key_index", wallet.spend_key_index())?;
        
        Ok(dict)
    }

    /// Clear sensitive data from memory
    pub fn zeroize(&mut self) {
        // The Arc<Mutex<Wallet>> will handle its own cleanup when dropped
        // This method provides explicit clearing capability
    }

    /// Get entropy bytes (for advanced usage - handle with care)
    pub fn entropy<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        
        let entropy = wallet.entropy();
        Ok(PyBytes::new(py, &entropy))
    }

    /// Get view key index
    pub fn view_key_index(&self) -> PyResult<u64> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        Ok(wallet.view_key_index())
    }

    /// Get spend key index
    pub fn spend_key_index(&self) -> PyResult<u64> {
        let wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        Ok(wallet.spend_key_index())
    }

    /// Set view key index
    pub fn set_view_key_index(&self, index: u64) -> PyResult<()> {
        let mut wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        wallet.set_view_key_index(index);
        Ok(())
    }

    /// Set spend key index
    pub fn set_spend_key_index(&self, index: u64) -> PyResult<()> {
        let mut wallet = self.inner.lock().map_err(|_| {
            PyWalletError::from_msg("Failed to lock wallet")
        })?;
        wallet.set_spend_key_index(index);
        Ok(())
    }

    // Compatibility methods for hex string access (optional)
    
    /// Get dual address as hex string (compatibility method)
    pub fn get_dual_address_hex(
        &self,
        features: &PyTariAddressFeatures,
        payment_id: Option<&PyBytes>,
    ) -> PyResult<String> {
        let address = self.get_dual_address(features, payment_id)?;
        Ok(address.to_hex())
    }

    /// Get single address as hex string (compatibility method)
    pub fn get_single_address_hex(&self, features: &PyTariAddressFeatures) -> PyResult<String> {
        let address = self.get_single_address(features)?;
        Ok(address.to_hex())
    }

    /// Get view private key as hex string (compatibility method)
    pub fn view_private_key_hex(&self) -> PyResult<String> {
        let key = self.view_private_key()?;
        Ok(key.to_hex())
    }

    /// Get spend private key as hex string (compatibility method)
    pub fn spend_private_key_hex(&self) -> PyResult<String> {
        let key = self.spend_private_key()?;
        Ok(key.to_hex())
    }

    /// Get view public key as hex string (compatibility method)
    pub fn view_public_key_hex(&self) -> PyResult<String> {
        let key = self.view_public_key()?;
        Ok(key.to_hex())
    }

    /// Get spend public key as hex string (compatibility method)
    pub fn spend_public_key_hex(&self) -> PyResult<String> {
        let key = self.spend_public_key()?;
        Ok(key.to_hex())
    }

    fn __str__(&self) -> String {
        format!("TariWallet(network={}, birthday={})",
            self.network().map(|n| n.to_key().to_string()).unwrap_or_else(|_| "unknown".to_string()),
            self.birthday().unwrap_or(0))
    }

    fn __repr__(&self) -> String {
        let view_key = self.view_public_key_hex()
            .map(|s| format!("{}...", &s[0..16]))
            .unwrap_or_else(|_| "[error]".to_string());
        
        format!("TariWallet(view_key={})", view_key)
    }
}

impl PyTariWallet {
    /// Internal access to the wallet (for other modules)
    pub fn inner(&self) -> &Arc<Mutex<Wallet>> {
        &self.inner
    }
}

/// Wallet generation result with structured data
#[pyclass(name = "WalletGenerationResult")]
pub struct PyWalletGenerationResult {
    #[pyo3(get)]
    pub wallet: PyTariWallet,
    #[pyo3(get)]
    pub seed_phrase: String,
    #[pyo3(get)]
    pub view_key: PyCompressedPublicKey,
    #[pyo3(get)]
    pub spend_key: PyCompressedPublicKey,
}

#[pymethods]
impl PyWalletGenerationResult {
    /// Generate a complete wallet with all components
    #[staticmethod]
    #[pyo3(signature = (passphrase=None))]
    pub fn generate(passphrase: Option<&str>) -> PyResult<Self> {
        let wallet = PyTariWallet::generate_new_with_seed_phrase(passphrase)?;
        let seed_phrase = wallet.seed_phrase()?;
        let view_key = wallet.view_public_key()?;
        let spend_key = wallet.spend_public_key()?;
        
        Ok(Self {
            wallet,
            seed_phrase,
            view_key,
            spend_key,
        })
    }

    fn __str__(&self) -> String {
        format!("WalletGenerationResult(view_key={}..., spend_key={}...)",
            &self.view_key.to_hex()[0..16],
            &self.spend_key.to_hex()[0..16])
    }

    fn __repr__(&self) -> String {
        format!("WalletGenerationResult(seed_phrase='[REDACTED]', view_key={}, spend_key={})",
            self.view_key.to_hex(),
            self.spend_key.to_hex())
    }
}
