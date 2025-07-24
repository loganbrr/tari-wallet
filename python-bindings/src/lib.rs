use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use pyo3::types::PyDict;
use std::sync::{Arc, Mutex};
use lightweight_wallet_libs::wallet::Wallet;
use lightweight_wallet_libs::crypto::signing::{sign_message_with_tari_wallet, verify_message_from_hex, derive_tari_signing_key};
use lightweight_wallet_libs::crypto::{RistrettoPublicKey, PublicKey};
use tari_utilities::hex::Hex;

mod scanner;
mod types;
mod runtime;
mod errors;
mod storage;

pub use scanner::{TariScanner, ScanResult, Balance, ScanProgress};
pub use types::{WalletTransaction, AddressFeatures};
pub use storage::TariWalletStorage;

/// Python wrapper for the Tari Wallet
#[pyclass]
pub struct TariWallet {
    pub(crate) inner: Arc<Mutex<Wallet>>,
}

#[pymethods]
impl TariWallet {
    /// Generate a new wallet with seed phrase - FULL RUST FUNCTIONALITY
    /// 
    /// Args:
    ///     passphrase: Optional passphrase for seed phrase encryption
    /// 
    /// Returns:
    ///     TariWallet: A new wallet instance with randomly generated seed phrase
    #[staticmethod]
    #[pyo3(signature = (passphrase=None))]
    fn generate_new_with_seed_phrase(passphrase: Option<&str>) -> PyResult<Self> {
        let wallet = Wallet::generate_new_with_seed_phrase(passphrase)
            .map_err(|e| PyRuntimeError::new_err(format!("Wallet generation failed: {}", e)))?;
        
        Ok(TariWallet {
            inner: Arc::new(Mutex::new(wallet)),
        })
    }

    /// Get the wallet birthday (block height when the wallet was created)
    fn birthday(&self) -> PyResult<u64> {
        let wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        Ok(wallet.birthday())
    }

    /// Set the wallet birthday
    fn set_birthday(&self, birthday: u64) -> PyResult<()> {
        let mut wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        wallet.set_birthday(birthday);
        Ok(())
    }

    /// Get the wallet label
    fn label(&self) -> PyResult<Option<String>> {
        let wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        Ok(wallet.label().cloned())
    }

    /// Set the wallet label
    fn set_label(&self, label: Option<String>) -> PyResult<()> {
        let mut wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        wallet.set_label(label);
        Ok(())
    }

    /// Get the network
    fn network(&self) -> PyResult<String> {
        let wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        Ok(wallet.network().to_string())
    }

    /// Set the network
    fn set_network(&self, network: String) -> PyResult<()> {
        let mut wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        wallet.set_network(network);
        Ok(())
    }

    /// Get the current key index
    fn current_key_index(&self) -> PyResult<u64> {
        let wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        Ok(wallet.current_key_index())
    }

    /// Set the current key index
    fn set_current_key_index(&self, index: u64) -> PyResult<()> {
        let mut wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        wallet.set_current_key_index(index);
        Ok(())
    }

    /// Add a custom property to the wallet metadata
    fn set_property(&self, key: String, value: String) -> PyResult<()> {
        let mut wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        wallet.set_property(key, value);
        Ok(())
    }

    /// Get a custom property from the wallet metadata
    fn get_property(&self, key: &str) -> PyResult<Option<String>> {
        let wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        Ok(wallet.get_property(key).cloned())
    }

    /// Remove a custom property from the wallet metadata
    fn remove_property(&self, key: &str) -> PyResult<Option<String>> {
        let mut wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        Ok(wallet.remove_property(key))
    }

    /// Export the original seed phrase if available
    fn export_seed_phrase(&self) -> PyResult<String> {
        let wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        wallet.export_seed_phrase()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to export seed phrase: {}", e)))
    }

    /// Generate a dual address with view and spend keys
    /// 
    /// Args:
    ///     features: AddressFeatures specifying the type of address to generate
    ///     payment_id: Optional payment ID as bytes
    /// 
    /// Returns:
    ///     str: The address as a hex string
    #[pyo3(signature = (features, payment_id=None), text_signature = "(features, payment_id=None)")]
    fn get_dual_address(&self, features: AddressFeatures, payment_id: Option<Vec<u8>>) -> PyResult<String> {
        let wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        
        let address = wallet.get_dual_address(features.inner, payment_id)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to generate dual address: {}", e)))?;
        
        Ok(address.to_hex())
    }

    /// Generate a single address with spend key only
    /// 
    /// Args:
    ///     features: AddressFeatures specifying the type of address to generate
    /// 
    /// Returns:
    ///     str: The address as a hex string
    #[pyo3(signature = (features), text_signature = "(features)")]
    fn get_single_address(&self, features: AddressFeatures) -> PyResult<String> {
        let wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        
        let address = wallet.get_single_address(features.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to generate single address: {}", e)))?;
        
        Ok(address.to_hex())
    }

    /// String representation of the wallet
    fn __str__(&self) -> PyResult<String> {
        let wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        
        let label = wallet.label().map(|s| s.as_str()).unwrap_or("Unlabeled");
        let network = wallet.network();
        let birthday = wallet.birthday();
        
        Ok(format!("TariWallet(label='{}', network='{}', birthday={})", label, network, birthday))
    }

    /// Representation of the wallet
    fn __repr__(&self) -> PyResult<String> {
        self.__str__()
    }

    /// Sign a message using the wallet's master key
    /// 
    /// Args:
    ///     message: The message to sign as a string
    /// 
    /// Returns:
    ///     dict: Dictionary with 'signature', 'nonce', and 'public_key' as hex strings
    fn sign_message(&self, message: String) -> PyResult<PyObject> {
        let wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        
        // Get the seed phrase from the wallet
        let seed_phrase = wallet.export_seed_phrase()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to export seed phrase: {}", e)))?;
        
        // Derive the signing key to get the public key
        let signing_key = derive_tari_signing_key(&seed_phrase, None)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to derive signing key: {}", e)))?;
        
        let public_key = RistrettoPublicKey::from_secret_key(&signing_key);
        let public_key_hex = public_key.to_hex();
        
        let (signature_hex, nonce_hex) = sign_message_with_tari_wallet(&seed_phrase, &message, None)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to sign message: {}", e)))?;
        
        Python::with_gil(|py| {
            let result = PyDict::new(py);
            result.set_item("signature", signature_hex)?;
            result.set_item("nonce", nonce_hex)?;
            result.set_item("public_key", public_key_hex)?;
            Ok(result.into())
        })
    }

    /// Verify a message signature
    /// 
    /// Args:
    ///     message: The original message as a string
    ///     signature_hex: The signature as a hex string
    ///     nonce_hex: The nonce as a hex string
    ///     public_key_hex: The public key as a hex string
    /// 
    /// Returns:
    ///     bool: True if the signature is valid, False otherwise
    fn verify_message(&self, message: String, signature_hex: String, nonce_hex: String, public_key_hex: String) -> PyResult<bool> {
        // Parse the public key from hex
        let public_key = RistrettoPublicKey::from_hex(&public_key_hex)
            .map_err(|e| PyRuntimeError::new_err(format!("Invalid public key hex: {}", e)))?;
        
        let is_valid = verify_message_from_hex(&public_key, &message, &signature_hex, &nonce_hex)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to verify message: {}", e)))?;
        
        Ok(is_valid)
    }

    /// Sync wallet with blockchain from birthday to current tip
    /// 
    /// Args:
    ///     base_node_url: The base node URL for blockchain scanning
    ///     
    /// Returns:
    ///     dict: Sync result with total_value found and blocks scanned
    fn sync(&self, base_node_url: String) -> PyResult<PyObject> {
        use crate::runtime::{execute_async, get_or_create_scanner};
        use lightweight_wallet_libs::scanning::BlockchainScanner;
        use lightweight_wallet_libs::errors::LightweightWalletError;
        
        let wallet = Arc::clone(&self.inner);
        let url_for_result = base_node_url.clone();
        
        let result = execute_async(async move {
            let scanner_arc = get_or_create_scanner(&base_node_url).await?;
            let mut scanner = scanner_arc.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner".into()))?;
            
            // Get wallet birthday for scan start
            let start_height = {
                let wallet_guard = wallet.lock()
                    .map_err(|_| LightweightWalletError::ConversionError("Failed to lock wallet".into()))?;
                wallet_guard.birthday()
            };
            
            // Get current tip height
            let tip_info = scanner.get_tip_info().await?;
            let end_height = tip_info.best_block_height;
            
            // Create scan config and perform scan
            let wallet_guard = wallet.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock wallet".into()))?;
            let scan_config = scanner.create_scan_config_with_wallet_keys(&*wallet_guard, start_height, Some(end_height))?;
            drop(wallet_guard);
            
            // Perform the sync scan
            let block_results = scanner.scan_blocks(scan_config).await?;
            
            // Calculate results
            let total_value: u64 = block_results.iter()
                .flat_map(|block| &block.wallet_outputs)
                .map(|output| output.value().as_u64())
                .sum();
            
            let blocks_scanned = end_height.saturating_sub(start_height);
            
            Ok((total_value, blocks_scanned, start_height, end_height))
        })?;
        
        let (total_value, blocks_scanned, start_height, end_height) = result;
        
        // Create result dict
        Python::with_gil(|py| {
            let result = PyDict::new(py);
            result.set_item("total_value", total_value)?;
            result.set_item("blocks_scanned", blocks_scanned)?;
            result.set_item("start_height", start_height)?;
            result.set_item("end_height", end_height)?;
            result.set_item("base_node_url", url_for_result)?;
            Ok(result.into())
        })
    }
}

/// Convenience function to generate a new wallet with seed phrase
/// 
/// Args:
///     passphrase: Optional passphrase for seed phrase encryption
/// 
/// Returns:
///     TariWallet: A new wallet instance with randomly generated seed phrase
#[pyfunction]
#[pyo3(signature = (passphrase=None))]
fn generate_new_wallet(passphrase: Option<&str>) -> PyResult<TariWallet> {
    TariWallet::generate_new_with_seed_phrase(passphrase)
}

/// A Python module implemented in Rust.
#[pymodule]
fn lightweight_wallet_libpy(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TariWallet>()?;
    m.add_class::<TariScanner>()?;
    m.add_class::<ScanResult>()?;
    m.add_class::<Balance>()?;
    m.add_class::<ScanProgress>()?;
    m.add_class::<WalletTransaction>()?;
    m.add_class::<AddressFeatures>()?;
    m.add_class::<TariWalletStorage>()?;
    m.add_function(wrap_pyfunction!(generate_new_wallet, m)?)?;
    Ok(())
}
