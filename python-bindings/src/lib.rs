use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use std::sync::{Arc, Mutex};
use lightweight_wallet_libs::wallet::Wallet;
use lightweight_wallet_libs::data_structures::address::TariAddressFeatures;

/// Python wrapper for the Tari Wallet
#[pyclass]
pub struct TariWallet {
    inner: Arc<Mutex<Wallet>>,
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
    fn get_dual_address(&self, payment_id: Option<Vec<u8>>) -> PyResult<String> {
        let wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        
        let features = TariAddressFeatures::create_interactive_and_one_sided();
        let address = wallet.get_dual_address(features, payment_id)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to generate dual address: {}", e)))?;
        
        Ok(address.to_hex())
    }

    /// Generate a single address with spend key only
    fn get_single_address(&self) -> PyResult<String> {
        let wallet = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        
        let features = TariAddressFeatures::create_interactive_only();
        let address = wallet.get_single_address(features)
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
    m.add_function(wrap_pyfunction!(generate_new_wallet, m)?)?;
    Ok(())
}
