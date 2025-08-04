//! Python bindings for the extraction module
//!
//! This module provides Python wrappers for the UTXO extraction functionality,
//! providing 1:1 API parity with the Rust core implementation.

use pyo3::prelude::*;
use std::sync::{Arc, Mutex};
use lightweight_wallet_libs::{
    extraction::{ExtractionConfig},
    data_structures::{PrivateKey, CompressedPublicKey},
    errors::LightweightWalletError,
};
use crate::errors::PyWalletError;

// Helper function for locking with error conversion
fn lock_with_conversion_error<'a, T>(
    arc_mutex: &'a Arc<Mutex<T>>,
    context: &'a str,
) -> Result<std::sync::MutexGuard<'a, T>, PyErr> {
    arc_mutex.lock().map_err(|e| {
        PyWalletError::from_msg(&format!("Failed to acquire lock for {}: {}", context, e)).into()
    })
}

/// Configuration for UTXO extraction operations
///
/// This class provides configuration options for extracting wallet outputs
/// from transaction outputs using various validation and key options.
///
/// # Security Note
///
/// Private and public keys should be handled securely and zeroized after use.
/// The extraction process validates ownership through encrypted data decryption.
#[pyclass(name = "TariExtractionConfig")]
#[derive(Clone)]
pub struct PyExtractionConfig {
    inner: Arc<Mutex<ExtractionConfig>>,
}

#[pymethods]
impl PyExtractionConfig {
    /// Create a new extraction configuration with default settings
    ///
    /// Default configuration enables all validation options but provides no keys.
    /// Keys must be set separately using set_private_key() or set_public_key().
    ///
    /// Returns:
    ///     TariExtractionConfig: New configuration instance with default settings
    #[new]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ExtractionConfig::default())),
        }
    }

    /// Create configuration with a private key
    ///
    /// Args:
    ///     private_key (bytes): 32-byte private key for decryption
    ///
    /// Returns:
    ///     TariExtractionConfig: Configuration with private key set
    ///
    /// Raises:
    ///     PyWalletError: If private key is invalid (not 32 bytes)
    #[staticmethod]
    pub fn with_private_key(private_key: Vec<u8>) -> PyResult<Self> {
        if private_key.len() != 32 {
            return Err(PyWalletError::from_wallet_error(LightweightWalletError::OperationNotSupported(
                "Private key must be exactly 32 bytes".to_string(),
            )).into());
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&private_key);
        let rust_private_key = PrivateKey::new(key_array);

        Ok(Self {
            inner: Arc::new(Mutex::new(ExtractionConfig::with_private_key(
                rust_private_key,
            ))),
        })
    }

    /// Create configuration with a public key
    ///
    /// Args:
    ///     public_key (bytes): 32-byte compressed public key
    ///
    /// Returns:
    ///     TariExtractionConfig: Configuration with public key set
    ///
    /// Raises:
    ///     PyWalletError: If public key is invalid (not 32 bytes)
    #[staticmethod]
    pub fn with_public_key(public_key: Vec<u8>) -> PyResult<Self> {
        if public_key.len() != 32 {
            return Err(PyWalletError::from_wallet_error(LightweightWalletError::OperationNotSupported(
                "Public key must be exactly 32 bytes".to_string(),
            )).into());
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&public_key);
        let rust_public_key = CompressedPublicKey::new(key_array);

        Ok(Self {
            inner: Arc::new(Mutex::new(ExtractionConfig::with_public_key(
                rust_public_key,
            ))),
        })
    }

    /// Set the private key for extraction
    ///
    /// Args:
    ///     private_key (bytes): 32-byte private key for decryption
    ///
    /// Raises:
    ///     PyWalletError: If private key is invalid (not 32 bytes)
    pub fn set_private_key(&self, private_key: Vec<u8>) -> PyResult<()> {
        if private_key.len() != 32 {
            return Err(PyWalletError::from_wallet_error(LightweightWalletError::OperationNotSupported(
                "Private key must be exactly 32 bytes".to_string(),
            )).into());
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&private_key);
        let rust_private_key = PrivateKey::new(key_array);

        let mut config = lock_with_conversion_error(&self.inner, "config")?;
        config.set_private_key(rust_private_key);
        Ok(())
    }

    /// Set the public key for extraction
    ///
    /// Args:
    ///     public_key (bytes): 32-byte compressed public key
    ///
    /// Raises:
    ///     PyWalletError: If public key is invalid (not 32 bytes)
    pub fn set_public_key(&self, public_key: Vec<u8>) -> PyResult<()> {
        if public_key.len() != 32 {
            return Err(PyWalletError::from_wallet_error(LightweightWalletError::OperationNotSupported(
                "Public key must be exactly 32 bytes".to_string(),
            )).into());
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&public_key);
        let rust_public_key = CompressedPublicKey::new(key_array);

        let mut config = lock_with_conversion_error(&self.inner, "config")?;
        config.set_public_key(rust_public_key);
        Ok(())
    }

    /// Get key derivation setting
    #[getter]
    pub fn enable_key_derivation(&self) -> PyResult<bool> {
        let config = lock_with_conversion_error(&self.inner, "config")?;
        Ok(config.enable_key_derivation)
    }

    /// Set key derivation setting
    pub fn set_enable_key_derivation(&self, enabled: bool) -> PyResult<()> {
        let mut config = lock_with_conversion_error(&self.inner, "config")?;
        config.enable_key_derivation = enabled;
        Ok(())
    }

    /// Enable or disable range proof validation
    ///
    /// Args:
    ///     enabled (bool): Whether to validate range proofs
    #[getter]
    pub fn validate_range_proofs(&self) -> PyResult<bool> {
        let config = lock_with_conversion_error(&self.inner, "config")?;
        Ok(config.validate_range_proofs)
    }

    pub fn set_validate_range_proofs(&self, enabled: bool) -> PyResult<()> {
        let mut config = lock_with_conversion_error(&self.inner, "config")?;
        config.validate_range_proofs = enabled;
        Ok(())
    }

    /// Enable or disable signature validation
    ///
    /// Args:
    ///     enabled (bool): Whether to validate signatures
    #[getter]
    pub fn validate_signatures(&self) -> PyResult<bool> {
        let config = lock_with_conversion_error(&self.inner, "config")?;
        Ok(config.validate_signatures)
    }

    pub fn set_validate_signatures(&self, enabled: bool) -> PyResult<()> {
        let mut config = lock_with_conversion_error(&self.inner, "config")?;
        config.validate_signatures = enabled;
        Ok(())
    }

    /// Enable or disable special output handling
    ///
    /// Args:
    ///     enabled (bool): Whether to handle special outputs (coinbase, burn, etc.)
    #[getter]
    pub fn handle_special_outputs(&self) -> PyResult<bool> {
        let config = lock_with_conversion_error(&self.inner, "config")?;
        Ok(config.handle_special_outputs)
    }

    pub fn set_handle_special_outputs(&self, enabled: bool) -> PyResult<()> {
        let mut config = lock_with_conversion_error(&self.inner, "config")?;
        config.handle_special_outputs = enabled;
        Ok(())
    }

    /// Enable or disable corruption detection
    ///
    /// Args:
    ///     enabled (bool): Whether to detect data corruption
    #[getter]
    pub fn detect_corruption(&self) -> PyResult<bool> {
        let config = lock_with_conversion_error(&self.inner, "config")?;
        Ok(config.detect_corruption)
    }

    pub fn set_detect_corruption(&self, enabled: bool) -> PyResult<()> {
        let mut config = lock_with_conversion_error(&self.inner, "config")?;
        config.detect_corruption = enabled;
        Ok(())
    }

    /// String representation for debugging
    fn __repr__(&self) -> PyResult<String> {
        let config = lock_with_conversion_error(&self.inner, "config")?;
        
        Ok(format!(
            "TariExtractionConfig(enable_key_derivation={}, validate_range_proofs={}, validate_signatures={}, handle_special_outputs={}, detect_corruption={}, has_private_key={}, has_public_key={})",
            config.enable_key_derivation,
            config.validate_range_proofs,
            config.validate_signatures,
            config.handle_special_outputs,
            config.detect_corruption,
            config.private_key.is_some(),
            config.public_key.is_some()
        ))
    }
}

/// Register extraction classes and functions with Python module
#[allow(dead_code)]
pub fn register_extraction_classes(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyExtractionConfig>()?;
    Ok(())
}
