//! Stealth address operations wrapper for Python bindings
//!
//! This module provides the TariStealthAddress class that wraps the existing
//! StealthAddressService with batch processing for output scanning and address generation.

use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use lightweight_wallet_libs::key_management::stealth_address::StealthAddressService;
use lightweight_wallet_libs::data_structures::types::{PrivateKey, CompressedPublicKey};
use crate::stealth_types::{StealthAddressInfo, StealthScanResult};

/// Internal stealth address service state
#[derive(Debug)]
struct StealthAddressState {
    service: StealthAddressService,
    default_chunk_size: usize,
}

impl StealthAddressState {
    fn new() -> Self {
        Self {
            service: StealthAddressService::new(),
            default_chunk_size: 1000, // Default chunk size for batch processing
        }
    }
}

/// Python wrapper for stealth address operations
/// 
/// Provides batch processing for stealth address generation, scanning, and key recovery
/// with memory-efficient chunked processing and progress reporting.
#[pyclass]
#[derive(Clone)]
pub struct TariStealthAddress {
    inner: Arc<Mutex<StealthAddressState>>,
}

#[pymethods]
impl TariStealthAddress {
    /// Create a new stealth address service
    /// 
    /// Args:
    ///     chunk_size: Optional chunk size for batch processing (default: 1000)
    /// 
    /// Returns:
    ///     TariStealthAddress: New stealth address service instance
    #[new]
    #[pyo3(signature = (chunk_size=None))]
    fn new(chunk_size: Option<usize>) -> Self {
        let mut state = StealthAddressState::new();
        if let Some(size) = chunk_size {
            state.default_chunk_size = size;
        }
        
        Self {
            inner: Arc::new(Mutex::new(state)),
        }
    }

    /// Generate a stealth address from view and spend keys
    /// 
    /// Args:
    ///     view_key_hex: View private key as hex string
    ///     spend_key_hex: Spend public key as hex string  
    ///     sender_private_key_hex: Sender's private key as hex string
    /// 
    /// Returns:
    ///     StealthAddressInfo: Generated stealth address information
    /// 
    /// Example:
    ///     address = stealth.create_stealth_address(view_key, spend_key, sender_key)
    fn create_stealth_address(
        &self,
        view_key_hex: &str,
        spend_key_hex: &str,
        sender_private_key_hex: &str,
    ) -> PyResult<StealthAddressInfo> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock stealth service: {}", e)))?;

        // Decode view key
        let view_key_bytes = hex::decode(view_key_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid view key hex: {}", e)))?;
        if view_key_bytes.len() != 32 {
            return Err(PyValueError::new_err("View key must be exactly 32 bytes"));
        }
        let mut view_key_array = [0u8; 32];
        view_key_array.copy_from_slice(&view_key_bytes);
        let view_key = PrivateKey::new(view_key_array);

        // Decode spend key
        let spend_key_bytes = hex::decode(spend_key_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid spend key hex: {}", e)))?;
        if spend_key_bytes.len() != 32 {
            return Err(PyValueError::new_err("Spend key must be exactly 32 bytes"));
        }
        let mut spend_key_array = [0u8; 32];
        spend_key_array.copy_from_slice(&spend_key_bytes);
        let spend_public_key = CompressedPublicKey::new(spend_key_array);

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
        let stealth_address = state.service.generate_stealth_address(
            &view_key,
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

    /// Recover stealth address keys from an output
    /// 
    /// Args:
    ///     view_key_hex: View private key as hex string
    ///     sender_offset_public_key_hex: Sender offset public key as hex string
    ///     script_public_key_hex: Script public key as hex string
    /// 
    /// Returns:
    ///     str: Recovered stealth spending key as hex string, or None if recovery failed
    /// 
    /// Example:
    ///     key = stealth.recover_stealth_key(view_key, sender_offset, script_key)
    fn recover_stealth_key(
        &self,
        view_key_hex: &str,
        sender_offset_public_key_hex: &str,
        script_public_key_hex: &str,
    ) -> PyResult<Option<String>> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock stealth service: {}", e)))?;

        // Decode view key
        let view_key_bytes = hex::decode(view_key_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid view key hex: {}", e)))?;
        if view_key_bytes.len() != 32 {
            return Err(PyValueError::new_err("View key must be exactly 32 bytes"));
        }
        let mut view_key_array = [0u8; 32];
        view_key_array.copy_from_slice(&view_key_bytes);
        let view_key = PrivateKey::new(view_key_array);

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
        let recovered_key = state.service.try_stealth_address_key_recovery(
            &view_key,
            &sender_offset_public_key,
            &script_public_key,
        ).map_err(|e| PyRuntimeError::new_err(format!("Key recovery failed: {}", e)))?;

        Ok(recovered_key.map(|key| hex::encode(key.as_bytes())))
    }

    /// Scan a list of outputs for stealth addresses
    /// 
    /// Args:
    ///     view_key_hex: View private key as hex string
    ///     outputs: List of output data dictionaries with required fields
    ///     chunk_size: Optional chunk size for processing (uses default if not specified)
    /// 
    /// Returns:
    ///     StealthScanResult: Scanning results with found addresses and statistics
    /// 
    /// Example:
    ///     outputs = [{"sender_offset": "abc...", "script_key": "def..."}]
    ///     result = stealth.scan_for_outputs(view_key, outputs)
    #[pyo3(signature = (view_key_hex, outputs, chunk_size=None))]
    fn scan_for_outputs(
        &self,
        view_key_hex: &str,
        outputs: Vec<PyObject>,
        chunk_size: Option<usize>,
    ) -> PyResult<StealthScanResult> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock stealth service: {}", e)))?;

        let processing_chunk_size = chunk_size.unwrap_or(state.default_chunk_size);
        let total_outputs = outputs.len();
        
        if total_outputs == 0 {
            return Ok(StealthScanResult::new(vec![], 0, None, None, None));
        }

        let start_time = Instant::now();

        // Decode view key once
        let view_key_bytes = hex::decode(view_key_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid view key hex: {}", e)))?;
        if view_key_bytes.len() != 32 {
            return Err(PyValueError::new_err("View key must be exactly 32 bytes"));
        }
        let mut view_key_array = [0u8; 32];
        view_key_array.copy_from_slice(&view_key_bytes);
        let view_key = PrivateKey::new(view_key_array);

        let mut found_addresses = Vec::new();
        let mut processed_count = 0;

        // Process outputs in chunks for memory efficiency
        for chunk in outputs.chunks(processing_chunk_size) {
            for output in chunk {
                processed_count += 1;

                // Extract required fields from output dictionary
                let (sender_offset_hex, script_key_hex) = Python::with_gil(|py| -> PyResult<(String, String)> {
                    let output_dict = output.bind(py);
                    
                    let sender_offset = output_dict
                        .get_item("sender_offset")
                        .map_err(|_| PyValueError::new_err("Output missing 'sender_offset' field"))?
                        .extract::<String>()?;
                    
                    let script_key = output_dict
                        .get_item("script_key")
                        .map_err(|_| PyValueError::new_err("Output missing 'script_key' field"))?
                        .extract::<String>()?;
                    
                    Ok((sender_offset, script_key))
                })?;

                // Try to recover stealth key for this output
                if let Ok(Some(recovered_key)) = self.recover_stealth_key(
                    view_key_hex,
                    &sender_offset_hex,
                    &script_key_hex,
                ) {
                    // Create stealth address info from recovered data
                    let view_public_key = hex::encode(
                        CompressedPublicKey::from_private_key(&view_key).as_bytes()
                    );
                    
                    found_addresses.push(StealthAddressInfo::new(
                        view_public_key,
                        "".to_string(), // Spend key not available from scanning
                        recovered_key,
                        sender_offset_hex,
                    ));
                }
            }
        }

        let duration = start_time.elapsed();
        let duration_ms = duration.as_millis() as u64;

        Ok(StealthScanResult::new(
            found_addresses,
            processed_count,
            None, // Start height not available
            None, // End height not available
            Some(duration_ms),
        ))
    }

    /// Generate multiple stealth addresses in batch
    /// 
    /// Args:
    ///     view_key_hex: View private key as hex string
    ///     spend_key_hex: Spend public key as hex string
    ///     sender_keys: List of sender private keys as hex strings
    ///     chunk_size: Optional chunk size for processing
    /// 
    /// Returns:
    ///     list: List of StealthAddressInfo objects
    /// 
    /// Example:
    ///     sender_keys = ["abc...", "def...", "123..."]
    ///     addresses = stealth.generate_batch_addresses(view_key, spend_key, sender_keys)
    #[pyo3(signature = (view_key_hex, spend_key_hex, sender_keys, chunk_size=None))]
    fn generate_batch_addresses(
        &self,
        view_key_hex: &str,
        spend_key_hex: &str,
        sender_keys: Vec<String>,
        chunk_size: Option<usize>,
    ) -> PyResult<Vec<StealthAddressInfo>> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock stealth service: {}", e)))?;

        let processing_chunk_size = chunk_size.unwrap_or(state.default_chunk_size);
        let mut addresses = Vec::new();

        // Process sender keys in chunks
        for chunk in sender_keys.chunks(processing_chunk_size) {
            for sender_key_hex in chunk {
                let address = self.create_stealth_address(
                    view_key_hex,
                    spend_key_hex,
                    sender_key_hex,
                )?;
                addresses.push(address);
            }
        }

        Ok(addresses)
    }

    /// Set the default chunk size for batch operations
    /// 
    /// Args:
    ///     chunk_size: New default chunk size
    /// 
    /// Example:
    ///     stealth.set_chunk_size(500)
    fn set_chunk_size(&self, chunk_size: usize) -> PyResult<()> {
        let mut state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock stealth service: {}", e)))?;
        
        if chunk_size == 0 {
            return Err(PyValueError::new_err("Chunk size must be greater than 0"));
        }
        
        state.default_chunk_size = chunk_size;
        Ok(())
    }

    /// Get the current default chunk size
    /// 
    /// Returns:
    ///     int: Current default chunk size
    #[getter]
    fn chunk_size(&self) -> PyResult<usize> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock stealth service: {}", e)))?;
        
        Ok(state.default_chunk_size)
    }

    /// Check if a stealth address is valid
    /// 
    /// Args:
    ///     address: StealthAddressInfo to validate
    /// 
    /// Returns:
    ///     bool: True if the address is valid
    fn validate_stealth_address(&self, address: &StealthAddressInfo) -> bool {
        address.is_valid()
    }

    /// Generate shared secret between two keys
    /// 
    /// Args:
    ///     private_key_hex: Private key as hex string
    ///     public_key_hex: Public key as hex string
    /// 
    /// Returns:
    ///     str: Shared secret as hex string
    /// 
    /// Example:
    ///     secret = stealth.generate_shared_secret(private_key, public_key)
    fn generate_shared_secret(&self, private_key_hex: &str, public_key_hex: &str) -> PyResult<String> {
        let state = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock stealth service: {}", e)))?;

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

        let shared_secret = state.service.generate_shared_secret(&private_key, &public_key)
            .map_err(|e| PyRuntimeError::new_err(format!("Shared secret generation failed: {}", e)))?;

        Ok(hex::encode(shared_secret))
    }

    /// String representation
    fn __repr__(&self) -> String {
        let chunk_size = self.chunk_size().unwrap_or(0);
        format!("TariStealthAddress(chunk_size={})", chunk_size)
    }

    /// String representation
    fn __str__(&self) -> String {
        self.__repr__()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_key() -> String {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
    }

    #[test]
    fn test_stealth_address_creation() {
        let stealth = TariStealthAddress::new(Some(500));
        assert_eq!(stealth.chunk_size().unwrap(), 500);
    }

    #[test]
    fn test_stealth_address_generation() {
        let stealth = TariStealthAddress::new(None);
        let view_key = generate_test_key();
        let spend_key = generate_test_key();
        let sender_key = generate_test_key();

        let result = stealth.create_stealth_address(&view_key, &spend_key, &sender_key);
        assert!(result.is_ok());
        
        let address = result.unwrap();
        assert!(address.is_valid());
    }

    #[test]
    fn test_shared_secret_generation() {
        let stealth = TariStealthAddress::new(None);
        let private_key = generate_test_key();
        let public_key = generate_test_key();

        let result = stealth.generate_shared_secret(&private_key, &public_key);
        assert!(result.is_ok());
        
        let secret = result.unwrap();
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_chunk_size_setting() {
        let stealth = TariStealthAddress::new(None);
        assert_eq!(stealth.chunk_size().unwrap(), 1000); // Default

        stealth.set_chunk_size(2000).unwrap();
        assert_eq!(stealth.chunk_size().unwrap(), 2000);

        // Test invalid chunk size
        assert!(stealth.set_chunk_size(0).is_err());
    }

    #[test]
    fn test_batch_address_generation() {
        let stealth = TariStealthAddress::new(Some(2)); // Small chunk size for testing
        let view_key = generate_test_key();
        let spend_key = generate_test_key();
        let sender_keys = vec![generate_test_key(), generate_test_key(), generate_test_key()];

        let result = stealth.generate_batch_addresses(&view_key, &spend_key, sender_keys, None);
        assert!(result.is_ok());
        
        let addresses = result.unwrap();
        assert_eq!(addresses.len(), 3);
        
        for address in addresses {
            assert!(address.is_valid());
        }
    }
}
