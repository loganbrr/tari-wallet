//! Stealth address operations wrapper for Python bindings
//!
//! This module provides the TariStealthAddress class that wraps the existing
//! StealthAddressService with batch processing for output scanning and address generation.

use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError};
use std::sync::{Arc, Mutex};

use lightweight_wallet_libs::key_management::stealth_address::StealthAddressService;
use lightweight_wallet_libs::data_structures::types::{PrivateKey, CompressedPublicKey};
use crate::stealth_types::{StealthAddressInfo, StealthScanResult};

/// Fixed chunk size for memory-efficient batch processing
const FIXED_CHUNK_SIZE: usize = 1000;

/// Python wrapper for stealth address operations (Simplified API)
/// 
/// Provides core stealth address functionality that mirrors the Rust StealthAddressService
/// with 1:1 API parity for security and consistency.
/// 
/// # Security-Focused Design
/// - **Removed**: Python-specific timing measurements and performance statistics
/// - **Removed**: Configurable chunk sizes and batch address generation
/// - **Removed**: Convenience methods and validation helpers
/// - **Retained**: Core cryptographic operations with fixed memory-efficient chunking
/// 
/// # Core Operations
/// - `create_stealth_address()`: Generate stealth addresses from keys
/// - `recover_stealth_key()`: Attempt key recovery from transaction outputs
/// - `scan_for_outputs()`: Batch scan outputs with fixed chunking (1000 items)
/// - `generate_shared_secret()`: Diffie-Hellman key agreement operations
/// 
/// # Memory Efficiency
/// - Fixed chunk size of 1000 items for optimal memory vs performance balance
/// - Streaming processing for large datasets without memory accumulation
/// - No configurable parameters to maintain API simplicity and security
/// 
/// # Example
/// ```python
/// stealth_service = TariStealthAddress()
/// stealth_addr = stealth_service.create_stealth_address(view_key, spend_key, sender_key)
/// scan_result = stealth_service.scan_for_outputs(view_key, spend_key, outputs)
/// ```
#[pyclass]
#[derive(Clone)]
pub struct TariStealthAddress {
    inner: Arc<Mutex<StealthAddressService>>,
}

#[pymethods]
impl TariStealthAddress {
    /// Create a new stealth address service
    /// 
    /// Returns:
    ///     TariStealthAddress: New stealth address service instance
    #[new]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StealthAddressService::new())),
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
        let service = self.inner.lock()
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
        let stealth_address = service.generate_stealth_address(
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
        let service = self.inner.lock()
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
        let recovered_key = service.try_stealth_address_key_recovery(
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
    /// 
    /// Returns:
    ///     StealthScanResult: Scanning results with found addresses
    /// 
    /// Example:
    ///     outputs = [{"sender_offset": "abc...", "script_key": "def..."}]
    ///     result = stealth.scan_for_outputs(view_key, outputs)
    pub fn scan_for_outputs(
        &self,
        view_key_hex: &str,
        outputs: Vec<PyObject>,
    ) -> PyResult<StealthScanResult> {
        // Validate that the stealth service is available before processing
        let _service_check = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock stealth service: {}", e)))?;

        let total_outputs = outputs.len();
        
        if total_outputs == 0 {
            return Ok(StealthScanResult::new(vec![], 0));
        }

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
        for chunk in outputs.chunks(FIXED_CHUNK_SIZE) {
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

        Ok(StealthScanResult::new(
            found_addresses,
            processed_count,
        ))
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
        let service = self.inner.lock()
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

        let shared_secret = service.generate_shared_secret(&private_key, &public_key)
            .map_err(|e| PyRuntimeError::new_err(format!("Shared secret generation failed: {}", e)))?;

        Ok(hex::encode(shared_secret))
    }

    /// Derive an output encryption key from a shared secret
    /// 
    /// Args:
    ///     shared_secret_hex: Shared secret as hex string
    /// 
    /// Returns:
    ///     str: Output encryption key as hex string
    /// 
    /// Example:
    ///     encryption_key = stealth.shared_secret_to_output_encryption_key(shared_secret)
    fn shared_secret_to_output_encryption_key(&self, shared_secret_hex: &str) -> PyResult<String> {
        let service = self.inner.lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to lock stealth service: {}", e)))?;

        let shared_secret = hex::decode(shared_secret_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid shared secret hex: {}", e)))?;

        let encryption_key = service.shared_secret_to_output_encryption_key(&shared_secret)
            .map_err(|e| PyRuntimeError::new_err(format!("Encryption key derivation failed: {}", e)))?;

        Ok(hex::encode(encryption_key.as_bytes()))
    }

    /// String representation
    fn __repr__(&self) -> String {
        "TariStealthAddress()".to_string()
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
        let stealth = TariStealthAddress::new();
        assert_eq!(stealth.__repr__(), "TariStealthAddress()");
    }

    #[test]
    fn test_stealth_address_generation() {
        let stealth = TariStealthAddress::new();
        let view_key = generate_test_key();
        let spend_key = generate_test_key();
        let sender_key = generate_test_key();

        let result = stealth.create_stealth_address(&view_key, &spend_key, &sender_key);
        assert!(result.is_ok());
        
        let address = result.unwrap();
        assert!(!address.view_public_key.is_empty());
        assert!(!address.stealth_spending_key.is_empty());
    }

    #[test]
    fn test_shared_secret_generation() {
        let stealth = TariStealthAddress::new();
        let private_key = generate_test_key();
        let public_key = generate_test_key();

        let result = stealth.generate_shared_secret(&private_key, &public_key);
        assert!(result.is_ok());
        
        let secret = result.unwrap();
        assert!(!secret.is_empty());
    }
}
