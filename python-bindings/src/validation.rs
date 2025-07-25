//! Comprehensive cryptographic validation API for Python bindings
//!
//! This module exposes Rust validation capabilities to Python applications,
//! providing secure validation of range proofs, commitments, signatures, and
//! encrypted data following PyO3 best practices.

use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError};
use pyo3::types::PyList;
use std::sync::{Arc, Mutex};
use lightweight_wallet_libs::validation::{
    LightweightCommitmentValidator,
    LightweightMinimumValuePromiseValidator,
    MinimumValuePromiseValidationOptions,
    MinimumValuePromiseValidationResult,
    LightweightEncryptedDataValidator,
    EncryptedDataValidationResult,
};
use lightweight_wallet_libs::data_structures::{
    types::{CompressedCommitment, MicroMinotari, PrivateKey},
    encrypted_data::EncryptedData,
    wallet_output::{LightweightRangeProof, LightweightRangeProofType},
};
use lightweight_wallet_libs::crypto::signing::{verify_message_from_hex};
use lightweight_wallet_libs::errors::LightweightWalletError;
use crate::errors::{convert_to_pyerr, WalletValidationError};
use crate::runtime::execute_async;

// ========== Validation Result Structures ==========

/// Python-accessible validation result containing success status and optional details
#[pyclass]
#[derive(Debug, Clone)]
pub struct ValidationResult {
    #[pyo3(get)]
    pub is_valid: bool,
    #[pyo3(get)]
    pub error_code: u32,
    #[pyo3(get)]
    pub details: Option<String>,
}

#[pymethods]
impl ValidationResult {
    #[new]
    fn new(is_valid: bool, error_code: u32, details: Option<String>) -> Self {
        Self {
            is_valid,
            error_code,
            details,
        }
    }

    fn __str__(&self) -> String {
        if self.is_valid {
            "ValidationResult(valid=True)".to_string()
        } else {
            format!(
                "ValidationResult(valid=False, error_code={}, details={})",
                self.error_code,
                self.details.as_deref().unwrap_or("None")
            )
        }
    }

    fn __repr__(&self) -> String {
        self.__str__()
    }
}

/// Batch validation results for multiple inputs
#[pyclass]
#[derive(Debug, Clone)]
pub struct BatchValidationResult {
    #[pyo3(get)]
    pub results: Vec<ValidationResult>,
    #[pyo3(get)]
    pub total_count: usize,
    #[pyo3(get)]
    pub valid_count: usize,
    #[pyo3(get)]
    pub invalid_count: usize,
}

#[pymethods]
impl BatchValidationResult {
    #[new]
    fn new(results: Vec<ValidationResult>) -> Self {
        let total_count = results.len();
        let valid_count = results.iter().filter(|r| r.is_valid).count();
        let invalid_count = total_count - valid_count;

        Self {
            results,
            total_count,
            valid_count,
            invalid_count,
        }
    }

    fn __str__(&self) -> String {
        format!(
            "BatchValidationResult(total={}, valid={}, invalid={})",
            self.total_count, self.valid_count, self.invalid_count
        )
    }

    fn __repr__(&self) -> String {
        self.__str__()
    }
}

// ========== Utility Functions ==========

/// Convert hex string to bytes with proper error handling
fn hex_to_bytes(hex_str: &str) -> PyResult<Vec<u8>> {
    hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| PyValueError::new_err(format!("Invalid hex string: {}", e)))
}

/// Convert hex string to 32-byte array for commitments
fn hex_to_commitment_bytes(hex_str: &str) -> PyResult<[u8; 32]> {
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

// ========== Range Proof Validation ==========

/// Range proof validator for BulletProofPlus and RevealedValue types
#[pyclass]
pub struct TariRangeProofValidator {
    inner: Arc<Mutex<LightweightMinimumValuePromiseValidator>>,
}

#[pymethods]
impl TariRangeProofValidator {
    #[new]
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(LightweightMinimumValuePromiseValidator::default())),
        }
    }

    /// Validate a range proof hex string
    /// 
    /// Args:
    ///     proof_hex: Hexadecimal-encoded range proof
    ///     commitment_hex: Hexadecimal-encoded commitment (32 bytes)
    ///     minimum_value: Optional minimum value promise
    /// 
    /// Returns:
    ///     bool: True if validation passes
    /// 
    /// Raises:
    ///     WalletValidationError: If validation fails with details
    ///     ValueError: If inputs are malformed
    #[pyo3(signature = (proof_hex, commitment_hex, minimum_value=None))]
    fn validate_range_proof(
        &self,
        proof_hex: &str,
        commitment_hex: &str,
        minimum_value: Option<u64>,
    ) -> PyResult<bool> {
        let proof_bytes = hex_to_bytes(proof_hex)?;
        let commitment_bytes = hex_to_commitment_bytes(commitment_hex)?;
        
        let commitment = CompressedCommitment::new(commitment_bytes);
        let minimum_value_promise = minimum_value.unwrap_or(0);
        
        // Create a lightweight range proof structure
        let range_proof = LightweightRangeProof {
            proof_type: LightweightRangeProofType::BulletProofPlus,
            proof_bytes,
        };

        let validator = self.inner.lock().unwrap();
        let options = MinimumValuePromiseValidationOptions::default();
        
        match validator.validate_minimum_value_promise(
            minimum_value_promise,
            &commitment,
            &range_proof,
            &options,
        ) {
            Ok(_) => Ok(true),
            Err(e) => Err(convert_to_pyerr(e.into())),
        }
    }

    /// Validate range proof and return detailed results
    /// 
    /// Args:
    ///     proof_hex: Hexadecimal-encoded range proof
    ///     commitment_hex: Hexadecimal-encoded commitment (32 bytes)
    ///     minimum_value: Optional minimum value promise
    /// 
    /// Returns:
    ///     ValidationResult: Detailed validation result with error information
    #[pyo3(signature = (proof_hex, commitment_hex, minimum_value=None))]
    fn validate_range_proof_detailed(
        &self,
        proof_hex: &str,
        commitment_hex: &str,
        minimum_value: Option<u64>,
    ) -> PyResult<ValidationResult> {
        match self.validate_range_proof(proof_hex, commitment_hex, minimum_value) {
            Ok(true) => Ok(ValidationResult::new(true, 0, None)),
            Ok(false) => Ok(ValidationResult::new(false, 1, Some("Range proof validation failed".to_string()))),
            Err(e) => {
                // Extract error details from Python exception
                let error_msg = format!("{}", e);
                Ok(ValidationResult::new(false, 2, Some(error_msg)))
            }
        }
    }

    /// Batch validate multiple range proofs
    /// 
    /// Args:
    ///     proof_commitment_pairs: List of (proof_hex, commitment_hex) tuples
    ///     minimum_values: Optional list of minimum values (must match pairs length)
    /// 
    /// Returns:
    ///     BatchValidationResult: Results for all validations
    fn batch_validate_range_proofs(
        &self,
        py: Python<'_>,
        proof_commitment_pairs: &PyList,
        minimum_values: Option<&PyList>,
    ) -> PyResult<BatchValidationResult> {
        let pairs: Vec<(String, String)> = proof_commitment_pairs
            .iter()
            .map(|item| {
                let tuple = item.extract::<(String, String)>()?;
                Ok(tuple)
            })
            .collect::<PyResult<Vec<_>>>()?;

        let min_values: Option<Vec<u64>> = if let Some(values) = minimum_values {
            Some(values.iter().map(|v| v.extract::<u64>()).collect::<PyResult<Vec<_>>>()?)
        } else {
            None
        };

        // Release GIL for CPU-intensive batch processing
        let results = py.allow_threads(|| {
            pairs
                .into_iter()
                .enumerate()
                .map(|(i, (proof_hex, commitment_hex))| {
                    let min_val = min_values.as_ref().and_then(|v| v.get(i)).copied();
                    self.validate_range_proof_detailed(&proof_hex, &commitment_hex, min_val)
                })
                .collect::<Result<Vec<_>, _>>()
        })?;

        Ok(BatchValidationResult::new(results))
    }
}

// ========== Commitment Validation ==========

/// Commitment structure and integrity validator
#[pyclass]
pub struct TariCommitmentValidator;

#[pymethods]
impl TariCommitmentValidator {
    #[new]
    fn new() -> Self {
        Self
    }

    /// Validate commitment structure and format
    /// 
    /// Args:
    ///     commitment_hex: Hexadecimal-encoded commitment (32 bytes)
    /// 
    /// Returns:
    ///     bool: True if validation passes
    /// 
    /// Raises:
    ///     WalletValidationError: If validation fails
    ///     ValueError: If input is malformed
    fn validate_commitment(&self, commitment_hex: &str) -> PyResult<bool> {
        let commitment_bytes = hex_to_commitment_bytes(commitment_hex)?;
        let commitment = CompressedCommitment::new(commitment_bytes);
        
        match LightweightCommitmentValidator::validate_structure(&commitment) {
            Ok(_) => Ok(true),
            Err(e) => Err(convert_to_pyerr(e.into())),
        }
    }

    /// Validate commitment with detailed results
    /// 
    /// Args:
    ///     commitment_hex: Hexadecimal-encoded commitment (32 bytes)
    /// 
    /// Returns:
    ///     ValidationResult: Detailed validation result
    fn validate_commitment_detailed(&self, commitment_hex: &str) -> PyResult<ValidationResult> {
        match self.validate_commitment(commitment_hex) {
            Ok(true) => Ok(ValidationResult::new(true, 0, None)),
            Ok(false) => Ok(ValidationResult::new(false, 1, Some("Commitment validation failed".to_string()))),
            Err(e) => {
                let error_msg = format!("{}", e);
                Ok(ValidationResult::new(false, 2, Some(error_msg)))
            }
        }
    }

    /// Batch validate multiple commitments
    /// 
    /// Args:
    ///     commitment_hexes: List of hexadecimal-encoded commitments
    /// 
    /// Returns:
    ///     BatchValidationResult: Results for all validations
    fn batch_validate_commitments(
        &self,
        py: Python<'_>,
        commitment_hexes: &PyList,
    ) -> PyResult<BatchValidationResult> {
        let hexes: Vec<String> = commitment_hexes
            .iter()
            .map(|item| item.extract::<String>())
            .collect::<PyResult<Vec<_>>>()?;

        // Release GIL for CPU-intensive batch processing
        let results = py.allow_threads(|| {
            hexes
                .into_iter()
                .map(|hex| self.validate_commitment_detailed(&hex))
                .collect::<Result<Vec<_>, _>>()
        })?;

        Ok(BatchValidationResult::new(results))
    }
}

// ========== Signature Validation ==========

/// Message signature validator using Tari-compatible signing
#[pyclass]
pub struct TariSignatureValidator;

#[pymethods]
impl TariSignatureValidator {
    #[new]
    fn new() -> Self {
        Self
    }

    /// Validate a message signature
    /// 
    /// Args:
    ///     signature_hex: Hexadecimal-encoded signature
    ///     message: Original message that was signed
    ///     public_key_hex: Hexadecimal-encoded public key
    /// 
    /// Returns:
    ///     bool: True if signature is valid
    /// 
    /// Raises:
    ///     WalletValidationError: If validation fails
    ///     ValueError: If inputs are malformed
    fn validate_signature(
        &self,
        signature_hex: &str,
        message: &str,
        public_key_hex: &str,
    ) -> PyResult<bool> {
        match verify_message_from_hex(signature_hex, message, public_key_hex) {
            Ok(is_valid) => Ok(is_valid),
            Err(e) => Err(convert_to_pyerr(e.into())),
        }
    }

    /// Validate signature with detailed results
    /// 
    /// Args:
    ///     signature_hex: Hexadecimal-encoded signature
    ///     message: Original message that was signed
    ///     public_key_hex: Hexadecimal-encoded public key
    /// 
    /// Returns:
    ///     ValidationResult: Detailed validation result
    fn validate_signature_detailed(
        &self,
        signature_hex: &str,
        message: &str,
        public_key_hex: &str,
    ) -> PyResult<ValidationResult> {
        match self.validate_signature(signature_hex, message, public_key_hex) {
            Ok(true) => Ok(ValidationResult::new(true, 0, None)),
            Ok(false) => Ok(ValidationResult::new(false, 1, Some("Signature verification failed".to_string()))),
            Err(e) => {
                let error_msg = format!("{}", e);
                Ok(ValidationResult::new(false, 2, Some(error_msg)))
            }
        }
    }

    /// Batch validate multiple signatures
    /// 
    /// Args:
    ///     signature_data: List of (signature_hex, message, public_key_hex) tuples
    /// 
    /// Returns:
    ///     BatchValidationResult: Results for all validations
    fn batch_validate_signatures(
        &self,
        py: Python<'_>,
        signature_data: &PyList,
    ) -> PyResult<BatchValidationResult> {
        let data: Vec<(String, String, String)> = signature_data
            .iter()
            .map(|item| item.extract::<(String, String, String)>())
            .collect::<PyResult<Vec<_>>>()?;

        // Release GIL for CPU-intensive batch processing
        let results = py.allow_threads(|| {
            data.into_iter()
                .map(|(sig_hex, message, pubkey_hex)| {
                    self.validate_signature_detailed(&sig_hex, &message, &pubkey_hex)
                })
                .collect::<Result<Vec<_>, _>>()
        })?;

        Ok(BatchValidationResult::new(results))
    }
}

// ========== Encrypted Data Validation ==========

/// Encrypted data integrity validator
#[pyclass]
pub struct TariEncryptedDataValidator {
    inner: Arc<Mutex<LightweightEncryptedDataValidator>>,
}

#[pymethods]
impl TariEncryptedDataValidator {
    #[new]
    #[pyo3(signature = (min_size=64, max_size=1024))]
    fn new(min_size: usize, max_size: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(LightweightEncryptedDataValidator::new(min_size, max_size))),
        }
    }

    /// Validate encrypted data integrity without decryption
    /// 
    /// Args:
    ///     encrypted_data_hex: Hexadecimal-encoded encrypted data
    /// 
    /// Returns:
    ///     bool: True if validation passes
    /// 
    /// Raises:
    ///     WalletValidationError: If validation fails
    ///     ValueError: If input is malformed
    fn validate_encrypted_data(&self, encrypted_data_hex: &str) -> PyResult<bool> {
        let data_bytes = hex_to_bytes(encrypted_data_hex)?;
        let encrypted_data = EncryptedData::from_bytes(&data_bytes)
            .map_err(|e| PyValueError::new_err(format!("Invalid encrypted data format: {}", e)))?;
        
        let validator = self.inner.lock().unwrap();
        match validator.validate_integrity(&encrypted_data) {
            Ok(_) => Ok(true),
            Err(e) => Err(convert_to_pyerr(e.into())),
        }
    }

    /// Validate encrypted data with detailed results
    /// 
    /// Args:
    ///     encrypted_data_hex: Hexadecimal-encoded encrypted data
    /// 
    /// Returns:
    ///     ValidationResult: Detailed validation result
    fn validate_encrypted_data_detailed(&self, encrypted_data_hex: &str) -> PyResult<ValidationResult> {
        match self.validate_encrypted_data(encrypted_data_hex) {
            Ok(true) => Ok(ValidationResult::new(true, 0, None)),
            Ok(false) => Ok(ValidationResult::new(false, 1, Some("Encrypted data validation failed".to_string()))),
            Err(e) => {
                let error_msg = format!("{}", e);
                Ok(ValidationResult::new(false, 2, Some(error_msg)))
            }
        }
    }

    /// Batch validate multiple encrypted data items
    /// 
    /// Args:
    ///     encrypted_data_hexes: List of hexadecimal-encoded encrypted data
    /// 
    /// Returns:
    ///     BatchValidationResult: Results for all validations
    fn batch_validate_encrypted_data(
        &self,
        py: Python<'_>,
        encrypted_data_hexes: &PyList,
    ) -> PyResult<BatchValidationResult> {
        let hexes: Vec<String> = encrypted_data_hexes
            .iter()
            .map(|item| item.extract::<String>())
            .collect::<PyResult<Vec<_>>>()?;

        // Release GIL for CPU-intensive batch processing
        let results = py.allow_threads(|| {
            hexes
                .into_iter()
                .map(|hex| self.validate_encrypted_data_detailed(&hex))
                .collect::<Result<Vec<_>, _>>()
        })?;

        Ok(BatchValidationResult::new(results))
    }
}
