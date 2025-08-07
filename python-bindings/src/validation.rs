//! Comprehensive cryptographic validation API for Python bindings
//!
//! This module exposes Rust validation capabilities to Python applications,
//! providing secure validation of range proofs, commitments, signatures, and
//! encrypted data following PyO3 best practices.

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use pyo3::types::PyList;
use std::sync::{Arc, Mutex};
use lightweight_wallet_libs::validation::{
    LightweightEncryptedDataValidator as CoreLightweightEncryptedDataValidator,
};
use lightweight_wallet_libs::data_structures::{
    types::CompressedCommitment,
    encrypted_data::EncryptedData,
    wallet_output::LightweightRangeProofType,
};
use lightweight_wallet_libs::validation::minimum_value_promise::{MinimumValuePromiseValidationOptions, LightweightMinimumValuePromiseValidator};
use crate::utils::{hex_to_bytes, hex_to_commitment_bytes};
use crate::crypto::PyMicroMinotari;
use crate::transaction::PyRangeProof;


// ========== Constants ==========

/// Fixed chunk size for memory-efficient batch processing
const DEFAULT_CHUNK_SIZE: usize = 1000;

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


// ========== Commitment Validation ==========

/// Commitment structure and integrity validator
#[pyclass]
pub struct LightweightCommitmentValidator;

#[pymethods]
impl LightweightCommitmentValidator {
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
        
        match lightweight_wallet_libs::validation::LightweightCommitmentValidator::validate_structure(&commitment) {
            Ok(_) => Ok(true),
            Err(e) => Err(PyValueError::new_err(format!("Validation error: {}", e)).into()),
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
    ///     chunk_size: Optional chunk size for memory management (default: 1000)
    /// 
    /// Returns:
    ///     BatchValidationResult: Results for all validations
    #[pyo3(signature = (commitment_hexes, chunk_size=None))]
    fn batch_validate_commitments(
        &self,
        py: Python<'_>,
        commitment_hexes: &Bound<'_, PyList>,
        chunk_size: Option<usize>,
    ) -> PyResult<BatchValidationResult> {
        let mut hexes = Vec::new();
        for item in commitment_hexes.iter() {
            hexes.push(item.extract::<String>()?);
        }

        let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);

        // Process in chunks for memory efficiency
        let results = py.allow_threads(|| {
            self.process_commitments_in_chunks(hexes, chunk_size)
        })?;

        Ok(BatchValidationResult::new(results))
    }
}

impl LightweightCommitmentValidator {
    /// Internal method to process commitments in chunks
    fn process_commitments_in_chunks(
        &self,
        hexes: Vec<String>,
        chunk_size: usize,
    ) -> PyResult<Vec<ValidationResult>> {
        process_validation_in_chunks(hexes, chunk_size, |hex| {
            self.validate_commitment_detailed(hex)
        })
    }
}



// ========== Encrypted Data Validation ==========

/// Encrypted data integrity validator
#[pyclass]
pub struct LightweightEncryptedDataValidator {
    inner: Arc<Mutex<CoreLightweightEncryptedDataValidator>>,
}

#[pymethods]
impl LightweightEncryptedDataValidator {
    #[new]
    #[pyo3(signature = (min_size=64, max_size=1024))]
    fn new(min_size: usize, max_size: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CoreLightweightEncryptedDataValidator::new(min_size, max_size))),
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
            Err(e) => Err(PyValueError::new_err(format!("Validation error: {}", e)).into()),
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
    ///     chunk_size: Optional chunk size for memory management (default: 1000)
    /// 
    /// Returns:
    ///     BatchValidationResult: Results for all validations
    #[pyo3(signature = (encrypted_data_hexes, chunk_size=None))]
    fn batch_validate_encrypted_data(
        &self,
        py: Python<'_>,
        encrypted_data_hexes: &Bound<'_, PyList>,
        chunk_size: Option<usize>,
    ) -> PyResult<BatchValidationResult> {
        let mut hexes = Vec::new();
        for item in encrypted_data_hexes.iter() {
            hexes.push(item.extract::<String>()?);
        }

        let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);

        // Process in chunks for memory efficiency
        let results = py.allow_threads(|| {
            self.process_encrypted_data_in_chunks(hexes, chunk_size)
        })?;

        Ok(BatchValidationResult::new(results))
    }
}

impl LightweightEncryptedDataValidator {
    /// Internal method to process encrypted data in chunks
    fn process_encrypted_data_in_chunks(
        &self,
        hexes: Vec<String>,
        chunk_size: usize,
    ) -> PyResult<Vec<ValidationResult>> {
        process_validation_in_chunks(hexes, chunk_size, |hex| {
            self.validate_encrypted_data_detailed(hex)
        })
    }
}

#[pyclass(name = "MinimumValuePromiseValidationOptions")]
pub struct PyMinimumValuePromiseValidationOptions {
    pub inner: MinimumValuePromiseValidationOptions,
}

#[pymethods]
impl PyMinimumValuePromiseValidationOptions {
    #[new]
    pub fn new(
        validate_range_proof_bounds: Option<bool>,
        validate_revealed_value_consistency: Option<bool>,
        validate_bulletproof_consistency: Option<bool>,
        allow_zero_values: Option<bool>,
        max_allowed_value: Option<u64>,
    ) -> Self {
        Self {
            inner: MinimumValuePromiseValidationOptions {
                validate_range_proof_bounds: validate_range_proof_bounds.unwrap_or(true),
                validate_revealed_value_consistency: validate_revealed_value_consistency.unwrap_or(true),
                validate_bulletproof_consistency: validate_bulletproof_consistency.unwrap_or(true),
                allow_zero_values: allow_zero_values.unwrap_or(true),
                max_allowed_value,
            },
        }
    }

    #[getter]
    pub fn validate_range_proof_bounds(&self) -> bool {
        self.inner.validate_range_proof_bounds
    }
    #[setter]
    pub fn set_validate_range_proof_bounds(&mut self, value: bool) {
        self.inner.validate_range_proof_bounds = value;
    }

    #[getter]
    pub fn validate_revealed_value_consistency(&self) -> bool {
        self.inner.validate_revealed_value_consistency
    }
    #[setter]
    pub fn set_validate_revealed_value_consistency(&mut self, value: bool) {
        self.inner.validate_revealed_value_consistency = value;
    }

    #[getter]
    pub fn validate_bulletproof_consistency(&self) -> bool {
        self.inner.validate_bulletproof_consistency
    }
    #[setter]
    pub fn set_validate_bulletproof_consistency(&mut self, value: bool) {
        self.inner.validate_bulletproof_consistency = value;
    }

    #[getter]
    pub fn allow_zero_values(&self) -> bool {
        self.inner.allow_zero_values
    }
    #[setter]
    pub fn set_allow_zero_values(&mut self, value: bool) {
        self.inner.allow_zero_values = value;
    }

    #[getter]
    pub fn max_allowed_value(&self) -> Option<u64> {
        self.inner.max_allowed_value
    }
    #[setter]
    pub fn set_max_allowed_value(&mut self, value: Option<u64>) {
        self.inner.max_allowed_value = value;
    }
}

#[pyclass(name = "LightweightMinimumValuePromiseValidator")]
pub struct PyLightweightMinimumValuePromiseValidator {
    pub inner: LightweightMinimumValuePromiseValidator,
}

#[pymethods]
impl PyLightweightMinimumValuePromiseValidator {
    #[new]
    pub fn new(bit_length: Option<usize>) -> Self {
        let bit_length = bit_length.unwrap_or(64);
        Self {
            inner: LightweightMinimumValuePromiseValidator::new(bit_length),
        }
    }

    pub fn validate_minimum_value_promise(
        &self,
        minimum_value_promise: &PyMicroMinotari,
        range_proof: Option<&PyRangeProof>,
        range_proof_type_str: &str,
        options: &PyMinimumValuePromiseValidationOptions,
    ) -> PyResult<bool> {
        let range_proof = range_proof.map(|rp| rp.inner());
        
        // Convert string to LightweightRangeProofType
        let range_proof_type = match range_proof_type_str {
            "BulletProofPlus" => LightweightRangeProofType::BulletProofPlus,
            "RevealedValue" => LightweightRangeProofType::RevealedValue,
            _ => return Err(PyValueError::new_err(format!("Invalid range proof type: {}", range_proof_type_str))),
        };
        
        match self.inner.validate_minimum_value_promise(
            minimum_value_promise.inner(),
            range_proof,
            &range_proof_type,
            &options.inner,
        ) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Generic chunk processing function to eliminate duplication
fn process_validation_in_chunks<F>(
    hexes: Vec<String>,
    chunk_size: usize,
    validator: F,
) -> PyResult<Vec<ValidationResult>>
where
    F: Fn(&str) -> PyResult<ValidationResult>,
{
    let mut all_results = Vec::new();
    
    for chunk in hexes.chunks(chunk_size) {
        let chunk_results: Result<Vec<ValidationResult>, PyErr> = chunk
            .iter()
            .map(|hex| validator(hex))
            .collect();
        
        match chunk_results {
            Ok(mut results) => all_results.append(&mut results),
            Err(e) => return Err(e),
        }
    }
    
    Ok(all_results)
}


