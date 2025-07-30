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
    LightweightEncryptedDataValidator,
};
use lightweight_wallet_libs::data_structures::{
    types::CompressedCommitment,
    encrypted_data::EncryptedData,
};
use crate::errors::convert_to_pyerr;


// ========== Chunk Configuration ==========

/// Configuration for chunked batch processing
#[derive(Debug, Clone)]
pub struct ChunkConfig {
    pub chunk_size: usize,
    #[allow(dead_code)]  // Reserved for future memory limiting feature
    pub max_memory_mb: Option<usize>,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            chunk_size: 1000,  // Default chunk size balances memory and performance
            max_memory_mb: None,  // No memory limit by default
        }
    }
}

impl ChunkConfig {
    pub fn new(chunk_size: usize) -> Self {
        Self {
            chunk_size,
            max_memory_mb: None,
        }
    }

    #[allow(dead_code)]  // Reserved for future memory limiting feature
    pub fn with_memory_limit(chunk_size: usize, max_memory_mb: usize) -> Self {
        Self {
            chunk_size,
            max_memory_mb: Some(max_memory_mb),
        }
    }
}

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

        let config = ChunkConfig::new(chunk_size.unwrap_or(1000));

        // Process in chunks for memory efficiency
        let results = py.allow_threads(|| {
            self.process_commitments_in_chunks(hexes, &config)
        })?;

        Ok(BatchValidationResult::new(results))
    }
}

impl LightweightCommitmentValidator {
    /// Internal method to process commitments in chunks
    fn process_commitments_in_chunks(
        &self,
        hexes: Vec<String>,
        config: &ChunkConfig,
    ) -> PyResult<Vec<ValidationResult>> {
        let mut all_results = Vec::new();
        
        for chunk in hexes.chunks(config.chunk_size) {
            
            let chunk_results: Result<Vec<ValidationResult>, PyErr> = chunk
                .iter()
                .map(|hex| self.validate_commitment_detailed(hex))
                .collect();
            
            match chunk_results {
                Ok(mut results) => {
                    all_results.append(&mut results);
                },
                Err(e) => return Err(e),
            }
        }
        

        
        Ok(all_results)
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

        let config = ChunkConfig::new(chunk_size.unwrap_or(1000));

        // Process in chunks for memory efficiency
        let results = py.allow_threads(|| {
            self.process_encrypted_data_in_chunks(hexes, &config)
        })?;

        Ok(BatchValidationResult::new(results))
    }
}

impl TariEncryptedDataValidator {
    /// Internal method to process encrypted data in chunks
    fn process_encrypted_data_in_chunks(
        &self,
        hexes: Vec<String>,
        config: &ChunkConfig,
    ) -> PyResult<Vec<ValidationResult>> {
        let mut all_results = Vec::new();
        
        for chunk in hexes.chunks(config.chunk_size) {
            let chunk_results: Result<Vec<ValidationResult>, PyErr> = chunk
                .iter()
                .map(|hex| self.validate_encrypted_data_detailed(hex))
                .collect();
            
            match chunk_results {
                Ok(mut results) => all_results.append(&mut results),
                Err(e) => return Err(e),
            }
        }
        
        Ok(all_results)
    }
}


