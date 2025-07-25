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
    LightweightCommitmentValidator,
    LightweightMinimumValuePromiseValidator,
    MinimumValuePromiseValidationOptions,
    LightweightEncryptedDataValidator,
};
use lightweight_wallet_libs::data_structures::{
    types::{CompressedCommitment, MicroMinotari},
    encrypted_data::EncryptedData,
    wallet_output::{LightweightRangeProof, LightweightRangeProofType},
};
use lightweight_wallet_libs::crypto::signing::verify_message_from_hex;
use crate::errors::convert_to_pyerr;
use std::time::Instant;

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
        let _commitment_bytes = hex_to_commitment_bytes(commitment_hex)?;
        
        let minimum_value_promise = minimum_value.unwrap_or(0);
        
        // Create a lightweight range proof structure
        let range_proof = LightweightRangeProof {
            bytes: proof_bytes,
        };

        let validator = self.inner.lock().unwrap();
        let options = MinimumValuePromiseValidationOptions::default();
        let minimum_value = MicroMinotari::new(minimum_value_promise);
        
        match validator.validate_minimum_value_promise(
            minimum_value,
            Some(&range_proof),
            &LightweightRangeProofType::BulletProofPlus,
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
    ///     chunk_size: Optional chunk size for memory management (default: 1000)
    /// 
    /// Returns:
    ///     BatchValidationResult: Results for all validations
    #[pyo3(signature = (proof_commitment_pairs, minimum_values=None, chunk_size=None))]
    fn batch_validate_range_proofs(
        &self,
        py: Python<'_>,
        proof_commitment_pairs: &Bound<'_, PyList>,
        minimum_values: Option<&Bound<'_, PyList>>,
        chunk_size: Option<usize>,
    ) -> PyResult<BatchValidationResult> {
        let mut pairs = Vec::new();
        for item in proof_commitment_pairs.iter() {
            let tuple: (String, String) = item.extract()?;
            pairs.push(tuple);
        }

        let min_values: Option<Vec<u64>> = if let Some(values) = minimum_values {
            let mut vals = Vec::new();
            for v in values.iter() {
                vals.push(v.extract::<u64>()?);
            }
            Some(vals)
        } else {
            None
        };

        let config = ChunkConfig::new(chunk_size.unwrap_or(1000));
        
        // Process in chunks for memory efficiency
        let results = py.allow_threads(|| {
            self.process_range_proofs_in_chunks(pairs, min_values, &config)
        })?;

        Ok(BatchValidationResult::new(results))
    }
}

impl TariRangeProofValidator {
    /// Internal method to process range proofs in chunks
    fn process_range_proofs_in_chunks(
        &self,
        pairs: Vec<(String, String)>,
        min_values: Option<Vec<u64>>,
        config: &ChunkConfig,
    ) -> PyResult<Vec<ValidationResult>> {
        let mut all_results = Vec::new();
        let start_time = Instant::now();
        let total_items = pairs.len();
        
        for (chunk_idx, chunk) in pairs.chunks(config.chunk_size).enumerate() {
            let chunk_start = Instant::now();
            
            let chunk_results: Result<Vec<ValidationResult>, PyErr> = chunk
                .iter()
                .enumerate()
                .map(|(idx, (proof_hex, commitment_hex))| {
                    let global_idx = chunk_idx * config.chunk_size + idx;
                    let min_val = min_values.as_ref().and_then(|v| v.get(global_idx)).copied();
                    self.validate_range_proof_detailed(proof_hex, commitment_hex, min_val)
                })
                .collect();
            
            match chunk_results {
                Ok(mut results) => {
                    all_results.append(&mut results);
                    let chunk_duration = chunk_start.elapsed();
                    // Log performance for large chunks (could be configurable in future)
                    if chunk.len() > 100 {
                        eprintln!("Range proof chunk {}: {} items in {:?}", 
                                 chunk_idx, chunk.len(), chunk_duration);
                    }
                },
                Err(e) => return Err(e),
            }
        }
        
        let total_duration = start_time.elapsed();
        if total_items > 1000 {
            eprintln!("Range proof validation completed: {} items in {:?} ({:.2} items/sec)", 
                     total_items, total_duration, 
                     total_items as f64 / total_duration.as_secs_f64());
        }
        
        Ok(all_results)
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

impl TariCommitmentValidator {
    /// Internal method to process commitments in chunks
    fn process_commitments_in_chunks(
        &self,
        hexes: Vec<String>,
        config: &ChunkConfig,
    ) -> PyResult<Vec<ValidationResult>> {
        let mut all_results = Vec::new();
        let start_time = Instant::now();
        let total_items = hexes.len();
        
        for (chunk_idx, chunk) in hexes.chunks(config.chunk_size).enumerate() {
            let chunk_start = Instant::now();
            
            let chunk_results: Result<Vec<ValidationResult>, PyErr> = chunk
                .iter()
                .map(|hex| self.validate_commitment_detailed(hex))
                .collect();
            
            match chunk_results {
                Ok(mut results) => {
                    all_results.append(&mut results);
                    let chunk_duration = chunk_start.elapsed();
                    if chunk.len() > 100 {
                        eprintln!("Commitment chunk {}: {} items in {:?}", 
                                 chunk_idx, chunk.len(), chunk_duration);
                    }
                },
                Err(e) => return Err(e),
            }
        }
        
        let total_duration = start_time.elapsed();
        if total_items > 1000 {
            eprintln!("Commitment validation completed: {} items in {:?} ({:.2} items/sec)", 
                     total_items, total_duration, 
                     total_items as f64 / total_duration.as_secs_f64());
        }
        
        Ok(all_results)
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
    ///     signature_hex: Hexadecimal-encoded signature scalar
    ///     nonce_hex: Hexadecimal-encoded public nonce
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
        nonce_hex: &str,
        message: &str,
        public_key_hex: &str,
    ) -> PyResult<bool> {
        use lightweight_wallet_libs::crypto::RistrettoPublicKey;
        use tari_utilities::hex::Hex;
        
        let public_key = RistrettoPublicKey::from_hex(public_key_hex)
            .map_err(|e| PyValueError::new_err(format!("Invalid public key hex: {}", e)))?;
        
        match verify_message_from_hex(&public_key, message, signature_hex, nonce_hex) {
            Ok(is_valid) => Ok(is_valid),
            Err(e) => Err(convert_to_pyerr(e)),
        }
    }

    /// Validate signature with detailed results
    /// 
    /// Args:
    ///     signature_hex: Hexadecimal-encoded signature scalar
    ///     nonce_hex: Hexadecimal-encoded public nonce
    ///     message: Original message that was signed
    ///     public_key_hex: Hexadecimal-encoded public key
    /// 
    /// Returns:
    ///     ValidationResult: Detailed validation result
    fn validate_signature_detailed(
        &self,
        signature_hex: &str,
        nonce_hex: &str,
        message: &str,
        public_key_hex: &str,
    ) -> PyResult<ValidationResult> {
        match self.validate_signature(signature_hex, nonce_hex, message, public_key_hex) {
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
    ///     signature_data: List of (signature_hex, nonce_hex, message, public_key_hex) tuples
    ///     chunk_size: Optional chunk size for memory management (default: 1000)
    /// 
    /// Returns:
    ///     BatchValidationResult: Results for all validations
    #[pyo3(signature = (signature_data, chunk_size=None))]
    fn batch_validate_signatures(
        &self,
        py: Python<'_>,
        signature_data: &Bound<'_, PyList>,
        chunk_size: Option<usize>,
    ) -> PyResult<BatchValidationResult> {
        let mut data = Vec::new();
        for item in signature_data.iter() {
            let tuple: (String, String, String, String) = item.extract()?;
            data.push(tuple);
        }

        let config = ChunkConfig::new(chunk_size.unwrap_or(1000));

        // Process in chunks for memory efficiency
        let results = py.allow_threads(|| {
            self.process_signatures_in_chunks(data, &config)
        })?;

        Ok(BatchValidationResult::new(results))
    }
}

impl TariSignatureValidator {
    /// Internal method to process signatures in chunks
    fn process_signatures_in_chunks(
        &self,
        data: Vec<(String, String, String, String)>,
        config: &ChunkConfig,
    ) -> PyResult<Vec<ValidationResult>> {
        let mut all_results = Vec::new();
        
        for chunk in data.chunks(config.chunk_size) {
            let chunk_results: Result<Vec<ValidationResult>, PyErr> = chunk
                .iter()
                .map(|(sig_hex, nonce_hex, message, pubkey_hex)| {
                    self.validate_signature_detailed(sig_hex, nonce_hex, message, pubkey_hex)
                })
                .collect();
            
            match chunk_results {
                Ok(mut results) => all_results.append(&mut results),
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
