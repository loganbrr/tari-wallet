//! UTXO Validation Engine - Comprehensive ownership and value validation for UTXO sets
//!
//! This module provides the TariUTXOValidator class that wraps Rust extraction and validation
//! modules to provide complete UTXO validation capabilities through PyO3 Python bindings.
//!
//! # Security Design
//! - Direct Rust core mapping following batch_validation.rs patterns
//! - Fixed 1000-item chunking for memory efficiency
//! - No convenience methods - 1:1 API parity with Rust validation system
//! - Thread-safe operations using Arc<Mutex<T>> patterns
//!
//! # Key Features
//! - Ownership validation through encrypted data decryption
//! - Value extraction through DecryptionResult processing
//! - Payment ID extraction using existing extraction modules
//! - Batch validation with memory-efficient chunking
//! - Integration with existing validation framework

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::sync::{Arc, Mutex};

use crate::errors::LightweightWalletError;
use crate::runtime::execute_async;

use lightweight_wallet_libs::data_structures::{
    transaction_output::LightweightTransactionOutput,
    encrypted_data::EncryptedDataDecryptor,
};
use lightweight_wallet_libs::extraction::{
    batch_validation::{BatchValidationOptions, validate_output_batch},
    payment_id_extraction::extract_payment_id_from_output,
};
use lightweight_wallet_libs::validation::range_proofs::verify_range_proof;
use lightweight_wallet_libs::key_management::PrivateKey;

/// Configuration options for UTXO validation operations
#[pyclass(name = "UTXOValidationConfig")]
#[derive(Clone)]
pub struct UTXOValidationConfig {
    /// Enable ownership validation through encrypted data decryption
    pub validate_ownership: bool,
    /// Enable value extraction from outputs
    pub extract_values: bool,
    /// Enable payment ID extraction
    pub extract_payment_ids: bool,
    /// Enable range proof validation
    pub validate_range_proofs: bool,
    /// Chunk size for batch processing (fixed at 1000 for memory efficiency)
    pub chunk_size: usize,
}

#[pymethods]
impl UTXOValidationConfig {
    #[new]
    #[pyo3(signature = (validate_ownership=true, extract_values=true, extract_payment_ids=true, validate_range_proofs=true))]
    fn new(
        validate_ownership: bool,
        extract_values: bool,
        extract_payment_ids: bool,
        validate_range_proofs: bool,
    ) -> Self {
        Self {
            validate_ownership,
            extract_values,
            extract_payment_ids,
            validate_range_proofs,
            chunk_size: 1000, // Fixed for memory efficiency
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "UTXOValidationConfig(ownership={}, values={}, payment_ids={}, range_proofs={}, chunk_size={})",
            self.validate_ownership,
            self.extract_values,
            self.extract_payment_ids,
            self.validate_range_proofs,
            self.chunk_size
        )
    }
}

/// Result of UTXO validation containing ownership, value, and payment ID information
#[pyclass(name = "UTXOValidationResult")]
#[derive(Clone)]
pub struct UTXOValidationResult {
    /// Whether the UTXO is owned by the wallet
    pub is_owned: bool,
    /// Extracted value (if ownership validation successful)
    pub value: Option<u64>,
    /// Extracted payment ID (if present)
    pub payment_id: Option<String>,
    /// Range proof validation result
    pub range_proof_valid: Option<bool>,
    /// Validation errors (if any)
    pub errors: Vec<String>,
}

#[pymethods]
impl UTXOValidationResult {
    #[getter]
    fn is_owned(&self) -> bool {
        self.is_owned
    }

    #[getter]
    fn value(&self) -> Option<u64> {
        self.value
    }

    #[getter]
    fn payment_id(&self) -> Option<String> {
        self.payment_id.clone()
    }

    #[getter]
    fn range_proof_valid(&self) -> Option<bool> {
        self.range_proof_valid
    }

    #[getter]
    fn errors(&self) -> Vec<String> {
        self.errors.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "UTXOValidationResult(owned={}, value={:?}, payment_id={:?}, range_proof_valid={:?}, errors={})",
            self.is_owned,
            self.value,
            self.payment_id,
            self.range_proof_valid,
            self.errors.len()
        )
    }
}

/// Summary of batch validation results
#[pyclass(name = "BatchValidationSummary")]
#[derive(Clone)]
pub struct BatchValidationSummary {
    /// Total number of outputs processed
    pub total_outputs: usize,
    /// Number of outputs owned by wallet
    pub owned_outputs: usize,
    /// Number of outputs with successful value extraction
    pub valid_outputs: usize,
    /// Number of outputs with payment IDs
    pub payment_id_outputs: usize,
    /// Number of outputs with valid range proofs
    pub valid_range_proofs: usize,
    /// Overall success rate (owned outputs / total outputs)
    pub success_rate: f64,
}

#[pymethods]
impl BatchValidationSummary {
    #[getter]
    fn total_outputs(&self) -> usize {
        self.total_outputs
    }

    #[getter]
    fn owned_outputs(&self) -> usize {
        self.owned_outputs
    }

    #[getter]
    fn valid_outputs(&self) -> usize {
        self.valid_outputs
    }

    #[getter]
    fn payment_id_outputs(&self) -> usize {
        self.payment_id_outputs
    }

    #[getter]
    fn valid_range_proofs(&self) -> usize {
        self.valid_range_proofs
    }

    #[getter]
    fn success_rate(&self) -> f64 {
        self.success_rate
    }

    fn __repr__(&self) -> String {
        format!(
            "BatchValidationSummary(total={}, owned={}, valid={}, payment_ids={}, valid_proofs={}, success_rate={:.2}%)",
            self.total_outputs,
            self.owned_outputs,
            self.valid_outputs,
            self.payment_id_outputs,
            self.valid_range_proofs,
            self.success_rate * 100.0
        )
    }
}

/// Core UTXO validation engine providing ownership detection, value extraction, and payment ID processing
#[pyclass(name = "TariUTXOValidator")]
pub struct TariUTXOValidator {
    /// Encrypted data decryptor for ownership validation
    decryptor: Arc<Mutex<EncryptedDataDecryptor>>,
    /// Validation configuration
    config: UTXOValidationConfig,
}

#[pymethods]
impl TariUTXOValidator {
    /// Create a new UTXO validator with wallet keys
    ///
    /// # Arguments
    /// * `view_key_hex` - Wallet view key as hex string
    /// * `spend_key_hex` - Wallet spend key as hex string
    /// * `config` - Validation configuration options
    #[new]
    #[pyo3(signature = (view_key_hex, spend_key_hex, config=None))]
    fn new(
        view_key_hex: &str,
        spend_key_hex: &str,
        config: Option<UTXOValidationConfig>,
    ) -> PyResult<Self> {
        let config = config.unwrap_or_else(|| UTXOValidationConfig::new(true, true, true, true));

        // Parse wallet keys
        let view_key_bytes = hex::decode(view_key_hex)
            .map_err(|e| LightweightWalletError::ConversionError(format!("Invalid view key hex: {}", e)))?;
        let spend_key_bytes = hex::decode(spend_key_hex)
            .map_err(|e| LightweightWalletError::ConversionError(format!("Invalid spend key hex: {}", e)))?;

        if view_key_bytes.len() != 32 {
            return Err(LightweightWalletError::ConversionError("View key must be 32 bytes".to_string()).into());
        }
        if spend_key_bytes.len() != 32 {
            return Err(LightweightWalletError::ConversionError("Spend key must be 32 bytes".to_string()).into());
        }

        let view_key = PrivateKey::from_bytes(&view_key_bytes)
            .map_err(|e| LightweightWalletError::CryptoError(format!("Invalid view key: {}", e)))?;
        let spend_key = PrivateKey::from_bytes(&spend_key_bytes)
            .map_err(|e| LightweightWalletError::CryptoError(format!("Invalid spend key: {}", e)))?;

        // Create decryptor for ownership validation
        let decryptor = EncryptedDataDecryptor::new(view_key, spend_key);

        Ok(Self {
            decryptor: Arc::new(Mutex::new(decryptor)),
            config,
        })
    }

    /// Validate a single UTXO for ownership, value, and payment ID
    ///
    /// # Arguments
    /// * `output_dict` - Dictionary containing UTXO data
    ///
    /// # Returns
    /// UTXOValidationResult with validation information
    #[pyo3(signature = (output_dict))]
    fn validate_utxo(&self, py: Python, output_dict: &Bound<'_, PyDict>) -> PyResult<UTXOValidationResult> {
        // Process synchronously since we need to access PyDict
        self.validate_utxo_internal(output_dict)
    }

    /// Validate a batch of UTXOs with memory-efficient chunking
    ///
    /// # Arguments
    /// * `output_list` - List of UTXO dictionaries
    ///
    /// # Returns
    /// Tuple of (results_list, summary)
    #[pyo3(signature = (output_list))]
    fn validate_batch(
        &self,
        py: Python,
        output_list: &Bound<'_, PyList>,
    ) -> PyResult<(Vec<UTXOValidationResult>, BatchValidationSummary)> {
        // Process synchronously since we need to access PyList
        self.validate_batch_internal(output_list)
    }

    /// Get current validation configuration
    #[getter]
    fn config(&self) -> UTXOValidationConfig {
        self.config.clone()
    }

    /// Update validation configuration
    #[setter]
    fn set_config(&mut self, config: UTXOValidationConfig) {
        self.config = config;
    }

    fn __repr__(&self) -> String {
        format!("TariUTXOValidator(config={})", self.config.__repr__())
    }
}

impl TariUTXOValidator {
    /// Internal method for validating a single UTXO
    fn validate_utxo_internal(&self, output_dict: &Bound<'_, PyDict>) -> PyResult<UTXOValidationResult> {
        let mut result = UTXOValidationResult {
            is_owned: false,
            value: None,
            payment_id: None,
            range_proof_valid: None,
            errors: Vec::new(),
        };

        // Convert Python dict to LightweightTransactionOutput
        let output = match self.dict_to_output(output_dict) {
            Ok(output) => output,
            Err(e) => {
                result.errors.push(format!("Failed to parse output: {}", e));
                return Ok(result);
            }
        };

        // Perform ownership validation if enabled
        if self.config.validate_ownership {
            match self.validate_ownership(&output) {
                Ok((is_owned, value, payment_id)) => {
                    result.is_owned = is_owned;
                    result.value = value;
                    result.payment_id = payment_id;
                }
                Err(e) => {
                    result.errors.push(format!("Ownership validation failed: {}", e));
                }
            }
        }

        // Perform range proof validation if enabled
        if self.config.validate_range_proofs {
            match self.validate_range_proof(&output) {
                Ok(valid) => result.range_proof_valid = Some(valid),
                Err(e) => {
                    result.errors.push(format!("Range proof validation failed: {}", e));
                }
            }
        }

        Ok(result)
    }

    /// Internal method for batch validation with chunking
    fn validate_batch_internal(
        &self,
        output_list: &Bound<'_, PyList>,
    ) -> PyResult<(Vec<UTXOValidationResult>, BatchValidationSummary)> {
        let mut all_results = Vec::new();
        let total_outputs = output_list.len();
        
        // Process in chunks for memory efficiency
        for chunk_start in (0..total_outputs).step_by(self.config.chunk_size) {
            let chunk_end = std::cmp::min(chunk_start + self.config.chunk_size, total_outputs);
            let mut chunk_results = Vec::new();

            for i in chunk_start..chunk_end {
                let output_dict = output_list.get_item(i)?
                    .downcast::<PyDict>()
                    .map_err(|_| LightweightWalletError::ConversionError("Expected dictionary for output".to_string()))?;

                let result = self.validate_utxo_internal(output_dict)?;
                chunk_results.push(result);
            }

            all_results.extend(chunk_results);
        }

        // Generate summary statistics
        let summary = self.generate_summary(&all_results);

        Ok((all_results, summary))
    }

    /// Validate ownership of a UTXO through encrypted data decryption
    fn validate_ownership(
        &self,
        output: &LightweightTransactionOutput,
    ) -> Result<(bool, Option<u64>, Option<String>), String> {
        let decryptor = self.decryptor.lock()
            .map_err(|_| "Failed to acquire decryptor lock".to_string())?;

        // Attempt to decrypt the output
        match decryptor.decrypt_output_data(output) {
            Ok(decryption_result) => {
                let value = if self.config.extract_values {
                    Some(decryption_result.value)
                } else {
                    None
                };

                let payment_id = if self.config.extract_payment_ids {
                    extract_payment_id_from_output(output)
                        .ok()
                        .flatten()
                        .map(|id| hex::encode(id))
                } else {
                    None
                };

                Ok((true, value, payment_id))
            }
            Err(_) => {
                // Failed decryption means we don't own this output
                Ok((false, None, None))
            }
        }
    }

    /// Validate range proof for a UTXO
    fn validate_range_proof(&self, output: &LightweightTransactionOutput) -> Result<bool, String> {
        // Use existing range proof validation from validation module
        verify_range_proof(&output.range_proof, &output.commitment)
            .map_err(|e| format!("Range proof validation error: {}", e))
    }

    /// Convert Python dictionary to LightweightTransactionOutput
    fn dict_to_output(&self, output_dict: &Bound<'_, PyDict>) -> PyResult<LightweightTransactionOutput> {
        // Extract required fields from dictionary
        let commitment_hex = output_dict.get_item("commitment")?
            .ok_or_else(|| LightweightWalletError::ConversionError("Missing 'commitment' field".to_string()))?
            .extract::<String>()?;

        let range_proof_hex = output_dict.get_item("range_proof")?
            .ok_or_else(|| LightweightWalletError::ConversionError("Missing 'range_proof' field".to_string()))?
            .extract::<String>()?;

        let encrypted_data_hex = output_dict.get_item("encrypted_data")?
            .ok_or_else(|| LightweightWalletError::ConversionError("Missing 'encrypted_data' field".to_string()))?
            .extract::<String>()?;

        // Parse hex fields
        let commitment = hex::decode(commitment_hex)
            .map_err(|e| LightweightWalletError::ConversionError(format!("Invalid commitment hex: {}", e)))?;
        let range_proof = hex::decode(range_proof_hex)
            .map_err(|e| LightweightWalletError::ConversionError(format!("Invalid range proof hex: {}", e)))?;
        let encrypted_data = hex::decode(encrypted_data_hex)
            .map_err(|e| LightweightWalletError::ConversionError(format!("Invalid encrypted data hex: {}", e)))?;

        // Create LightweightTransactionOutput
        // Note: This is a simplified conversion - actual implementation would need proper
        // field mapping based on the complete LightweightTransactionOutput structure
        let output = LightweightTransactionOutput {
            commitment: commitment.try_into()
                .map_err(|_| TariError::InvalidInput("Invalid commitment length".to_string()))?,
            range_proof: range_proof.into(),
            encrypted_data: encrypted_data.into(),
            // Default values for other fields - actual implementation would parse these too
            ..Default::default()
        };

        Ok(output)
    }

    /// Generate batch validation summary statistics
    fn generate_summary(&self, results: &[UTXOValidationResult]) -> BatchValidationSummary {
        let total_outputs = results.len();
        let owned_outputs = results.iter().filter(|r| r.is_owned).count();
        let valid_outputs = results.iter().filter(|r| r.value.is_some()).count();
        let payment_id_outputs = results.iter().filter(|r| r.payment_id.is_some()).count();
        let valid_range_proofs = results.iter()
            .filter(|r| r.range_proof_valid == Some(true))
            .count();

        let success_rate = if total_outputs > 0 {
            owned_outputs as f64 / total_outputs as f64
        } else {
            0.0
        };

        BatchValidationSummary {
            total_outputs,
            owned_outputs,
            valid_outputs,
            payment_id_outputs,
            valid_range_proofs,
            success_rate,
        }
    }
}
