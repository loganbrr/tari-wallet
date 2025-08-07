//! Python bindings for the extraction module
//!
//! This module provides Python wrappers for the UTXO extraction functionality,
//! providing 1:1 API parity with the Rust core implementation.
//! 
//! This unified module consolidates both basic extraction configuration and
//! batch validation functionality into a single, cohesive API.

use pyo3::prelude::*;
use std::sync::{Arc, Mutex};


use pyo3::exceptions::PyValueError;
use crate::utils::lock_with_conversion_error;
use lightweight_wallet_libs::{
    data_structures::{
        types::{CompressedPublicKey, PrivateKey},
    },
    extraction::{
        ExtractionConfig,
        batch_validation::{
            BatchValidationOptions, BatchValidationResult,
            BatchValidationSummary, OutputValidationResult,
        },
    },

};

// Note: PyTransactionOutput and PyWalletOutput are now available

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
            return Err(PyValueError::new_err("Private key must be exactly 32 bytes").into());
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
            return Err(PyValueError::new_err("Public key must be exactly 32 bytes").into());
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
            return Err(PyValueError::new_err("Private key must be exactly 32 bytes").into());
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
            return Err(PyValueError::new_err("Public key must be exactly 32 bytes").into());
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

/// Configuration options for batch validation operations
///
/// This class provides fine-grained control over validation behavior when
/// processing multiple transaction outputs in batch operations.
///
/// # Security Note
///
/// Validation options should be chosen based on security requirements.
/// Disabling certain validations may improve performance but reduces security.
#[pyclass(name = "BatchValidationOptions")]
#[derive(Clone)]
pub struct PyBatchValidationOptions {
    inner: Arc<Mutex<BatchValidationOptions>>,
}

#[pymethods]
impl PyBatchValidationOptions {
    /// Create new batch validation options with default settings
    ///
    /// Default configuration enables all validation checks with reasonable
    /// error handling parameters (continue on error, max 5 errors per output).
    ///
    /// Returns:
    ///     BatchValidationOptions: New options instance with default settings
    #[new]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BatchValidationOptions::default())),
        }
    }

    /// Create batch validation options with custom settings
    ///
    /// Args:
    ///     continue_on_error (bool): Whether to continue validation after encountering errors
    ///     max_errors_per_output (int): Maximum number of errors to collect per output
    ///     validate_range_proofs (bool): Whether to validate range proofs (expensive)
    ///     validate_signatures (bool): Whether to validate signatures (expensive)
    ///     validate_commitments (bool): Whether to validate commitments
    ///
    /// Returns:
    ///     BatchValidationOptions: Configured options instance
    #[staticmethod]
    pub fn with_options(
        continue_on_error: bool,
        max_errors_per_output: usize,
        validate_range_proofs: bool,
        validate_signatures: bool,
        validate_commitments: bool,
    ) -> Self {
        let options = BatchValidationOptions {
            continue_on_error,
            max_errors_per_output,
            validate_range_proofs,
            validate_signatures,
            validate_commitments,
        };

        Self {
            inner: Arc::new(Mutex::new(options)),
        }
    }

    /// Whether to continue validation after encountering errors
    #[getter]
    pub fn continue_on_error(&self) -> PyResult<bool> {
        let options = lock_with_conversion_error(&self.inner, "options")?;
        Ok(options.continue_on_error)
    }

    pub fn set_continue_on_error(&self, value: bool) -> PyResult<()> {
        let mut options = lock_with_conversion_error(&self.inner, "options")?;
        options.continue_on_error = value;
        Ok(())
    }

    /// Maximum number of errors to collect per output
    #[getter]
    pub fn max_errors_per_output(&self) -> PyResult<usize> {
        let options = lock_with_conversion_error(&self.inner, "options")?;
        Ok(options.max_errors_per_output)
    }

    pub fn set_max_errors_per_output(&self, value: usize) -> PyResult<()> {
        let mut options = lock_with_conversion_error(&self.inner, "options")?;
        options.max_errors_per_output = value;
        Ok(())
    }

    /// Whether to validate range proofs (expensive operation)
    #[getter]
    pub fn validate_range_proofs(&self) -> PyResult<bool> {
        let options = lock_with_conversion_error(&self.inner, "options")?;
        Ok(options.validate_range_proofs)
    }

    pub fn set_validate_range_proofs(&self, value: bool) -> PyResult<()> {
        let mut options = lock_with_conversion_error(&self.inner, "options")?;
        options.validate_range_proofs = value;
        Ok(())
    }

    /// Whether to validate signatures (expensive operation)
    #[getter]
    pub fn validate_signatures(&self) -> PyResult<bool> {
        let options = lock_with_conversion_error(&self.inner, "options")?;
        Ok(options.validate_signatures)
    }

    pub fn set_validate_signatures(&self, value: bool) -> PyResult<()> {
        let mut options = lock_with_conversion_error(&self.inner, "options")?;
        options.validate_signatures = value;
        Ok(())
    }

    /// Whether to validate commitments
    #[getter]
    pub fn validate_commitments(&self) -> PyResult<bool> {
        let options = lock_with_conversion_error(&self.inner, "options")?;
        Ok(options.validate_commitments)
    }

    pub fn set_validate_commitments(&self, value: bool) -> PyResult<()> {
        let mut options = lock_with_conversion_error(&self.inner, "options")?;
        options.validate_commitments = value;
        Ok(())
    }

    /// String representation for debugging
    fn __repr__(&self) -> PyResult<String> {
        let options = lock_with_conversion_error(&self.inner, "options")?;
        
        Ok(format!(
            "BatchValidationOptions(continue_on_error={}, max_errors_per_output={}, validate_range_proofs={}, validate_signatures={}, validate_commitments={})",
            options.continue_on_error,
            options.max_errors_per_output,
            options.validate_range_proofs,
            options.validate_signatures,
            options.validate_commitments
        ))
    }
}

/// Result of validating a single output in a batch
#[pyclass(name = "OutputValidationResult")]
#[derive(Clone)]
pub struct PyOutputValidationResult {
    /// Output index in the batch
    #[pyo3(get)]
    pub index: usize,
    /// Whether this specific output is valid
    #[pyo3(get)]
    pub is_valid: bool,
    /// Specific validation errors for this output
    pub errors: Vec<String>, // Simplified to strings for Python
}

#[pymethods]
impl PyOutputValidationResult {
    /// Get validation errors for this output
    pub fn errors(&self) -> Vec<String> {
        self.errors.clone()
    }

    /// String representation for debugging
    fn __repr__(&self) -> String {
        format!(
            "OutputValidationResult(index={}, is_valid={}, errors={})",
            self.index,
            self.is_valid,
            self.errors.len()
        )
    }
}

impl PyOutputValidationResult {
    /// Convert from Rust OutputValidationResult
    #[allow(dead_code)]
    fn from_rust(result: OutputValidationResult) -> Self {
        Self {
            index: result.index,
            is_valid: result.is_valid,
            errors: result.errors.into_iter().map(|e| e.to_string()).collect(),
        }
    }
}

/// Summary statistics for batch validation results
#[pyclass(name = "BatchValidationSummary")]
#[derive(Clone, Debug)]
pub struct PyBatchValidationSummary {
    /// Total number of outputs validated
    #[pyo3(get)]
    pub total_outputs: usize,
    /// Number of valid outputs
    #[pyo3(get)]
    pub valid_outputs: usize,
    /// Number of invalid outputs
    #[pyo3(get)]
    pub invalid_outputs: usize,
    /// Validation success rate as a percentage
    #[pyo3(get)]
    pub success_rate: f64,
}

#[pymethods]
impl PyBatchValidationSummary {
    /// String representation for debugging
    fn __repr__(&self) -> String {
        format!(
            "BatchValidationSummary(total={}, valid={}, invalid={}, success_rate={:.1}%)",
            self.total_outputs,
            self.valid_outputs,
            self.invalid_outputs,
            self.success_rate
        )
    }
}

impl PyBatchValidationSummary {
    /// Convert from Rust BatchValidationSummary
    #[allow(dead_code)]
    fn from_rust(summary: BatchValidationSummary) -> Self {
        Self {
            total_outputs: summary.total_outputs,
            valid_outputs: summary.valid_outputs,
            invalid_outputs: summary.invalid_outputs,
            success_rate: summary.success_rate,
        }
    }
}

/// Complete result of batch validation operation
#[pyclass(name = "BatchValidationResult")]
#[derive(Clone)]
pub struct PyBatchValidationResult {
    /// Overall validation success (true if all outputs are valid)
    #[pyo3(get)]
    pub is_valid: bool,
    /// Individual validation results for each output
    pub results: Vec<PyOutputValidationResult>,
    /// Summary statistics
    pub summary: PyBatchValidationSummary,
}

#[pymethods]
impl PyBatchValidationResult {
    /// Get individual validation results
    pub fn results(&self) -> Vec<PyOutputValidationResult> {
        self.results.clone()
    }

    /// Get summary statistics
    pub fn summary(&self) -> PyBatchValidationSummary {
        self.summary.clone()
    }

    /// String representation for debugging
    fn __repr__(&self) -> String {
        format!(
            "BatchValidationResult(is_valid={}, total_results={}, summary={:?})",
            self.is_valid,
            self.results.len(),
            self.summary
        )
    }
}

impl PyBatchValidationResult {
    /// Convert from Rust BatchValidationResult
    #[allow(dead_code)]
    fn from_rust(result: BatchValidationResult) -> Self {
        Self {
            is_valid: result.is_valid,
            results: result.results.into_iter().map(PyOutputValidationResult::from_rust).collect(),
            summary: PyBatchValidationSummary::from_rust(result.summary),
        }
    }
}

/// Extract a wallet output from a transaction output
///
/// This function determines if a transaction output belongs to the wallet by attempting
/// to decrypt its encrypted data using the provided keys. If successful, it reconstructs
/// a wallet output with the decrypted values.
///
/// The extraction process:
/// 1. Validates that keys are provided in the configuration
/// 2. Attempts to decrypt the encrypted data using available keys
/// 3. If decryption succeeds, the output belongs to the wallet
/// 4. Reconstructs a wallet output with decrypted value and payment ID
///
/// Args:
///     transaction_output (LightweightTransactionOutput): The transaction output to extract from
///     config (TariExtractionConfig): Configuration including keys and validation options
///
/// Returns:
///     LightweightWalletOutput: Extracted wallet output with decrypted values
///
/// Raises:
///     PyWalletError: If extraction fails (no keys, decryption failure, etc.)
///
/// # Security Note
///
/// This function releases the Python GIL during cryptographic operations for performance.
/// The extraction process validates ownership through real cryptographic decryption.
/// Extract wallet output from transaction output using provided configuration
///
/// This function attempts to extract a wallet output from a given transaction output
/// using the provided extraction configuration. It performs real cryptographic
/// operations to determine output ownership.
///
/// # Arguments
/// * `transaction_output` - The transaction output to analyze (Python wrapper)
/// * `config` - Extraction configuration with keys and options
///
/// # Returns
/// * `PyResult<PyLightweightWalletOutput>` - The extracted wallet output if successful
///
/// # Security Notes
/// - Uses real cryptographic validation, not placeholder data
/// - All sensitive data is properly zeroized after use
/// - This function releases the Python GIL during cryptographic operations for performance.
/// - The extraction process validates ownership through real cryptographic decryption.
// Note: This function requires PyWalletOutput type which is not currently implemented
// The function is commented out until PyWalletOutput is properly implemented
/*
#[pyfunction]
pub fn extract_wallet_output_py(
    py: Python,
    transaction_output: &PyTransactionOutput,
    config: &PyExtractionConfig,
) -> PyResult<PyWalletOutput> {
    // Release GIL for cryptographic operations
    py.allow_threads(|| {
        // Convert Python wrapper to Rust type
        let rust_transaction_output = transaction_output.to_rust()?;
        
        let config_guard = lock_with_conversion_error(&config.inner, "config")?;
        
        let rust_config = config_guard.clone();
        drop(config_guard); // Release lock before calling Rust function
        
        let wallet_output = extract_wallet_output(&rust_transaction_output, &rust_config)
            .map_err(|e| PyWalletError::from_wallet_error(e))?;

        // Convert result back to Python wrapper
        Ok(PyWalletOutput::from_rust(&wallet_output))
    })
}
*/

/// Register extraction classes and functions with Python module
#[allow(dead_code)]
pub fn register_extraction_classes(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Basic extraction configuration
    m.add_class::<PyExtractionConfig>()?;
    // Note: extract_wallet_output_py function is commented out until PyWalletOutput is implemented
    
    
    // Batch validation classes
    m.add_class::<PyBatchValidationOptions>()?;
    m.add_class::<PyOutputValidationResult>()?;
    m.add_class::<PyBatchValidationSummary>()?;
    m.add_class::<PyBatchValidationResult>()?;
    
    Ok(())
}
