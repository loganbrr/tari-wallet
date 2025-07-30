//! Python bindings for batch validation functionality
//!
//! This module provides Python wrappers for efficient batch validation of
//! transaction outputs with configurable validation options and parallel processing support.

use pyo3::prelude::*;
use std::sync::{Arc, Mutex};

use crate::errors::PyWalletError;
use crate::extraction_wrappers::PyLightweightTransactionOutput;
use lightweight_wallet_libs::{
    data_structures::transaction_output::LightweightTransactionOutput,
    extraction::{
        validate_output_batch, BatchValidationOptions, BatchValidationResult, 
        BatchValidationSummary, OutputValidationResult,
    },
    errors::LightweightWalletError,
};

#[cfg(feature = "grpc")]
use lightweight_wallet_libs::extraction::validate_output_batch_parallel;

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
        let options = self.inner.lock().map_err(|e| {
            PyWalletError(LightweightWalletError::ConversionError(format!("Failed to lock options: {}", e)))
        })?;
        Ok(options.continue_on_error)
    }

    pub fn set_continue_on_error(&self, value: bool) -> PyResult<()> {
        let mut options = self.inner.lock().map_err(|e| {
            PyWalletError(LightweightWalletError::ConversionError(format!("Failed to lock options: {}", e)))
        })?;
        options.continue_on_error = value;
        Ok(())
    }

    /// Maximum number of errors to collect per output
    #[getter]
    pub fn max_errors_per_output(&self) -> PyResult<usize> {
        let options = self.inner.lock().map_err(|e| {
            PyWalletError(LightweightWalletError::ConversionError(format!("Failed to lock options: {}", e)))
        })?;
        Ok(options.max_errors_per_output)
    }

    pub fn set_max_errors_per_output(&self, value: usize) -> PyResult<()> {
        let mut options = self.inner.lock().map_err(|e| {
            PyWalletError(LightweightWalletError::ConversionError(format!("Failed to lock options: {}", e)))
        })?;
        options.max_errors_per_output = value;
        Ok(())
    }

    /// Whether to validate range proofs (can be expensive)
    #[getter]
    pub fn validate_range_proofs(&self) -> PyResult<bool> {
        let options = self.inner.lock().map_err(|e| {
            PyWalletError(LightweightWalletError::ConversionError(format!("Failed to lock options: {}", e)))
        })?;
        Ok(options.validate_range_proofs)
    }

    pub fn set_validate_range_proofs(&self, value: bool) -> PyResult<()> {
        let mut options = self.inner.lock().map_err(|e| {
            PyWalletError(LightweightWalletError::ConversionError(format!("Failed to lock options: {}", e)))
        })?;
        options.validate_range_proofs = value;
        Ok(())
    }

    /// Whether to validate signatures (can be expensive)
    #[getter]
    pub fn validate_signatures(&self) -> PyResult<bool> {
        let options = self.inner.lock().map_err(|e| {
            PyWalletError(LightweightWalletError::ConversionError(format!("Failed to lock options: {}", e)))
        })?;
        Ok(options.validate_signatures)
    }

    pub fn set_validate_signatures(&self, value: bool) -> PyResult<()> {
        let mut options = self.inner.lock().map_err(|e| {
            PyWalletError(LightweightWalletError::ConversionError(format!("Failed to lock options: {}", e)))
        })?;
        options.validate_signatures = value;
        Ok(())
    }

    /// Whether to validate commitments
    #[getter]
    pub fn validate_commitments(&self) -> PyResult<bool> {
        let options = self.inner.lock().map_err(|e| {
            PyWalletError(LightweightWalletError::ConversionError(format!("Failed to lock options: {}", e)))
        })?;
        Ok(options.validate_commitments)
    }

    pub fn set_validate_commitments(&self, value: bool) -> PyResult<()> {
        let mut options = self.inner.lock().map_err(|e| {
            PyWalletError(LightweightWalletError::ConversionError(format!("Failed to lock options: {}", e)))
        })?;
        options.validate_commitments = value;
        Ok(())
    }

    /// String representation for debugging
    fn __repr__(&self) -> PyResult<String> {
        let options = self.inner.lock().map_err(|e| {
            PyWalletError(LightweightWalletError::ConversionError(format!("Failed to lock options: {}", e)))
        })?;
        
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

/// Individual output validation result
///
/// Contains validation status and error information for a single transaction output
/// within a batch validation operation.
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
    /// Get validation errors as list of strings
    #[getter]
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
    fn from_rust(result: OutputValidationResult) -> Self {
        let errors = result.errors.into_iter()
            .map(|e| format!("{:?}", e))
            .collect();

        Self {
            index: result.index,
            is_valid: result.is_valid,
            errors,
        }
    }
}

/// Summary statistics for batch validation
///
/// Provides aggregate statistics and success rates for batch validation operations,
/// useful for monitoring validation performance and detecting systematic issues.
#[pyclass(name = "BatchValidationSummary")]
#[derive(Clone)]
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
            "BatchValidationSummary(total={}, valid={}, invalid={}, success_rate={:.2}%)",
            self.total_outputs,
            self.valid_outputs,
            self.invalid_outputs,
            self.success_rate
        )
    }
}

impl PyBatchValidationSummary {
    fn from_rust(summary: BatchValidationSummary) -> Self {
        Self {
            total_outputs: summary.total_outputs,
            valid_outputs: summary.valid_outputs,
            invalid_outputs: summary.invalid_outputs,
            success_rate: summary.success_rate,
        }
    }
}

/// Batch validation result containing validation status for multiple outputs
///
/// Contains comprehensive results from validating a batch of transaction outputs,
/// including individual results for each output and aggregate statistics.
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
    #[getter]
    pub fn results(&self) -> Vec<PyOutputValidationResult> {
        self.results.clone()
    }

    /// Get summary statistics
    #[getter]
    pub fn summary(&self) -> PyBatchValidationSummary {
        self.summary.clone()
    }

    /// String representation for debugging
    fn __repr__(&self) -> String {
        format!(
            "BatchValidationResult(is_valid={}, total_outputs={}, success_rate={:.2}%)",
            self.is_valid,
            self.summary.total_outputs,
            self.summary.success_rate
        )
    }
}

impl PyBatchValidationResult {
    fn from_rust(result: BatchValidationResult) -> Self {
        let results = result.results.into_iter()
            .map(PyOutputValidationResult::from_rust)
            .collect();

        Self {
            is_valid: result.is_valid,
            results,
            summary: PyBatchValidationSummary::from_rust(result.summary),
        }
    }
}

/// Validate a batch of transaction outputs with sequential processing
///
/// Validates multiple transaction outputs in sequence, providing comprehensive
/// validation results with configurable error handling and validation options.
///
/// The validation process includes:
/// - Commitment integrity checks (32-byte length, valid prefix)
/// - Range proof validation (size constraints, structure validation)
/// - Optional signature validation (when enabled)
///
/// Args:
///     outputs (List[LightweightTransactionOutput]): List of transaction outputs to validate
///     options (BatchValidationOptions): Configuration for validation behavior
///
/// Returns:
///     BatchValidationResult: Comprehensive validation results with individual and summary statistics
///
/// Raises:
///     PyWalletError: If validation process fails due to internal errors
///
/// # Performance Note
///
/// This function releases the Python GIL during validation for improved performance
/// with concurrent Python operations. For large batches, consider using the parallel
/// version if available (requires grpc feature).
#[pyfunction]
pub fn validate_output_batch_py(
    py: Python,
    outputs: Vec<PyLightweightTransactionOutput>,
    options: &PyBatchValidationOptions,
) -> PyResult<PyBatchValidationResult> {
    // Release GIL for potentially long-running validation
    py.allow_threads(|| {
        // Convert Python wrappers to Rust types
        let rust_outputs: Result<Vec<LightweightTransactionOutput>, PyErr> = outputs
            .iter()
            .map(|output| output.to_rust())
            .collect();
        let rust_outputs = rust_outputs?;
        
        let options_guard = options.inner.lock().map_err(|e| {
            PyWalletError(LightweightWalletError::ConversionError(format!("Failed to lock options: {}", e)))
        })?;
        
        let rust_options = options_guard.clone();
        drop(options_guard);

        let result = validate_output_batch(&rust_outputs, &rust_options);

        Ok(PyBatchValidationResult::from_rust(result))
    })
}

/// Validate a batch of transaction outputs with parallel processing
///
/// Similar to validate_output_batch but uses parallel processing for improved
/// performance on large batches. Only available when the 'grpc' feature is enabled.
///
/// Args:
///     outputs (List[LightweightTransactionOutput]): List of transaction outputs to validate
///     options (BatchValidationOptions): Configuration for validation behavior
///
/// Returns:
///     BatchValidationResult: Comprehensive validation results with individual and summary statistics
///
/// Raises:
///     PyWalletError: If validation process fails due to internal errors
///
/// # Performance Note
///
/// This function uses Rayon for parallel processing and releases the Python GIL
/// during validation. Best suited for large batches (>100 outputs) where the
/// parallel overhead is justified by improved throughput.
#[cfg(feature = "grpc")]
#[pyfunction]
pub fn validate_output_batch_parallel_py(
    py: Python,
    outputs: Vec<PyLightweightTransactionOutput>,
    options: &PyBatchValidationOptions,
) -> PyResult<PyBatchValidationResult> {
    // Release GIL for parallel validation
    py.allow_threads(|| {
        // Convert Python wrappers to Rust types
        let rust_outputs: Result<Vec<LightweightTransactionOutput>, PyErr> = outputs
            .iter()
            .map(|output| output.to_rust())
            .collect();
        let rust_outputs = rust_outputs?;
        
        let options_guard = options.inner.lock().map_err(|e| {
            PyWalletError(LightweightWalletError::ConversionError(format!("Failed to lock options: {}", e)))
        })?;
        
        let rust_options = options_guard.clone();
        drop(options_guard);

        let result = validate_output_batch_parallel(&rust_outputs, &rust_options);

        Ok(PyBatchValidationResult::from_rust(result))
    })
}

/// Register batch validation classes and functions with Python module
pub fn register_batch_validation_classes(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBatchValidationOptions>()?;
    m.add_class::<PyOutputValidationResult>()?;
    m.add_class::<PyBatchValidationSummary>()?;
    m.add_class::<PyBatchValidationResult>()?;
    m.add_function(wrap_pyfunction!(validate_output_batch_py, m)?)?;
    
    #[cfg(feature = "grpc")]
    m.add_function(wrap_pyfunction!(validate_output_batch_parallel_py, m)?)?;
    
    Ok(())
}
