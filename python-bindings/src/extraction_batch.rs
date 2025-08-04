//! Python bindings for batch validation functionality
//!
//! This module provides Python wrappers for efficient batch validation of
//! transaction outputs with configurable validation options and parallel processing support.

use pyo3::prelude::*;
use std::sync::{Arc, Mutex};
use lightweight_wallet_libs::{
    extraction::{
        batch_validation::{
            BatchValidationOptions, BatchValidationResult,
            BatchValidationSummary, OutputValidationResult,
        },
    },
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

    /// Whether to validate range proofs (can be expensive)
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

    /// Whether to validate signatures (can be expensive)
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    fn from_rust(result: BatchValidationResult) -> Self {
        let results = result.results.into_iter()
            .map(PyOutputValidationResult::from_rust)
            .collect();

        let summary = PyBatchValidationSummary::from_rust(result.summary);

        Self {
            is_valid: result.is_valid,
            results,
            summary,
        }
    }
}

/// Register batch validation classes and functions with Python module
#[allow(dead_code)]
pub fn register_batch_validation_classes(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBatchValidationOptions>()?;
    m.add_class::<PyBatchValidationResult>()?;
    m.add_class::<PyBatchValidationSummary>()?;
    m.add_class::<PyOutputValidationResult>()?;
    Ok(())
}
