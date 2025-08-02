//! Python bindings for extraction result and configuration types
//!
//! This module provides Python wrappers for all extraction component result types,
//! providing 1:1 API parity with the Rust core implementation.

use pyo3::prelude::*;
use std::sync::{Arc, Mutex};

use crate::extraction_utils::lock_with_conversion_error;
use lightweight_wallet_libs::{
    extraction::{
        DecryptionOptions, DecryptionResult, PaymentIdExtractionResult, PaymentIdMetadata,
    },
};

/// Options for encrypted data decryption operations
///
/// This class provides configuration for decryption behavior when extracting
/// values from encrypted transaction outputs.
///
/// # Security Note
///
/// Decryption options should be chosen carefully based on security requirements.
/// Setting max_keys_to_try to a reasonable limit prevents DoS attacks.
#[pyclass(name = "DecryptionOptions")]
#[derive(Clone)]
pub struct PyDecryptionOptions {
    inner: Arc<Mutex<DecryptionOptions>>,
}

#[pymethods]
impl PyDecryptionOptions {
    /// Create new decryption options with default settings
    ///
    /// Default configuration tries all keys, validates decrypted data,
    /// has no key limit, and doesn't return partial results.
    ///
    /// Returns:
    ///     DecryptionOptions: New options instance with default settings
    #[new]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(DecryptionOptions::default())),
        }
    }

    /// Create decryption options with custom settings
    ///
    /// Args:
    ///     try_all_keys (bool): Whether to try all available keys if first fails
    ///     validate_decrypted_data (bool): Whether to validate decrypted data
    ///     max_keys_to_try (int): Maximum keys to try (0 = unlimited)
    ///     return_partial_results (bool): Whether to return partial results on failure
    ///
    /// Returns:
    ///     DecryptionOptions: Configured options instance
    #[staticmethod]
    pub fn with_options(
        try_all_keys: bool,
        validate_decrypted_data: bool,
        max_keys_to_try: usize,
        return_partial_results: bool,
    ) -> Self {
        let options = DecryptionOptions {
            try_all_keys,
            validate_decrypted_data,
            max_keys_to_try,
            return_partial_results,
        };

        Self {
            inner: Arc::new(Mutex::new(options)),
        }
    }

    /// Whether to try all available keys if the first one fails
    #[getter]
    pub fn try_all_keys(&self) -> PyResult<bool> {
        let options = lock_with_conversion_error(&self.inner, "options")?;
        Ok(options.try_all_keys)
    }

    pub fn set_try_all_keys(&self, value: bool) -> PyResult<()> {
        let mut options = lock_with_conversion_error(&self.inner, "options")?;
        options.try_all_keys = value;
        Ok(())
    }

    /// Whether to validate the decrypted data
    #[getter]
    pub fn validate_decrypted_data(&self) -> PyResult<bool> {
        let options = lock_with_conversion_error(&self.inner, "options")?;
        Ok(options.validate_decrypted_data)
    }

    pub fn set_validate_decrypted_data(&self, value: bool) -> PyResult<()> {
        let mut options = lock_with_conversion_error(&self.inner, "options")?;
        options.validate_decrypted_data = value;
        Ok(())
    }

    /// Maximum number of keys to try (0 = unlimited)
    #[getter]
    pub fn max_keys_to_try(&self) -> PyResult<usize> {
        let options = lock_with_conversion_error(&self.inner, "options")?;
        Ok(options.max_keys_to_try)
    }

    pub fn set_max_keys_to_try(&self, value: usize) -> PyResult<()> {
        let mut options = lock_with_conversion_error(&self.inner, "options")?;
        options.max_keys_to_try = value;
        Ok(())
    }

    /// Whether to return partial results on failure
    #[getter]
    pub fn return_partial_results(&self) -> PyResult<bool> {
        let options = lock_with_conversion_error(&self.inner, "options")?;
        Ok(options.return_partial_results)
    }

    pub fn set_return_partial_results(&self, value: bool) -> PyResult<()> {
        let mut options = lock_with_conversion_error(&self.inner, "options")?;
        options.return_partial_results = value;
        Ok(())
    }

    /// String representation for debugging
    fn __repr__(&self) -> PyResult<String> {
        let options = lock_with_conversion_error(&self.inner, "options")?;
        
        Ok(format!(
            "DecryptionOptions(try_all_keys={}, validate_decrypted_data={}, max_keys_to_try={}, return_partial_results={})",
            options.try_all_keys,
            options.validate_decrypted_data,
            options.max_keys_to_try,
            options.return_partial_results
        ))
    }
}

impl PyDecryptionOptions {
    pub fn inner(&self) -> Arc<Mutex<DecryptionOptions>> {
        self.inner.clone()
    }
}

/// Result of encrypted data decryption operation
///
/// Contains the results of attempting to decrypt encrypted data from a transaction output,
/// including extracted values, keys used, and error information.
#[pyclass(name = "DecryptionResult")]
#[derive(Clone)]
pub struct PyDecryptionResult {
    /// Whether the decryption was successful
    #[pyo3(get)]
    pub success: bool,
    /// The decrypted value in microTari (if successful)
    pub value: Option<u64>,
    /// The decrypted mask as bytes (if successful)
    pub mask: Option<Vec<u8>>,
    /// The extracted payment ID description (if successful)
    pub payment_id: Option<String>,
    /// The key used for decryption as bytes (if successful)
    pub used_key: Option<Vec<u8>>,
    /// Error message if decryption failed
    pub error: Option<String>,
    /// Number of keys tried during decryption
    #[pyo3(get)]
    pub keys_tried: usize,
}

#[pymethods]
impl PyDecryptionResult {
    /// Get the decrypted value in microTari
    #[getter]
    pub fn value(&self) -> Option<u64> {
        self.value
    }

    /// Get the decrypted mask as bytes
    #[getter]
    pub fn mask(&self) -> Option<Vec<u8>> {
        self.mask.clone()
    }

    /// Get the extracted payment ID description
    #[getter]
    pub fn payment_id(&self) -> Option<String> {
        self.payment_id.clone()
    }

    /// Get the key used for decryption as bytes
    #[getter]
    pub fn used_key(&self) -> Option<Vec<u8>> {
        self.used_key.clone()
    }

    /// Get error message if decryption failed
    #[getter]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }

    /// Check if the decryption was successful
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Get the error message if decryption failed
    pub fn error_message(&self) -> Option<String> {
        self.error.clone()
    }

    /// String representation for debugging
    fn __repr__(&self) -> String {
        if self.success {
            format!(
                "DecryptionResult(success=true, value={:?}, keys_tried={})",
                self.value, self.keys_tried
            )
        } else {
            format!(
                "DecryptionResult(success=false, error={:?}, keys_tried={})",
                self.error, self.keys_tried
            )
        }
    }
}

impl PyDecryptionResult {
    pub fn from_rust(result: DecryptionResult) -> Self {
        let value = result.value.map(|v| v.as_u64());
        let mask = result.mask.map(|m| m.as_bytes().to_vec());
        let payment_id = result.payment_id.map(|pid| format!("{:?}", pid));
        let used_key = result.used_key.map(|k| k.as_bytes().to_vec());

        Self {
            success: result.success,
            value,
            mask,
            payment_id,
            used_key,
            error: result.error,
            keys_tried: result.keys_tried,
        }
    }
}

/// Metadata about an extracted payment ID
///
/// Provides additional information about the structure and validity of
/// an extracted payment ID for analysis and validation purposes.
#[pyclass(name = "PaymentIdMetadata")]
#[derive(Clone)]
pub struct PyPaymentIdMetadata {
    /// The transaction type inferred from the payment ID
    pub transaction_type: Option<String>,
    /// Whether the payment ID contains valid UTF-8 data
    #[pyo3(get)]
    pub has_valid_utf8: bool,
    /// The size of the payment ID in bytes
    #[pyo3(get)]
    pub size_bytes: usize,
    /// Whether this is a standard payment ID format
    #[pyo3(get)]
    pub is_standard_format: bool,
}

#[pymethods]
impl PyPaymentIdMetadata {
    /// Get the transaction type as string
    #[getter]
    pub fn transaction_type(&self) -> Option<String> {
        self.transaction_type.clone()
    }

    /// String representation for debugging
    fn __repr__(&self) -> String {
        format!(
            "PaymentIdMetadata(type={:?}, utf8={}, size={}, standard={})",
            self.transaction_type, self.has_valid_utf8, self.size_bytes, self.is_standard_format
        )
    }
}

impl PyPaymentIdMetadata {
    pub fn from_rust(metadata: PaymentIdMetadata) -> Self {
        let transaction_type = metadata.transaction_type.map(|t| format!("{:?}", t));

        Self {
            transaction_type,
            has_valid_utf8: metadata.has_valid_utf8,
            size_bytes: metadata.size_bytes,
            is_standard_format: metadata.is_standard_format,
        }
    }
}

/// Result of payment ID extraction operation
///
/// Contains the results of attempting to extract and validate a payment ID
/// from encrypted transaction data.
#[pyclass(name = "PaymentIdExtractionResult")]
#[derive(Clone)]
pub struct PyPaymentIdExtractionResult {
    /// The extracted payment ID description (if successful)
    pub payment_id: Option<String>,
    /// Error message if extraction failed
    pub error: Option<String>,
    /// Additional metadata about the extraction
    pub metadata: PyPaymentIdMetadata,
}

#[pymethods]
impl PyPaymentIdExtractionResult {
    /// Get the extracted payment ID description
    #[getter]
    pub fn payment_id(&self) -> Option<String> {
        self.payment_id.clone()
    }

    /// Get error message if extraction failed
    #[getter]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }

    /// Get additional metadata about the extraction
    #[getter]
    pub fn metadata(&self) -> PyPaymentIdMetadata {
        self.metadata.clone()
    }

    /// Check if the extraction was successful
    pub fn is_success(&self) -> bool {
        self.payment_id.is_some()
    }

    /// Get the error message if extraction failed
    pub fn error_message(&self) -> Option<String> {
        self.error.clone()
    }

    /// String representation for debugging
    fn __repr__(&self) -> String {
        if self.is_success() {
            format!(
                "PaymentIdExtractionResult(success=true, payment_id={:?})",
                self.payment_id
            )
        } else {
            format!(
                "PaymentIdExtractionResult(success=false, error={:?})",
                self.error
            )
        }
    }
}

impl PyPaymentIdExtractionResult {
    pub fn from_rust(result: PaymentIdExtractionResult) -> Self {
        let payment_id = result.payment_id.map(|pid| format!("{:?}", pid));

        Self {
            payment_id,
            error: result.error,
            metadata: PyPaymentIdMetadata::from_rust(result.metadata),
        }
    }
}

/// Register extraction type classes with Python module
pub fn register_extraction_type_classes(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyDecryptionOptions>()?;
    m.add_class::<PyDecryptionResult>()?;
    m.add_class::<PyPaymentIdMetadata>()?;
    m.add_class::<PyPaymentIdExtractionResult>()?;
    Ok(())
}
