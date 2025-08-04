//! Enhanced error handling for Python bindings
//!
//! This module provides a comprehensive error mapping system that converts
//! Rust errors to appropriate Python exceptions with preserved context and
//! source chain information.

use pyo3::prelude::*;
use pyo3::exceptions::{
    PyRuntimeError, PyValueError, PyIOError, PyTimeoutError,
    PyConnectionError, PyTypeError, PyNotImplementedError
};
use lightweight_wallet_libs::errors::LightweightWalletError;
use std::sync::PoisonError;

/// Enhanced PyO3 error wrapper with direct message creation
/// 
/// This error type provides clean error creation and comprehensive mapping
/// from Rust errors to appropriate Python exception types while preserving
/// error context and source chain information.
#[derive(Debug)]
pub struct PyWalletError {
    message: String,
    error_type: ErrorType,
    source_chain: Vec<String>,
}

#[derive(Debug, Clone)]
enum ErrorType {
    Value,
    Runtime, 
    IO,
    Connection,
    Timeout,
    Type,
    NotImplemented,
}

impl PyWalletError {
    /// Create a new error from a message
    pub fn from_msg(message: &str) -> Self {
        Self {
            message: message.to_string(),
            error_type: ErrorType::Runtime,
            source_chain: Vec::new(),
        }
    }

    /// Create a value error
    pub fn value_error(message: &str) -> Self {
        Self {
            message: message.to_string(),
            error_type: ErrorType::Value,
            source_chain: Vec::new(),
        }
    }

    /// Create an IO error
    pub fn io_error(message: &str) -> Self {
        Self {
            message: message.to_string(),
            error_type: ErrorType::IO,
            source_chain: Vec::new(),
        }
    }

    /// Create a connection error
    pub fn connection_error(message: &str) -> Self {
        Self {
            message: message.to_string(),
            error_type: ErrorType::Connection,
            source_chain: Vec::new(),
        }
    }

    /// Create a timeout error
    pub fn timeout_error(message: &str) -> Self {
        Self {
            message: message.to_string(),
            error_type: ErrorType::Timeout,
            source_chain: Vec::new(),
        }
    }

    /// Create a type error
    pub fn type_error(message: &str) -> Self {
        Self {
            message: message.to_string(),
            error_type: ErrorType::Type,
            source_chain: Vec::new(),
        }
    }

    /// Add context to the error
    pub fn with_context(mut self, context: &str) -> Self {
        self.source_chain.push(context.to_string());
        self
    }

    /// Get the full error message with source chain
    pub fn full_message(&self) -> String {
        if self.source_chain.is_empty() {
            self.message.clone()
        } else {
            format!("{}: {}", self.message, self.source_chain.join(" -> "))
        }
    }
}

impl From<LightweightWalletError> for PyWalletError {
    fn from(err: LightweightWalletError) -> Self {
        use LightweightWalletError::*;
        
        let (message, error_type) = match &err {
            // Data structure errors -> ValueError
            DataStructureError(e) => (
                format!("Data structure error: {}", e),
                ErrorType::Value
            ),
            
            // Validation errors -> ValueError  
            ValidationError(e) => (
                format!("Validation error: {}", e),
                ErrorType::Value
            ),
            
            // Storage errors -> IOError
            StorageError(e) => (
                format!("Storage error: {}", e),
                ErrorType::IO
            ),
            
            // Scanning errors -> ConnectionError
            ScanningError(e) => (
                format!("Scanning error: {}", e),
                ErrorType::Connection
            ),
            
            // Key management errors -> ValueError (sensitive data handling)
            KeyManagementError(e) => (
                format!("Key management error: {}", e),
                ErrorType::Value
            ),
            
            // Encryption errors -> ValueError
            EncryptionError(e) => (
                format!("Encryption error: {}", e),
                ErrorType::Value
            ),
            
            // Network errors -> ConnectionError
            NetworkError(e) => (
                format!("Network error: {}", e),
                ErrorType::Connection
            ),
            
            // Timeout errors -> TimeoutError
            Timeout(e) => (
                format!("Timeout error: {}", e),
                ErrorType::Timeout
            ),
            
            // Conversion errors -> ValueError
            ConversionError(e) => (
                format!("Conversion error: {}", e),
                ErrorType::Value
            ),
            
            // Connection errors -> ConnectionError
            ConnectionError(e) => (
                format!("Connection error: {}", e),
                ErrorType::Connection
            ),
            
            // gRPC errors -> ConnectionError
            GrpcError(e) => (
                format!("gRPC error: {}", e),
                ErrorType::Connection
            ),
            
            // Hex errors -> ValueError
            HexError(e) => (
                format!("Hex error: {}", e),
                ErrorType::Value
            ),
            
            // Serialization errors -> ValueError
            SerializationError(e) => (
                format!("Serialization error: {}", e),
                ErrorType::Value
            ),
            
            // Range validation errors -> ValueError
            RangeValidationError(e) => (
                format!("Range validation error: {}", e),
                ErrorType::Value
            ),
            
            // Cryptographic signature errors -> ValueError
            CryptographicSignatureError(e) => (
                format!("Cryptographic signature error: {}", e),
                ErrorType::Value
            ),
            
            // Fallback for any unhandled variants -> RuntimeError
            _ => (
                format!("Wallet error: {}", err),
                ErrorType::Runtime
            ),
        };

        // Build source chain from error sources
        let mut source_chain = Vec::new();
        let mut current_source = err.source();
        while let Some(source) = current_source {
            source_chain.push(source.to_string());
            current_source = source.source();
        }

        Self {
            message,
            error_type,
            source_chain,
        }
    }
}

impl From<PyWalletError> for PyErr {
    fn from(err: PyWalletError) -> Self {
        let full_message = err.full_message();
        
        match err.error_type {
            ErrorType::Value => PyValueError::new_err(full_message),
            ErrorType::Runtime => PyRuntimeError::new_err(full_message),
            ErrorType::IO => PyIOError::new_err(full_message),
            ErrorType::Connection => PyConnectionError::new_err(full_message),
            ErrorType::Timeout => PyTimeoutError::new_err(full_message),
            ErrorType::Type => PyTypeError::new_err(full_message),
            ErrorType::NotImplemented => PyNotImplementedError::new_err(full_message),
        }
    }
}

impl std::fmt::Display for PyWalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.full_message())
    }
}

impl std::error::Error for PyWalletError {}

/// Convenience function for lock errors
pub fn lock_error(resource: &str) -> impl Fn(PoisonError<std::sync::MutexGuard<'_, impl std::fmt::Debug>>) -> PyWalletError {
    let resource = resource.to_string();
    move |_| PyWalletError::from_msg(&format!("Failed to lock {}", resource))
}

/// Helper macro for error propagation with context
#[macro_export]
macro_rules! py_try {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => return Err(PyWalletError::from(err).into()),
        }
    };
    ($expr:expr, $context:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => return Err(PyWalletError::from(err).with_context($context).into()),
        }
    };
}

/// Result type alias for convenience
pub type PyWalletResult<T> = Result<T, PyWalletError>;

/// Convert any error to PyWalletError
impl<E: std::error::Error + 'static> From<E> for PyWalletError
where
    E: Send + Sync,
{
    fn from(err: E) -> Self {
        PyWalletError::from_msg(&err.to_string())
    }
}

/// Custom error types for specific domains

/// Validation specific error
#[derive(Debug)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl ValidationError {
    pub fn new(field: &str, message: &str) -> Self {
        Self {
            field: field.to_string(),
            message: message.to_string(),
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Validation error for {}: {}", self.field, self.message)
    }
}

impl std::error::Error for ValidationError {}

impl From<ValidationError> for PyWalletError {
    fn from(err: ValidationError) -> Self {
        PyWalletError::value_error(&err.to_string())
    }
}

/// Cryptographic error
#[derive(Debug)]
pub struct CryptoError {
    pub operation: String,
    pub message: String,
}

impl CryptoError {
    pub fn new(operation: &str, message: &str) -> Self {
        Self {
            operation: operation.to_string(),
            message: message.to_string(),
        }
    }
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cryptographic error in {}: {}", self.operation, self.message)
    }
}

impl std::error::Error for CryptoError {}

impl From<CryptoError> for PyWalletError {
    fn from(err: CryptoError) -> Self {
        PyWalletError::value_error(&err.to_string())
    }
}

/// Address parsing error
#[derive(Debug)]
pub struct AddressError {
    pub address_type: String,
    pub format: String,
    pub message: String,
}

impl AddressError {
    pub fn new(address_type: &str, format: &str, message: &str) -> Self {
        Self {
            address_type: address_type.to_string(),
            format: format.to_string(),
            message: message.to_string(),
        }
    }
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Address error for {} in {} format: {}", 
            self.address_type, self.format, self.message)
    }
}

impl std::error::Error for AddressError {}

impl From<AddressError> for PyWalletError {
    fn from(err: AddressError) -> Self {
        PyWalletError::value_error(&err.to_string())
    }
}

/// Transaction error
#[derive(Debug)]
pub struct TransactionError {
    pub transaction_id: Option<String>,
    pub component: String,
    pub message: String,
}

impl TransactionError {
    pub fn new(component: &str, message: &str) -> Self {
        Self {
            transaction_id: None,
            component: component.to_string(),
            message: message.to_string(),
        }
    }

    pub fn with_id(mut self, transaction_id: &str) -> Self {
        self.transaction_id = Some(transaction_id.to_string());
        self
    }
}

impl std::fmt::Display for TransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.transaction_id {
            Some(id) => write!(f, "Transaction error for {} in component {}: {}", 
                id, self.component, self.message),
            None => write!(f, "Transaction error in component {}: {}", 
                self.component, self.message),
        }
    }
}

impl std::error::Error for TransactionError {}

impl From<TransactionError> for PyWalletError {
    fn from(err: TransactionError) -> Self {
        PyWalletError::value_error(&err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = PyWalletError::from_msg("Test error");
        assert_eq!(err.message, "Test error");
        assert!(matches!(err.error_type, ErrorType::Runtime));
    }

    #[test]
    fn test_error_with_context() {
        let err = PyWalletError::from_msg("Test error")
            .with_context("wallet operation")
            .with_context("key derivation");
        
        assert_eq!(err.full_message(), "Test error: wallet operation -> key derivation");
    }

    #[test]
    fn test_validation_error() {
        let err = ValidationError::new("seed_phrase", "Invalid length");
        let py_err = PyWalletError::from(err);
        assert!(py_err.message.contains("Validation error for seed_phrase"));
    }

    #[test]
    fn test_crypto_error() {
        let err = CryptoError::new("signature verification", "Invalid signature");
        let py_err = PyWalletError::from(err);
        assert!(py_err.message.contains("Cryptographic error in signature verification"));
    }
}
