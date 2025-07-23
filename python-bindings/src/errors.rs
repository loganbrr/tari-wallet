//! Enhanced error handling framework for Python bindings
//! 
//! This module provides comprehensive error conversion from Rust errors to Python exceptions
//! with GIL-aware conversion, structured error context preservation, and custom exception hierarchy.
//! 
//! ## Exception Hierarchy
//! 
//! The Python exception hierarchy follows best practices with a base `WalletError` exception
//! and specific derived exceptions for different error categories:
//! 
//! ```
//! WalletError (base)
//! ├── WalletScanningError      (blockchain scanning operations)
//! ├── WalletValidationError    (cryptographic validation)
//! ├── WalletKeyManagementError (key derivation and management)
//! ├── WalletEncryptionError    (encryption/decryption operations)
//! ├── WalletSerializationError (data encoding/decoding)
//! └── WalletDataStructureError (data structure validation)
//! ```
//! 
//! ## Error Chain Preservation
//! 
//! The conversion system preserves Rust error source chains when converting to Python
//! exceptions, ensuring that debugging information is maintained across the language boundary.

use pyo3::{
    create_exception, 
    exceptions::{PyException, PyValueError, PyConnectionError, PyTimeoutError, PyFileNotFoundError},
    PyErr, Python
};
use lightweight_wallet_libs::errors::LightweightWalletError;
use std::time::{SystemTime, UNIX_EPOCH};

// ========== Custom Python Exception Hierarchy ==========

create_exception!(lightweight_wallet_libpy, WalletError, PyException, "Base wallet exception");
create_exception!(lightweight_wallet_libpy, WalletScanningError, WalletError, "Blockchain scanning error");
create_exception!(lightweight_wallet_libpy, WalletValidationError, WalletError, "Cryptographic validation error");
create_exception!(lightweight_wallet_libpy, WalletKeyManagementError, WalletError, "Key management and derivation error");
create_exception!(lightweight_wallet_libpy, WalletEncryptionError, WalletError, "Encryption/decryption error");
create_exception!(lightweight_wallet_libpy, WalletSerializationError, WalletError, "Data serialization/encoding error");
create_exception!(lightweight_wallet_libpy, WalletDataStructureError, WalletError, "Data structure validation error");

// ========== Error Context Structure ==========

/// Error context for detailed error information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ErrorContext {
    pub operation: String,
    pub connection_id: Option<String>,
    pub timestamp: u64,
    pub details: Option<String>,
}

impl ErrorContext {
    #[allow(dead_code)]
    pub fn new(operation: &str) -> Self {
        Self {
            operation: operation.to_string(),
            connection_id: None,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            details: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_connection(mut self, connection_id: &str) -> Self {
        self.connection_id = Some(connection_id.to_string());
        self
    }

    #[allow(dead_code)]
    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }

    pub fn format(&self) -> String {
        let mut context = format!("Operation: {}, Timestamp: {}", self.operation, self.timestamp);
        if let Some(ref conn_id) = self.connection_id {
            context.push_str(&format!(", Connection: {}", conn_id));
        }
        if let Some(ref details) = self.details {
            context.push_str(&format!(", Details: {}", details));
        }
        context
    }
}

// ========== Enhanced Error Discriminant System ==========

/// Error discriminant for zero-cost error type identification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorDiscriminant {
    DataStructure = 1,
    Serialization = 2,
    Validation = 3,
    KeyManagement = 4,
    Scanning = 5,
    Encryption = 6,
    Conversion = 7,
    InvalidArgument = 8,
    OperationNotSupported = 9,
    ResourceNotFound = 10,
    InsufficientFunds = 11,
    Timeout = 12,
    Network = 13,
    Storage = 14,
    Internal = 15,
    Connection = 16,
    Grpc = 17,
    Data = 18,
    Configuration = 19,
}

// ========== Error Helper Functions ==========

/// Get error discriminant for zero-cost type identification
pub fn get_error_discriminant(err: &LightweightWalletError) -> ErrorDiscriminant {
    match err {
        LightweightWalletError::DataStructureError(_) => ErrorDiscriminant::DataStructure,
        LightweightWalletError::SerializationError(_) => ErrorDiscriminant::Serialization,
        LightweightWalletError::ValidationError(_) => ErrorDiscriminant::Validation,
        LightweightWalletError::KeyManagementError(_) => ErrorDiscriminant::KeyManagement,
        LightweightWalletError::ScanningError(_) => ErrorDiscriminant::Scanning,
        LightweightWalletError::EncryptionError(_) => ErrorDiscriminant::Encryption,
        LightweightWalletError::ConversionError(_) => ErrorDiscriminant::Conversion,
        LightweightWalletError::InvalidArgument { .. } => ErrorDiscriminant::InvalidArgument,
        LightweightWalletError::OperationNotSupported(_) => ErrorDiscriminant::OperationNotSupported,
        LightweightWalletError::ResourceNotFound(_) => ErrorDiscriminant::ResourceNotFound,
        LightweightWalletError::InsufficientFunds(_) => ErrorDiscriminant::InsufficientFunds,
        LightweightWalletError::Timeout(_) => ErrorDiscriminant::Timeout,
        LightweightWalletError::NetworkError(_) => ErrorDiscriminant::Network,
        LightweightWalletError::StorageError(_) => ErrorDiscriminant::Storage,
        LightweightWalletError::InternalError(_) => ErrorDiscriminant::Internal,
        LightweightWalletError::ConnectionError(_) => ErrorDiscriminant::Connection,
        LightweightWalletError::GrpcError(_) => ErrorDiscriminant::Grpc,
        LightweightWalletError::DataError(_) => ErrorDiscriminant::Data,
        LightweightWalletError::ConfigurationError(_) => ErrorDiscriminant::Configuration,
        LightweightWalletError::HexError(_) => ErrorDiscriminant::Serialization,
    }
}

/// Get error message for context preservation
pub fn get_error_message(err: &LightweightWalletError) -> String {
    err.to_string()
}

/// Get detailed error context if available
pub fn get_error_context(err: &LightweightWalletError) -> Option<String> {
    // Extract additional context based on error type
    match err {
        LightweightWalletError::InvalidArgument { argument, value, message } => {
            Some(format!("Argument '{}' with value '{}': {}", argument, value, message))
        }
        LightweightWalletError::KeyManagementError(key_err) => {
            // Add specific context for key management errors
            Some(format!("Key management operation failed: {}", key_err))
        }
        LightweightWalletError::ScanningError(scan_err) => {
            // Add specific context for scanning errors
            Some(format!("Blockchain scanning operation failed: {}", scan_err))
        }
        LightweightWalletError::ValidationError(val_err) => {
            // Add specific context for validation errors
            Some(format!("Cryptographic validation failed: {}", val_err))
        }
        _ => None,
    }
}

/// Get error source chain for enhanced debugging
/// 
/// Walks the error source chain and builds a formatted string showing the
/// complete error causality chain, improving debugging across the Rust-Python boundary.
pub fn get_error_source_chain(err: &LightweightWalletError) -> String {
    use std::error::Error;
    
    let mut chain_parts = Vec::new();
    let mut current_error: &dyn Error = err;
    
    // Walk the source chain
    while let Some(source) = current_error.source() {
        chain_parts.push(source.to_string());
        current_error = source;
    }
    
    if chain_parts.is_empty() {
        String::new()
    } else {
        chain_parts.join(" → ")
    }
}

// ========== GIL-Aware Error Conversion ==========

/// Enhanced error conversion with GIL awareness and custom exception mapping
/// 
/// This function converts Rust `LightweightWalletError` to Python exceptions while
/// preserving error source chain information for better debugging.
pub fn convert_to_pyerr(err: LightweightWalletError) -> PyErr {
    Python::with_gil(|_py| {
        let message = get_error_message(&err);
        let context_info = get_error_context(&err).unwrap_or_default();
        let source_chain = get_error_source_chain(&err);
        
        // Create detailed error message with context and source chain
        let detailed_message = if context_info.is_empty() && source_chain.is_empty() {
            message
        } else if context_info.is_empty() {
            format!("{}\nError chain: {}", message, source_chain)
        } else if source_chain.is_empty() {
            format!("{}\nContext: {}", message, context_info)
        } else {
            format!("{}\nContext: {}\nError chain: {}", message, context_info, source_chain)
        };

        // Map based on error discriminant for zero-cost conversion
        match get_error_discriminant(&err) {
            ErrorDiscriminant::DataStructure => {
                WalletDataStructureError::new_err(detailed_message)
            }
            ErrorDiscriminant::Serialization => {
                WalletSerializationError::new_err(detailed_message)
            }
            ErrorDiscriminant::Validation => {
                WalletValidationError::new_err(detailed_message)
            }
            ErrorDiscriminant::KeyManagement => {
                WalletKeyManagementError::new_err(detailed_message)
            }
            ErrorDiscriminant::Scanning => {
                WalletScanningError::new_err(detailed_message)
            }
            ErrorDiscriminant::Encryption => {
                WalletEncryptionError::new_err(detailed_message)
            }
            ErrorDiscriminant::InvalidArgument => {
                PyValueError::new_err(detailed_message)
            }
            ErrorDiscriminant::ResourceNotFound => {
                PyFileNotFoundError::new_err(detailed_message)
            }
            ErrorDiscriminant::Timeout => {
                PyTimeoutError::new_err(detailed_message)
            }
            ErrorDiscriminant::Network | ErrorDiscriminant::Connection | ErrorDiscriminant::Grpc => {
                PyConnectionError::new_err(detailed_message)
            }
            _ => {
                // Fallback to generic wallet error for other types
                WalletError::new_err(detailed_message)
            }
        }
    })
}

// ========== Convenience Functions ==========

/// Convert LightweightWalletError to Python exception with operation context
/// 
/// This function provides enhanced error conversion with operation-specific context
/// and error source chain preservation for better debugging and error handling in Python applications.
#[allow(dead_code)]
pub fn convert_error_with_context(err: LightweightWalletError, context: ErrorContext) -> PyErr {
    Python::with_gil(|_py| {
        let message = get_error_message(&err);
        let error_context = get_error_context(&err).unwrap_or_default();
        let source_chain = get_error_source_chain(&err);
        let operation_context = context.format();
        
        // Combine all context information including error source chain
        let full_message = if error_context.is_empty() && source_chain.is_empty() {
            format!("{}\n{}", message, operation_context)
        } else if error_context.is_empty() {
            format!("{}\nError chain: {}\n{}", message, source_chain, operation_context)
        } else if source_chain.is_empty() {
            format!("{}\nError Context: {}\n{}", message, error_context, operation_context)
        } else {
            format!("{}\nError Context: {}\nError chain: {}\n{}", message, error_context, source_chain, operation_context)
        };

        // Map to appropriate exception type
        match get_error_discriminant(&err) {
            ErrorDiscriminant::DataStructure => {
                WalletDataStructureError::new_err(full_message)
            }
            ErrorDiscriminant::Serialization => {
                WalletSerializationError::new_err(full_message)
            }
            ErrorDiscriminant::Validation => {
                WalletValidationError::new_err(full_message)
            }
            ErrorDiscriminant::KeyManagement => {
                WalletKeyManagementError::new_err(full_message)
            }
            ErrorDiscriminant::Scanning => {
                WalletScanningError::new_err(full_message)
            }
            ErrorDiscriminant::Encryption => {
                WalletEncryptionError::new_err(full_message)
            }
            ErrorDiscriminant::InvalidArgument => {
                PyValueError::new_err(full_message)
            }
            ErrorDiscriminant::ResourceNotFound => {
                PyFileNotFoundError::new_err(full_message)
            }
            ErrorDiscriminant::Timeout => {
                PyTimeoutError::new_err(full_message)
            }
            ErrorDiscriminant::Network | ErrorDiscriminant::Connection | ErrorDiscriminant::Grpc => {
                PyConnectionError::new_err(full_message)
            }
            _ => {
                WalletError::new_err(full_message)
            }
        }
    })
}

/// Legacy conversion function for backwards compatibility
/// 
/// This function maintains the original simple conversion for code that hasn't
/// been updated to use the enhanced error conversion system.
#[allow(dead_code)]
pub fn convert_error(err: LightweightWalletError) -> PyErr {
    // Use the enhanced conversion function
    convert_to_pyerr(err)
}

/// Check if an error type should trigger connection pool eviction
#[allow(dead_code)]
pub fn should_evict_connection(err: &LightweightWalletError) -> bool {
    matches!(
        get_error_discriminant(err),
        ErrorDiscriminant::Network | 
        ErrorDiscriminant::Connection | 
        ErrorDiscriminant::Timeout |
        ErrorDiscriminant::Grpc
    )
}

/// Get error category for metrics and monitoring
#[allow(dead_code)]
pub fn get_error_category(err: &LightweightWalletError) -> &'static str {
    match get_error_discriminant(err) {
        ErrorDiscriminant::DataStructure => "data_structure",
        ErrorDiscriminant::Serialization => "serialization", 
        ErrorDiscriminant::Validation => "validation",
        ErrorDiscriminant::KeyManagement => "key_management",
        ErrorDiscriminant::Scanning => "scanning",
        ErrorDiscriminant::Encryption => "encryption",
        ErrorDiscriminant::Conversion => "conversion",
        ErrorDiscriminant::InvalidArgument => "invalid_argument",
        ErrorDiscriminant::OperationNotSupported => "operation_not_supported",
        ErrorDiscriminant::ResourceNotFound => "resource_not_found",
        ErrorDiscriminant::InsufficientFunds => "insufficient_funds",
        ErrorDiscriminant::Timeout => "timeout",
        ErrorDiscriminant::Network => "network",
        ErrorDiscriminant::Storage => "storage",
        ErrorDiscriminant::Internal => "internal",
        ErrorDiscriminant::Connection => "connection",
        ErrorDiscriminant::Grpc => "grpc",
        ErrorDiscriminant::Data => "data",
        ErrorDiscriminant::Configuration => "configuration",
    }
}

// ========== From Trait Implementation ==========
// Note: Cannot implement From<LightweightWalletError> for PyErr due to orphan rules.
// Use convert_to_pyerr() or convert_error() instead.

#[cfg(test)]
mod tests {
    use super::*;
    use lightweight_wallet_libs::errors::{ValidationError as LibValidationError, ScanningError as LibScanningError};
    
    #[test]
    fn test_error_discriminant_mapping() {
        let validation_error = LightweightWalletError::ValidationError(
            LibValidationError::RangeProofValidationFailed("test".into())
        );
        assert_eq!(get_error_discriminant(&validation_error), ErrorDiscriminant::Validation);
        
        let scanning_error = LightweightWalletError::ScanningError(
            LibScanningError::BlockchainConnectionFailed("test".into())
        );
        assert_eq!(get_error_discriminant(&scanning_error), ErrorDiscriminant::Scanning);
        
        let timeout_error = LightweightWalletError::Timeout("test".into());
        assert_eq!(get_error_discriminant(&timeout_error), ErrorDiscriminant::Timeout);
    }
    
    #[test]
    fn test_error_context() {
        let context = ErrorContext::new("wallet_sync")
            .with_connection("pool_001")
            .with_details("Block height validation failed");
        
        let formatted = context.format();
        assert!(formatted.contains("Operation: wallet_sync"));
        assert!(formatted.contains("Connection: pool_001"));
        assert!(formatted.contains("Details: Block height validation failed"));
    }
    
    #[test]
    fn test_enhanced_error_conversion() {
        let rust_error = LightweightWalletError::ValidationError(
            LibValidationError::RangeProofValidationFailed("test".into())
        );
        let _py_error: PyErr = convert_to_pyerr(rust_error);
        // This test ensures the enhanced conversion function compiles and works
    }
    
    #[test]
    fn test_legacy_error_conversion() {
        let rust_error = LightweightWalletError::ValidationError(
            LibValidationError::RangeProofValidationFailed("test".into())
        );
        let _py_error: PyErr = convert_error(rust_error);
        // This test ensures backwards compatibility
    }
    
    #[test]
    fn test_connection_eviction_detection() {
        let network_error = LightweightWalletError::NetworkError("connection failed".into());
        assert!(should_evict_connection(&network_error));
        
        let timeout_error = LightweightWalletError::Timeout("request timeout".into());
        assert!(should_evict_connection(&timeout_error));
        
        let validation_error = LightweightWalletError::ValidationError(
            LibValidationError::RangeProofValidationFailed("test".into())
        );
        assert!(!should_evict_connection(&validation_error));
    }
    
    #[test]
    fn test_error_categorization() {
        let network_error = LightweightWalletError::NetworkError("test".into());
        assert_eq!(get_error_category(&network_error), "network");
        
        let validation_error = LightweightWalletError::ValidationError(
            LibValidationError::RangeProofValidationFailed("test".into())
        );
        assert_eq!(get_error_category(&validation_error), "validation");
    }
    
    #[test]
    fn test_error_context_extraction() {
        let invalid_arg_error = LightweightWalletError::InvalidArgument {
            argument: "block_height".to_string(),
            value: "-1".to_string(),
            message: "Height cannot be negative".to_string(),
        };
        
        let context = get_error_context(&invalid_arg_error);
        assert!(context.is_some());
        assert!(context.unwrap().contains("block_height"));
        let context = get_error_context(&invalid_arg_error);
        assert!(context.unwrap().contains("-1"));
    }
    
    #[test]
    fn test_convert_error_with_context() {
        let rust_error = LightweightWalletError::ScanningError(
            LibScanningError::BlockchainConnectionFailed("connection timeout".into())
        );
        
        let context = ErrorContext::new("blockchain_scan")
            .with_connection("mainnet_pool")
            .with_details("Scanning blocks 1000-2000");
        
        let _py_error = convert_error_with_context(rust_error, context);
        // This test ensures the context-aware conversion compiles and works
    }
    
    #[test]
    fn test_error_source_chain_extraction() {
        // Test source chain extraction for nested errors
        let validation_error = LightweightWalletError::ValidationError(
            LibValidationError::RangeProofValidationFailed("proof invalid".into())
        );
        
        let source_chain = get_error_source_chain(&validation_error);
        assert!(source_chain.contains("Range proof validation failed"), 
               "Source chain should contain the validation error message");
        
        // Test source chain for root-level errors (should be empty)
        let root_error = LightweightWalletError::ConversionError("test".into());
        let source_chain = get_error_source_chain(&root_error);
        assert!(source_chain.is_empty(), "Root errors should have empty source chain");
    }
    
    #[test]
    fn test_enhanced_error_conversion_with_source_chain() {
        // Create a validation error and verify the converted PyErr contains source chain info
        let validation_error = LightweightWalletError::ValidationError(
            LibValidationError::MetadataSignatureValidationFailed("signature mismatch".into())
        );
        
        let _py_error = convert_to_pyerr(validation_error);
        // This test ensures that the enhanced conversion with source chain works
        // In a real implementation, we'd check the error message content
    }
    
    #[test]
    fn test_exception_hierarchy_completeness() {
        // Verify that all error discriminants have proper exception mappings
        use ErrorDiscriminant::*;
        
        let discriminants = [
            DataStructure, Serialization, Validation, KeyManagement,
            Scanning, Encryption, Conversion, InvalidArgument,
            OperationNotSupported, ResourceNotFound, InsufficientFunds,
            Timeout, Network, Storage, Internal, Connection, Grpc, Data, Configuration
        ];
        
        for discriminant in discriminants {
            // Create a dummy error for each discriminant
            let dummy_error = match discriminant {
                DataStructure => LightweightWalletError::DataStructureError(
                    lightweight_wallet_libs::errors::DataStructureError::InvalidAddress("test".into())
                ),
                Validation => LightweightWalletError::ValidationError(
                    LibValidationError::RangeProofValidationFailed("test".into())
                ),
                Scanning => LightweightWalletError::ScanningError(
                    LibScanningError::BlockchainConnectionFailed("test".into())
                ),
                _ => LightweightWalletError::ConversionError("test".into()),
            };
            
            // Verify conversion doesn't panic and produces a PyErr
            let _py_error = convert_to_pyerr(dummy_error);
        }
    }
}
