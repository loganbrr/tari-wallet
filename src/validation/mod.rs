//! Validation module for lightweight wallet functionality
//! 
//! This module provides lightweight validation for UTXOs and transactions
//! without requiring the full Tari crypto stack.

pub mod batch;
pub mod commitment;
pub mod encrypted_data;
pub mod minimum_value_promise;
pub mod script_pattern;

pub use batch::{
    validate_output_batch,
    BatchValidationResult,
    BatchValidationOptions,
    OutputValidationResult,
    BatchValidationSummary,
};

#[cfg(feature = "grpc")]
pub use batch::validate_output_batch_parallel;

pub use commitment::LightweightCommitmentValidator;

pub use encrypted_data::{
    LightweightEncryptedDataValidator,
    EncryptedDataValidationResult,
    validate_encrypted_data_comprehensive,
};

pub use minimum_value_promise::{
    LightweightMinimumValuePromiseValidator,
    MinimumValuePromiseValidationOptions,
    MinimumValuePromiseValidationResult,
};

// Re-export commonly used types and functions
pub use script_pattern::{ScriptPattern, analyze_script_pattern, is_wallet_output}; 