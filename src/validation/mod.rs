//! Validation module for lightweight wallet functionality
//!
//! This module provides lightweight validation for UTXOs and transactions
//! without requiring the full Tari crypto stack.

pub mod commitment;
pub mod encrypted_data;
pub mod minimum_value_promise;
pub mod script_pattern;

pub use commitment::LightweightCommitmentValidator;

pub use encrypted_data::{
    validate_encrypted_data_comprehensive, EncryptedDataValidationResult,
    LightweightEncryptedDataValidator,
};

pub use minimum_value_promise::{
    LightweightMinimumValuePromiseValidator, MinimumValuePromiseValidationOptions,
    MinimumValuePromiseValidationResult,
};

// Re-export commonly used types and functions
pub use script_pattern::{analyze_script_pattern, is_wallet_output, ScriptPattern};
