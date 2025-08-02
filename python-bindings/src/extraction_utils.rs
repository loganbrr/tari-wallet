//! Common utilities for extraction modules
//!
//! This module provides shared functionality to eliminate code duplication
//! across extraction-related modules, including error handling patterns,
//! hex conversion utilities, and validation processing.

use pyo3::prelude::*;
use std::sync::{Arc, Mutex};
use borsh::BorshSerialize;

use crate::errors::PyWalletError;
use crate::extraction_wrappers::PyLightweightTransactionOutput;
use lightweight_wallet_libs::{
    data_structures::transaction_output::LightweightTransactionOutput,
    errors::LightweightWalletError,
};

/// Standardized Arc<Mutex<T>> lock error handling
///
/// Provides consistent error messages and handling for mutex lock failures
/// across all extraction configuration types.
pub fn lock_with_conversion_error<'a, T>(
    mutex: &'a Arc<Mutex<T>>, 
    context: &str
) -> PyResult<std::sync::MutexGuard<'a, T>> {
    mutex.lock().map_err(|e| {
        PyWalletError(LightweightWalletError::ConversionError(
            format!("Failed to lock {}: {}", context, e)
        )).into()
    })
}

/// Serialize a field to hex with standardized error handling
///
/// Provides consistent serialization and hex encoding for complex types
/// following the established pattern for Python bindings.
pub fn serialize_field_to_hex<T: BorshSerialize>(
    field: &T, 
    field_name: &str
) -> PyResult<String> {
    use borsh::to_vec;
    
    let bytes = to_vec(field).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(
            format!("Failed to serialize {}: {}", field_name, e)
        )
    })?;
    
    Ok(hex::encode(bytes))
}

/// Common processing logic for converting Python outputs to Rust
///
/// Eliminates duplication in input conversion between validation functions.
pub fn convert_outputs_to_rust(
    outputs: Vec<PyLightweightTransactionOutput>
) -> PyResult<Vec<LightweightTransactionOutput>> {
    outputs
        .iter()
        .map(|output| output.to_rust())
        .collect()
}



/// Common hex conversion utilities for wrapper types
pub mod hex_utils {
    use super::*;
    use lightweight_wallet_libs::data_structures::types::{CompressedCommitment, CompressedPublicKey};

    /// Convert compressed commitment to hex
    pub fn commitment_to_hex(commitment: &CompressedCommitment) -> String {
        hex::encode(commitment.as_bytes())
    }

    /// Convert compressed public key to hex
    pub fn public_key_to_hex(key: &CompressedPublicKey) -> String {
        hex::encode(key.as_bytes())
    }

    /// Convert optional field to hex
    pub fn optional_to_hex<T: BorshSerialize>(field: &Option<T>, field_name: &str) -> PyResult<Option<String>> {
        match field {
            Some(value) => Ok(Some(serialize_field_to_hex(value, field_name)?)),
            None => Ok(None),
        }
    }
}
