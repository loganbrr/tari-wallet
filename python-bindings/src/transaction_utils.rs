//! Transaction utility functions for Python bindings
//!
//! This module consolidates transaction-related functionality that was previously
//! duplicated between storage.rs and transaction.rs modules.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use lightweight_wallet_libs::data_structures::{
    transaction::{TransactionDirection, TransactionStatus},
    payment_id::PaymentId,
    wallet_transaction::WalletTransaction,
};
use lightweight_wallet_libs::storage::storage_trait::StoredWallet;

/// Parse transaction direction from string
pub fn parse_transaction_direction(direction_str: &str) -> Result<TransactionDirection, String> {
    match direction_str {
        "inbound" => Ok(TransactionDirection::Inbound),
        "outbound" => Ok(TransactionDirection::Outbound),
        _ => Err(format!("Invalid direction '{}'. Must be 'inbound' or 'outbound'", direction_str)),
    }
}

/// Parse transaction status from string
pub fn parse_transaction_status(status_str: &str) -> Result<TransactionStatus, String> {
    match status_str {
        "minedconfirmed" => Ok(TransactionStatus::MinedConfirmed),
        "minedunconfirmed" => Ok(TransactionStatus::MinedUnconfirmed),
        "coinbase" => Ok(TransactionStatus::Coinbase),
        "rejected" => Ok(TransactionStatus::Rejected),
        "broadcast" => Ok(TransactionStatus::Broadcast),
        "pending" => Ok(TransactionStatus::Pending),
        _ => Err(format!(
            "Invalid status '{}'. Must be one of: minedconfirmed, minedunconfirmed, coinbase, rejected, broadcast, pending",
            status_str
        )),
    }
}

/// Create a transaction dictionary for Python conversion
#[allow(dead_code)]
pub fn create_transaction_dict<'py>(py: Python<'py>, tx: &WalletTransaction) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("block_height", tx.block_height)?;
    dict.set_item("output_index", tx.output_index)?;
    dict.set_item("input_index", tx.input_index)?;
    dict.set_item("commitment_hex", tx.commitment_hex())?;
    dict.set_item("output_hash_hex", tx.output_hash.as_ref().map(|h| hex::encode(h)))?;
    dict.set_item("value", tx.value)?;
    dict.set_item("payment_id", format!("{:?}", tx.payment_id))?;
    dict.set_item("is_spent", tx.is_spent)?;
    dict.set_item("spent_in_block", tx.spent_in_block)?;
    dict.set_item("spent_in_input", tx.spent_in_input)?;
    dict.set_item("transaction_status", format!("{:?}", tx.transaction_status).to_lowercase())?;
    dict.set_item("transaction_direction", format!("{:?}", tx.transaction_direction).to_lowercase())?;
    dict.set_item("is_mature", tx.is_mature)?;
    Ok(dict)
}

/// Create wallet data dictionary for Python conversion
#[allow(dead_code)]
pub fn create_wallet_dict<'py>(py: Python<'py>, wallet: &StoredWallet) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("id", wallet.id)?;
    dict.set_item("name", &wallet.name)?;
    dict.set_item("seed_phrase", &wallet.seed_phrase)?;
    dict.set_item("view_key_hex", &wallet.view_key_hex)?;
    dict.set_item("spend_key_hex", &wallet.spend_key_hex)?;
    dict.set_item("birthday_block", wallet.birthday_block)?;
    dict.set_item("latest_scanned_block", wallet.latest_scanned_block)?;
    dict.set_item("created_at", &wallet.created_at)?;
    dict.set_item("updated_at", &wallet.updated_at)?;
    Ok(dict)
}

/// Simplified payment ID creation (placeholder for now)
#[allow(dead_code)]
pub fn create_payment_id() -> PaymentId {
    PaymentId::Empty
}
