//! Storage trait definition for wallet transaction persistence
//! 
//! This module defines the `WalletStorage` trait that provides a common interface
//! for different storage backends to persist and retrieve wallet transaction data.

use async_trait::async_trait;
use std::collections::HashMap;

use crate::{
    data_structures::{
        wallet_transaction::{WalletTransaction, WalletState},
        types::CompressedCommitment,
        transaction::{TransactionStatus, TransactionDirection},
    },
    errors::LightweightWalletResult,
};

/// Storage query filters for retrieving transactions
#[derive(Debug, Clone, Default)]
pub struct TransactionFilter {
    /// Filter by block height range
    pub block_height_range: Option<(u64, u64)>,
    /// Filter by transaction direction
    pub direction: Option<TransactionDirection>,
    /// Filter by transaction status
    pub status: Option<TransactionStatus>,
    /// Filter by spent status
    pub is_spent: Option<bool>,
    /// Filter by maturity status
    pub is_mature: Option<bool>,
    /// Limit number of results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Transaction storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    /// Total number of transactions stored
    pub total_transactions: usize,
    /// Number of inbound transactions
    pub inbound_count: usize,
    /// Number of outbound transactions
    pub outbound_count: usize,
    /// Number of unspent transactions
    pub unspent_count: usize,
    /// Number of spent transactions
    pub spent_count: usize,
    /// Total value received
    pub total_received: u64,
    /// Total value spent
    pub total_spent: u64,
    /// Current balance
    pub current_balance: i64,
    /// Highest block height processed
    pub highest_block: Option<u64>,
    /// Lowest block height processed
    pub lowest_block: Option<u64>,
}

/// Trait for wallet transaction storage backends
#[async_trait]
pub trait WalletStorage: Send + Sync {
    /// Initialize the storage backend (create tables, indexes, etc.)
    async fn initialize(&self) -> LightweightWalletResult<()>;

    /// Save a single transaction to storage
    async fn save_transaction(&self, transaction: &WalletTransaction) -> LightweightWalletResult<()>;

    /// Save multiple transactions in a batch for efficiency
    async fn save_transactions(&self, transactions: &[WalletTransaction]) -> LightweightWalletResult<()>;

    /// Update an existing transaction (e.g., mark as spent)
    async fn update_transaction(&self, transaction: &WalletTransaction) -> LightweightWalletResult<()>;

    /// Mark a transaction as spent by commitment
    async fn mark_transaction_spent(
        &self,
        commitment: &CompressedCommitment,
        spent_in_block: u64,
        spent_in_input: usize,
    ) -> LightweightWalletResult<bool>;

    /// Get a transaction by commitment
    async fn get_transaction_by_commitment(
        &self,
        commitment: &CompressedCommitment,
    ) -> LightweightWalletResult<Option<WalletTransaction>>;

    /// Get transactions with optional filtering
    async fn get_transactions(
        &self,
        filter: Option<TransactionFilter>,
    ) -> LightweightWalletResult<Vec<WalletTransaction>>;

    /// Get all transactions and build a WalletState
    async fn load_wallet_state(&self) -> LightweightWalletResult<WalletState>;

    /// Get storage statistics
    async fn get_statistics(&self) -> LightweightWalletResult<StorageStats>;

    /// Get transactions by block height range
    async fn get_transactions_by_block_range(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> LightweightWalletResult<Vec<WalletTransaction>>;

    /// Get unspent transactions only
    async fn get_unspent_transactions(&self) -> LightweightWalletResult<Vec<WalletTransaction>>;

    /// Get spent transactions only
    async fn get_spent_transactions(&self) -> LightweightWalletResult<Vec<WalletTransaction>>;

    /// Check if a commitment exists in storage
    async fn has_commitment(&self, commitment: &CompressedCommitment) -> LightweightWalletResult<bool>;

    /// Get the highest block height processed
    async fn get_highest_block(&self) -> LightweightWalletResult<Option<u64>>;

    /// Get the lowest block height processed
    async fn get_lowest_block(&self) -> LightweightWalletResult<Option<u64>>;

    /// Clear all transactions (useful for re-scanning)
    async fn clear_all_transactions(&self) -> LightweightWalletResult<()>;

    /// Get transaction count
    async fn get_transaction_count(&self) -> LightweightWalletResult<usize>;

    /// Close the storage connection gracefully
    async fn close(&self) -> LightweightWalletResult<()>;
}

impl TransactionFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by block height range
    pub fn with_block_range(mut self, from: u64, to: u64) -> Self {
        self.block_height_range = Some((from, to));
        self
    }

    /// Filter by transaction direction
    pub fn with_direction(mut self, direction: TransactionDirection) -> Self {
        self.direction = Some(direction);
        self
    }

    /// Filter by transaction status
    pub fn with_status(mut self, status: TransactionStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Filter by spent status
    pub fn with_spent_status(mut self, is_spent: bool) -> Self {
        self.is_spent = Some(is_spent);
        self
    }

    /// Filter by maturity status
    pub fn with_maturity(mut self, is_mature: bool) -> Self {
        self.is_mature = Some(is_mature);
        self
    }

    /// Limit results
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set offset for pagination
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }
} 