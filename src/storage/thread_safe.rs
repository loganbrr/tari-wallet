//! Thread-safe storage wrapper for use in multi-threaded contexts
//!
//! This module provides a `ThreadSafeStorage` wrapper that allows sharing a 
//! storage implementation across threads while maintaining the `WalletStorage` 
//! trait interface. It uses `Arc<Mutex<T>>` for thread-safe access and converts
//! async operations to synchronous ones using `futures::executor::block_on`.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::{
    data_structures::{
        types::CompressedCommitment,
        wallet_transaction::{WalletState, WalletTransaction},
    },
    errors::LightweightWalletResult,
    storage::{
        OutputFilter, StorageStats, StoredOutput, StoredWallet, TransactionFilter, WalletStorage,
    },
};

/// A thread-safe wrapper around a `WalletStorage` implementation
/// 
/// This wrapper allows a storage backend to be shared across threads
/// by wrapping it in `Arc<Mutex<T>>` and implementing `WalletStorage`
/// by forwarding calls to the inner storage with proper locking.
/// 
/// All async operations are converted to synchronous ones using 
/// `futures::executor::block_on` to maintain the expected interface.
pub struct ThreadSafeStorage<T: WalletStorage>(Arc<Mutex<T>>);

impl<T: WalletStorage> ThreadSafeStorage<T> {
    /// Create a new thread-safe storage wrapper
    pub fn new(storage: T) -> Self {
        Self(Arc::new(Mutex::new(storage)))
    }

    /// Get a cloned reference to the inner storage
    pub fn inner(&self) -> Arc<Mutex<T>> {
        Arc::clone(&self.0)
    }

    /// Create from an existing Arc<Mutex<T>>
    pub fn from_arc(storage: Arc<Mutex<T>>) -> Self {
        Self(storage)
    }
}

impl<T: WalletStorage> Clone for ThreadSafeStorage<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

#[async_trait]
impl<T: WalletStorage> WalletStorage for ThreadSafeStorage<T> {
    async fn initialize(&self) -> LightweightWalletResult<()> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.initialize())
    }

    // === Wallet Management Methods ===

    async fn save_wallet(&self, wallet: &StoredWallet) -> LightweightWalletResult<u32> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.save_wallet(wallet))
    }

    async fn get_wallet_by_id(
        &self,
        wallet_id: u32,
    ) -> LightweightWalletResult<Option<StoredWallet>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_wallet_by_id(wallet_id))
    }

    async fn get_wallet_by_name(
        &self,
        name: &str,
    ) -> LightweightWalletResult<Option<StoredWallet>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_wallet_by_name(name))
    }

    async fn list_wallets(&self) -> LightweightWalletResult<Vec<StoredWallet>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.list_wallets())
    }

    async fn delete_wallet(&self, wallet_id: u32) -> LightweightWalletResult<bool> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.delete_wallet(wallet_id))
    }

    async fn wallet_name_exists(&self, name: &str) -> LightweightWalletResult<bool> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.wallet_name_exists(name))
    }

    async fn update_wallet_scanned_block(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> LightweightWalletResult<()> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.update_wallet_scanned_block(wallet_id, block_height))
    }

    // === Transaction Management Methods ===

    async fn save_transaction(
        &self,
        wallet_id: u32,
        transaction: &WalletTransaction,
    ) -> LightweightWalletResult<()> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.save_transaction(wallet_id, transaction))
    }

    async fn save_transactions(
        &self,
        wallet_id: u32,
        transactions: &[WalletTransaction],
    ) -> LightweightWalletResult<()> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.save_transactions(wallet_id, transactions))
    }

    async fn update_transaction(
        &self,
        transaction: &WalletTransaction,
    ) -> LightweightWalletResult<()> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.update_transaction(transaction))
    }

    async fn mark_transaction_spent(
        &self,
        commitment: &CompressedCommitment,
        spent_in_block: u64,
        spent_in_input: usize,
    ) -> LightweightWalletResult<bool> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.mark_transaction_spent(commitment, spent_in_block, spent_in_input))
    }

    async fn mark_transactions_spent_batch(
        &self,
        spent_commitments: &[(CompressedCommitment, u64, usize)],
    ) -> LightweightWalletResult<usize> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.mark_transactions_spent_batch(spent_commitments))
    }

    async fn get_transaction_by_commitment(
        &self,
        commitment: &CompressedCommitment,
    ) -> LightweightWalletResult<Option<WalletTransaction>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_transaction_by_commitment(commitment))
    }

    async fn get_transactions(
        &self,
        filter: Option<TransactionFilter>,
    ) -> LightweightWalletResult<Vec<WalletTransaction>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_transactions(filter))
    }

    async fn load_wallet_state(&self, wallet_id: u32) -> LightweightWalletResult<WalletState> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.load_wallet_state(wallet_id))
    }

    async fn get_statistics(&self) -> LightweightWalletResult<StorageStats> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_statistics())
    }

    async fn get_wallet_statistics(
        &self,
        wallet_id: Option<u32>,
    ) -> LightweightWalletResult<StorageStats> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_wallet_statistics(wallet_id))
    }

    async fn get_transactions_by_block_range(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> LightweightWalletResult<Vec<WalletTransaction>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_transactions_by_block_range(from_block, to_block))
    }

    async fn get_unspent_transactions(&self) -> LightweightWalletResult<Vec<WalletTransaction>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_unspent_transactions())
    }

    async fn get_spent_transactions(&self) -> LightweightWalletResult<Vec<WalletTransaction>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_spent_transactions())
    }

    async fn has_commitment(
        &self,
        commitment: &CompressedCommitment,
    ) -> LightweightWalletResult<bool> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.has_commitment(commitment))
    }

    async fn get_highest_block(&self) -> LightweightWalletResult<Option<u64>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_highest_block())
    }

    async fn get_lowest_block(&self) -> LightweightWalletResult<Option<u64>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_lowest_block())
    }

    async fn clear_all_transactions(&self) -> LightweightWalletResult<()> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.clear_all_transactions())
    }

    async fn get_transaction_count(&self) -> LightweightWalletResult<usize> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_transaction_count())
    }

    async fn close(&self) -> LightweightWalletResult<()> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.close())
    }

    // === UTXO Output Management Methods ===

    async fn save_output(&self, output: &StoredOutput) -> LightweightWalletResult<u32> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.save_output(output))
    }

    async fn save_outputs(&self, outputs: &[StoredOutput]) -> LightweightWalletResult<Vec<u32>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.save_outputs(outputs))
    }

    async fn update_output(&self, output: &StoredOutput) -> LightweightWalletResult<()> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.update_output(output))
    }

    async fn mark_output_spent(
        &self,
        output_id: u32,
        spent_in_tx_id: u64,
    ) -> LightweightWalletResult<()> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.mark_output_spent(output_id, spent_in_tx_id))
    }

    async fn get_output_by_id(
        &self,
        output_id: u32,
    ) -> LightweightWalletResult<Option<StoredOutput>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_output_by_id(output_id))
    }

    async fn get_output_by_commitment(
        &self,
        commitment: &[u8],
    ) -> LightweightWalletResult<Option<StoredOutput>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_output_by_commitment(commitment))
    }

    async fn get_outputs(
        &self,
        filter: Option<OutputFilter>,
    ) -> LightweightWalletResult<Vec<StoredOutput>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_outputs(filter))
    }

    async fn get_unspent_outputs(
        &self,
        wallet_id: u32,
    ) -> LightweightWalletResult<Vec<StoredOutput>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_unspent_outputs(wallet_id))
    }

    async fn get_spendable_outputs(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> LightweightWalletResult<Vec<StoredOutput>> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_spendable_outputs(wallet_id, block_height))
    }

    async fn get_spendable_balance(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> LightweightWalletResult<u64> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_spendable_balance(wallet_id, block_height))
    }

    async fn delete_output(&self, output_id: u32) -> LightweightWalletResult<bool> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.delete_output(output_id))
    }

    async fn clear_outputs(&self, wallet_id: u32) -> LightweightWalletResult<()> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.clear_outputs(wallet_id))
    }

    async fn get_output_count(&self, wallet_id: u32) -> LightweightWalletResult<usize> {
        let storage = self.0.lock().unwrap();
        futures::executor::block_on(storage.get_output_count(wallet_id))
    }
}
