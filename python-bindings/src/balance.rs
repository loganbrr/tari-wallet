//! Rust-native balance wrapper that directly reflects WalletState balance logic

use pyo3::prelude::*;
use std::sync::{Arc, Mutex};

use lightweight_wallet_libs::storage::{WalletStorage, sqlite::SqliteStorage};
use lightweight_wallet_libs::errors::LightweightWalletError;
use crate::runtime::execute_async;

/// Balance wrapper that directly exposes Rust WalletState balance data
#[pyclass]
pub struct TariBalance {
    /// Running balance from WalletState (can be negative)
    #[pyo3(get)]
    pub running_balance: i64,
    /// Storage reference for computing balances
    storage: Arc<Mutex<Option<SqliteStorage>>>,
    /// Wallet ID for balance queries
    wallet_id: u32,
}

#[pymethods]
impl TariBalance {
    /// Create a new balance wrapper from storage and wallet ID
    #[new]
    #[pyo3(signature = (storage, wallet_id), text_signature = "(storage, wallet_id)")]
    pub fn new(storage: &crate::storage::TariWalletStorage, wallet_id: u32) -> PyResult<Self> {
        // Load wallet state to get current running balance
        let storage_ref = storage.get_shared_storage()?;
        let storage_ref_clone: Arc<Mutex<Option<lightweight_wallet_libs::storage::sqlite::SqliteStorage>>> = Arc::clone(&storage_ref);
        let running_balance = execute_async(async move {
            let storage_guard = storage_ref_clone.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock storage".into()))?;
            
            let storage_impl = storage_guard.as_ref()
                .ok_or_else(|| LightweightWalletError::ConversionError("Storage not initialized".into()))?;
            
            let wallet_state = storage_impl.load_wallet_state(wallet_id).await?;
            Ok(wallet_state.get_balance())
        })?;
        
        Ok(TariBalance {
            running_balance,
            storage: storage_ref,
            wallet_id,
        })
    }

    /// Get the current running balance (direct from WalletState)
    fn get_running_balance(&self) -> PyResult<i64> {
        let storage_ref = Arc::clone(&self.storage);
        let wallet_id = self.wallet_id;
        
        execute_async(async move {
            let storage_guard = storage_ref.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock storage".into()))?;
            
            let storage = storage_guard.as_ref()
                .ok_or_else(|| LightweightWalletError::ConversionError("Storage not initialized".into()))?;
            
            let wallet_state = storage.load_wallet_state(wallet_id).await?;
            Ok(wallet_state.get_balance())
        })
    }

    /// Get available balance (mature, unspent outputs)
    fn available(&self) -> PyResult<u64> {
        let storage_ref = Arc::clone(&self.storage);
        let wallet_id = self.wallet_id;
        
        execute_async(async move {
            let storage_guard = storage_ref.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock storage".into()))?;
            
            let storage = storage_guard.as_ref()
                .ok_or_else(|| LightweightWalletError::ConversionError("Storage not initialized".into()))?;
            
            let wallet_state = storage.load_wallet_state(wallet_id).await?;
            
            // Calculate available balance from unspent, mature transactions
            let available = wallet_state.get_unspent_transactions()
                .iter()
                .filter(|tx| tx.is_mature && !tx.is_spent)
                .map(|tx| tx.value)
                .sum();
            
            Ok(available)
        })
    }

    /// Get pending balance (immature outputs that haven't matured yet)
    fn pending(&self) -> PyResult<u64> {
        let storage_ref = Arc::clone(&self.storage);
        let wallet_id = self.wallet_id;
        
        execute_async(async move {
            let storage_guard = storage_ref.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock storage".into()))?;
            
            let storage = storage_guard.as_ref()
                .ok_or_else(|| LightweightWalletError::ConversionError("Storage not initialized".into()))?;
            
            let wallet_state = storage.load_wallet_state(wallet_id).await?;
            
            // Calculate pending balance from unspent, immature transactions
            let pending = wallet_state.get_unspent_transactions()
                .iter()
                .filter(|tx| !tx.is_mature && !tx.is_spent)
                .map(|tx| tx.value)
                .sum();
            
            Ok(pending)
        })
    }

    /// Get immature balance (same as pending for coinbase outputs)
    fn immature(&self) -> PyResult<u64> {
        // For now, immature is the same as pending
        // This could be enhanced to specifically track coinbase outputs
        self.pending()
    }

    /// Get total balance (running balance as unsigned if positive, 0 if negative)
    fn total(&self) -> PyResult<u64> {
        let balance = self.get_running_balance()?;
        Ok(if balance >= 0 { balance as u64 } else { 0 })
    }

    /// Get detailed balance statistics
    fn get_stats(&self) -> PyResult<(u64, u64, i64, usize, usize)> {
        let storage_ref = Arc::clone(&self.storage);
        let wallet_id = self.wallet_id;
        
        execute_async(async move {
            let storage_guard = storage_ref.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock storage".into()))?;
            
            let storage = storage_guard.as_ref()
                .ok_or_else(|| LightweightWalletError::ConversionError("Storage not initialized".into()))?;
            
            let wallet_state = storage.load_wallet_state(wallet_id).await?;
            Ok(wallet_state.get_summary())
        })
    }

    fn __repr__(&self) -> PyResult<String> {
        let available = self.available()?;
        let pending = self.pending()?;
        let immature = self.immature()?;
        let total = self.total()?;
        
        Ok(format!(
            "TariBalance(running_balance={}, available={}, pending={}, immature={}, total={})",
            self.running_balance,
            available,
            pending,
            immature,
            total
        ))
    }
}
