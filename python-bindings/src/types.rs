//! Python type definitions for wallet data structures

use pyo3::prelude::*;
use lightweight_wallet_libs::data_structures::wallet_transaction::WalletTransaction as RustWalletTransaction;

/// Python wrapper for WalletTransaction
#[pyclass]
#[derive(Clone)]
pub struct WalletTransaction {
    inner: RustWalletTransaction,
}

#[pymethods]
impl WalletTransaction {
    /// Get the transaction hash as hex string
    #[getter]
    fn hash(&self) -> String {
        // Note: This is a simplified implementation
        // In the real implementation, you'd extract the actual transaction hash
        format!("tx_{}", self.inner.commitment_hex())
    }
    
    /// Get the commitment as hex string
    #[getter]
    fn commitment(&self) -> String {
        self.inner.commitment_hex()
    }
    
    /// Get the amount in micro Tari
    #[getter]
    fn amount(&self) -> u64 {
        self.inner.value
    }
    
    /// Get the maturity height (for coinbase transactions)
    #[getter]
    fn maturity_height(&self) -> u64 {
        // For non-coinbase transactions, return 0 (immediately mature)
        if self.inner.is_coinbase() {
            // Simplified: add 1000 blocks for coinbase maturity
            self.inner.block_height + 1000
        } else {
            self.inner.block_height
        }
    }
    
    /// Get the block height where this transaction was found
    #[getter]
    fn height(&self) -> u64 {
        self.inner.block_height
    }
    
    /// Check if this is a coinbase transaction
    #[getter]
    fn is_coinbase(&self) -> bool {
        self.inner.is_coinbase()
    }
    
    /// Check if this transaction is mature (spendable)
    fn is_mature(&self, current_height: u64) -> bool {
        current_height >= self.maturity_height()
    }
    
    /// String representation
    fn __repr__(&self) -> String {
        format!(
            "WalletTransaction(amount={}, height={}, maturity={}, coinbase={})",
            self.amount(),
            self.height(),
            self.maturity_height(),
            self.is_coinbase()
        )
    }
    
    /// String representation
    fn __str__(&self) -> String {
        self.__repr__()
    }
}

impl From<RustWalletTransaction> for WalletTransaction {
    fn from(inner: RustWalletTransaction) -> Self {
        Self { inner }
    }
}

impl From<WalletTransaction> for RustWalletTransaction {
    fn from(wrapper: WalletTransaction) -> Self {
        wrapper.inner
    }
}
