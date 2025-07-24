//! UTXO management wrapper exposing existing StoredOutput functionality
//!
//! This module provides Python-friendly interfaces to the existing UTXO extraction 
//! and storage functionality, wrapping existing StoredOutput structures and exposing
//! existing filtering capabilities.

use pyo3::prelude::*;
use pyo3::types::PyList;
use std::sync::{Arc, Mutex};

use lightweight_wallet_libs::storage::{
    WalletStorage,
    storage_trait::{OutputFilter, OutputStatus}
};
use crate::runtime::execute_async;

/// Python wrapper for UTXO management
#[pyclass]
pub struct TariUTXOManager {
    storage: Arc<Mutex<Option<Box<dyn WalletStorage + Send + Sync>>>>,
}

/// Python wrapper for UTXO information
#[pyclass]
#[derive(Clone)]
pub struct UTXOInfo {
    #[pyo3(get)]
    pub id: Option<u32>,
    #[pyo3(get)]
    pub wallet_id: u32,
    #[pyo3(get)]
    pub commitment_hex: String,
    #[pyo3(get)]
    pub hash_hex: String,
    #[pyo3(get)]
    pub value: u64,
    #[pyo3(get)]
    pub spending_key_hex: String,
    #[pyo3(get)]
    pub script_private_key_hex: String,
    #[pyo3(get)]
    pub maturity: u64,
    #[pyo3(get)]
    pub script_lock_height: u64,
    #[pyo3(get)]
    pub status: u32,
    #[pyo3(get)]
    pub mined_height: Option<u64>,
    #[pyo3(get)]
    pub spent_in_tx_id: Option<u64>,
    #[pyo3(get)]
    pub minimum_value_promise: u64,
}

/// Python wrapper for UTXO filtering
#[pyclass]
#[derive(Clone, Default)]
pub struct UTXOFilter {
    #[pyo3(get, set)]
    pub wallet_id: Option<u32>,
    #[pyo3(get, set)]
    pub min_value: Option<u64>,
    #[pyo3(get, set)]
    pub max_value: Option<u64>,
    #[pyo3(get, set)]
    pub status: Option<u32>, // OutputStatus as u32
    #[pyo3(get, set)]
    pub mature_only: bool,
    #[pyo3(get, set)]
    pub spendable_at_height: Option<u64>,
    #[pyo3(get, set)]
    pub limit: Option<usize>,
    #[pyo3(get, set)]
    pub offset: Option<usize>,
}

/// UTXO list with summary information
#[pyclass]
pub struct UTXOList {
    #[pyo3(get)]
    pub utxos: Vec<UTXOInfo>,
    #[pyo3(get)]
    pub total_value: u64,
    #[pyo3(get)]
    pub mature_count: u64,
    #[pyo3(get)]
    pub immature_count: u64,
    #[pyo3(get)]
    pub spendable_count: u64,
}

#[pymethods]
impl TariUTXOManager {
    /// Create a new UTXO manager
    #[new]
    fn new() -> PyResult<Self> {
        Ok(TariUTXOManager {
            storage: Arc::new(Mutex::new(None)),
        })
    }

    /// Set the storage backend for UTXO operations
    /// 
    /// Args:
    ///     storage: TariWalletStorage instance
    fn set_storage(&self, _storage: &crate::TariWalletStorage) -> PyResult<()> {
        // This is a placeholder - in practice we'd need to extract the storage
        // from TariWalletStorage, but for now this provides the interface
        Ok(())
    }

    /// Get UTXOs with optional filtering
    /// 
    /// Args:
    ///     filter: UTXOFilter instance for filtering results
    /// 
    /// Returns:
    ///     UTXOList: List of UTXOs with summary information
    fn get_utxos(&self, filter: Option<UTXOFilter>) -> PyResult<UTXOList> {
        let storage_arc = Arc::clone(&self.storage);
        let filter_opts = filter.unwrap_or_default();
        
        execute_async(async move {
            let storage_guard = storage_arc.lock()
                .map_err(|_| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                        "Failed to lock storage".into()
                    )
                })?;
            
            let storage = storage_guard.as_ref()
                .ok_or_else(|| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                        "Storage not initialized - call set_storage() first".into()
                    )
                })?;

            // Convert Python filter to Rust OutputFilter
            let mut output_filter = OutputFilter::new();
            
            if let Some(wallet_id) = filter_opts.wallet_id {
                output_filter = output_filter.with_wallet_id(wallet_id);
            }
            
            if let Some(status) = filter_opts.status {
                output_filter = output_filter.with_status(OutputStatus::from(status));
            }
            
            if let Some(min_val) = filter_opts.min_value {
                if let Some(max_val) = filter_opts.max_value {
                    output_filter = output_filter.with_value_range(min_val, max_val);
                }
            }
            
            if let Some(height) = filter_opts.spendable_at_height {
                output_filter = output_filter.spendable_at(height);
            }
            
            if let Some(limit) = filter_opts.limit {
                output_filter = output_filter.with_limit(limit);
            }
            
            if let Some(offset) = filter_opts.offset {
                output_filter = output_filter.with_offset(offset);
            }

            // Get outputs from storage
            let outputs = storage.get_outputs(Some(output_filter)).await?;

            // Convert to Python-friendly format
            let mut utxos = Vec::new();
            let mut total_value = 0u64;
            let mut mature_count = 0u64;
            let mut immature_count = 0u64;
            let mut spendable_count = 0u64;

            for output in outputs {
                total_value += output.value;
                
                // Simple maturity check (would need current height in practice)
                if output.maturity == 0 || output.mined_height.is_some() {
                    mature_count += 1;
                } else {
                    immature_count += 1;
                }

                if output.is_spendable() {
                    spendable_count += 1;
                }

                let utxo_info = UTXOInfo {
                    id: output.id,
                    wallet_id: output.wallet_id,
                    commitment_hex: output.commitment_hex(),
                    hash_hex: output.hash_hex(),
                    value: output.value,
                    spending_key_hex: output.spending_key.clone(),
                    script_private_key_hex: output.script_private_key.clone(),
                    maturity: output.maturity,
                    script_lock_height: output.script_lock_height,
                    status: output.status,
                    mined_height: output.mined_height,
                    spent_in_tx_id: output.spent_in_tx_id,
                    minimum_value_promise: output.minimum_value_promise,
                };

                utxos.push(utxo_info);
            }

            let utxo_list = UTXOList {
                utxos,
                total_value,
                mature_count,
                immature_count,
                spendable_count,
            };

            Ok(utxo_list)
        })
    }

    /// Get unspent UTXOs for a specific wallet
    /// 
    /// Args:
    ///     wallet_id: int - Wallet ID to get UTXOs for
    /// 
    /// Returns:
    ///     UTXOList: List of unspent UTXOs
    fn get_unspent_utxos(&self, wallet_id: u32) -> PyResult<UTXOList> {
        let mut filter = UTXOFilter::default();
        filter.wallet_id = Some(wallet_id);
        filter.status = Some(OutputStatus::Unspent as u32);
        self.get_utxos(Some(filter))
    }

    /// Get spendable UTXOs for a wallet at a specific block height
    /// 
    /// Args:
    ///     wallet_id: int - Wallet ID
    ///     block_height: int - Current block height for maturity calculations
    /// 
    /// Returns:
    ///     UTXOList: List of spendable UTXOs
    fn get_spendable_utxos(&self, wallet_id: u32, block_height: u64) -> PyResult<UTXOList> {
        let storage_arc = Arc::clone(&self.storage);
        
        execute_async(async move {
            let storage_guard = storage_arc.lock()
                .map_err(|_| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                        "Failed to lock storage".into()
                    )
                })?;
            
            let storage = storage_guard.as_ref()
                .ok_or_else(|| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                        "Storage not initialized - call set_storage() first".into()
                    )
                })?;

            // Use existing storage method
            let outputs = storage.get_spendable_outputs(wallet_id, block_height).await?;

            // Convert to Python-friendly format with summary
            let mut utxos = Vec::new();
            let mut total_value = 0u64;

            for output in outputs {
                total_value += output.value;

                let utxo_info = UTXOInfo {
                    id: output.id,
                    wallet_id: output.wallet_id,
                    commitment_hex: output.commitment_hex(),
                    hash_hex: output.hash_hex(),
                    value: output.value,
                    spending_key_hex: output.spending_key.clone(),
                    script_private_key_hex: output.script_private_key.clone(),
                    maturity: output.maturity,
                    script_lock_height: output.script_lock_height,
                    status: output.status,
                    mined_height: output.mined_height,
                    spent_in_tx_id: output.spent_in_tx_id,
                    minimum_value_promise: output.minimum_value_promise,
                };

                utxos.push(utxo_info);
            }

            let utxo_count = utxos.len() as u64;
            let utxo_list = UTXOList {
                utxos,
                total_value,
                mature_count: utxo_count,  // All spendable UTXOs are mature
                immature_count: 0,
                spendable_count: utxo_count,
            };

            Ok(utxo_list)
        })
    }

    /// Get spendable balance for a wallet at a specific block height
    /// 
    /// Args:
    ///     wallet_id: int - Wallet ID
    ///     block_height: int - Current block height for maturity calculations
    /// 
    /// Returns:
    ///     int: Total spendable balance in microMinotari
    fn get_spendable_balance(&self, wallet_id: u32, block_height: u64) -> PyResult<u64> {
        let storage_arc = Arc::clone(&self.storage);
        
        execute_async(async move {
            let storage_guard = storage_arc.lock()
                .map_err(|_| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                        "Failed to lock storage".into()
                    )
                })?;
            
            let storage = storage_guard.as_ref()
                .ok_or_else(|| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                        "Storage not initialized - call set_storage() first".into()
                    )
                })?;

            // Use existing storage method
            let balance = storage.get_spendable_balance(wallet_id, block_height).await?;

            Ok(balance)
        })
    }

    /// String representation
    fn __str__(&self) -> String {
        "TariUTXOManager".to_string()
    }

    /// Representation
    fn __repr__(&self) -> String {
        self.__str__()
    }
}

#[pymethods]
impl UTXOFilter {
    /// Create a new UTXO filter
    #[new]
    fn new() -> Self {
        Self::default()
    }

    /// Set wallet ID filter
    fn with_wallet_id(&mut self, wallet_id: u32) -> Self {
        self.wallet_id = Some(wallet_id);
        self.clone()
    }

    /// Set value range filter
    fn with_value_range(&mut self, min_value: u64, max_value: u64) -> Self {
        self.min_value = Some(min_value);
        self.max_value = Some(max_value);
        self.clone()
    }

    /// Set status filter (0=Unspent, 1=Spent, 2=Locked, 3=Frozen)
    fn with_status(&mut self, status: u32) -> Self {
        self.status = Some(status);
        self.clone()
    }

    /// Filter for outputs spendable at given block height
    fn spendable_at(&mut self, block_height: u64) -> Self {
        self.spendable_at_height = Some(block_height);
        self.clone()
    }

    /// Set pagination limit
    fn with_limit(&mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self.clone()
    }

    /// Set pagination offset
    fn with_offset(&mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self.clone()
    }

    /// String representation
    fn __str__(&self) -> String {
        format!("UTXOFilter(wallet_id={:?}, status={:?}, value_range={:?}-{:?})", 
                self.wallet_id, self.status, self.min_value, self.max_value)
    }
}

#[pymethods]
impl UTXOInfo {
    /// Check if this UTXO can be spent at the given block height
    fn can_spend_at_height(&self, block_height: u64) -> bool {
        self.status == (OutputStatus::Unspent as u32)
            && self.spent_in_tx_id.is_none()
            && self.mined_height.is_some()
            && block_height >= self.maturity
            && block_height >= self.script_lock_height
    }

    /// Check if this UTXO is currently spendable (assuming current tip)
    fn is_spendable(&self) -> bool {
        self.status == (OutputStatus::Unspent as u32)
            && self.spent_in_tx_id.is_none()
            && self.mined_height.is_some()
    }

    /// String representation
    fn __str__(&self) -> String {
        format!("UTXOInfo(id={:?}, value={}, status={})", 
                self.id, self.value, self.status)
    }
}

#[pymethods]
impl UTXOList {
    /// Get total count of UTXOs
    fn count(&self) -> usize {
        self.utxos.len()
    }

    /// Get UTXOs as Python list
    fn to_list(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let list = PyList::empty(py);
            for utxo in &self.utxos {
                list.append(utxo.clone())?;
            }
            Ok(list.into())
        })
    }

    /// String representation
    fn __str__(&self) -> String {
        format!("UTXOList(count={}, total_value={}, spendable={})", 
                self.utxos.len(), self.total_value, self.spendable_count)
    }
}
