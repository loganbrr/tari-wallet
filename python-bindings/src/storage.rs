//! PyO3 storage wrapper exposing existing SQLite storage operations
//!
//! This module provides Python-friendly interfaces to the existing SQLite storage backend,
//! implementing proper connection lifecycle management and exposing existing wallet 
//! lifecycle methods, transaction persistence, and UTXO management.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use lightweight_wallet_libs::storage::{
    WalletStorage,
    sqlite::SqliteStorage,
    storage_trait::{StoredWallet, TransactionFilter, StoredOutput, OutputFilter, OutputStatus},
};
use lightweight_wallet_libs::data_structures::{
    types::{PrivateKey, CompressedCommitment},
    wallet_transaction::WalletTransaction,
    transaction::{TransactionDirection, TransactionStatus},
    payment_id::PaymentId,
};
use crate::runtime::execute_async;

/// PyO3 wrapper for SQLite storage backend
#[pyclass]
pub struct TariWalletStorage {
    inner: Arc<Mutex<Option<SqliteStorage>>>,
    path: Option<PathBuf>,
}

#[pymethods]
impl TariWalletStorage {
    /// Create a new storage instance with file path
    /// 
    /// Args:
    ///     path: Path to SQLite database file, or None for in-memory database
    #[new]
    #[pyo3(signature = (path=None))]
    fn new(path: Option<String>) -> PyResult<Self> {
        Ok(TariWalletStorage {
            inner: Arc::new(Mutex::new(None)),
            path: path.map(PathBuf::from),
        })
    }

    /// Initialize storage connection (call this before using storage)
    fn initialize(&self) -> PyResult<()> {
        let storage_arc = Arc::clone(&self.inner);
        let path = self.path.clone();
        
        execute_async(async move {
            // Create storage instance
            let storage = if let Some(db_path) = path {
                SqliteStorage::new(db_path).await?
            } else {
                SqliteStorage::new_in_memory().await?
            };

            // Initialize database schema
            storage.initialize().await?;

            // Store the initialized storage
            {
                let mut storage_guard = storage_arc.lock()
                    .map_err(|_| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                            "Failed to lock storage".into()
                        )
                    })?;
                *storage_guard = Some(storage);
            }

            Ok(())
        })
    }

    /// Close storage connection
    fn close(&self) -> PyResult<()> {
        let storage_arc = Arc::clone(&self.inner);
        
        execute_async(async move {
            let mut storage_guard = storage_arc.lock()
                .map_err(|_| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                        "Failed to lock storage".into()
                    )
                })?;

            if let Some(storage) = storage_guard.take() {
                storage.close().await?;
            }

            Ok(())
        })
    }

    // === Wallet Management Methods ===

    /// Save a wallet to storage (create or update)
    /// 
    /// Args:
    ///     wallet_data: Dictionary with wallet information
    ///         - name: str (required) - User-friendly wallet name
    ///         - seed_phrase: str (optional) - Encrypted seed phrase
    ///         - view_key_hex: str (required) - Private view key in hex
    ///         - spend_key_hex: str (optional) - Private spend key in hex
    ///         - birthday_block: int (required) - Wallet birthday block height
    /// 
    /// Returns:
    ///     int: Wallet ID assigned by storage
    fn save_wallet(&self, wallet_data: &Bound<'_, PyDict>) -> PyResult<u32> {
        let storage_arc = Arc::clone(&self.inner);
        
        // Extract data from dictionary
        let name = match wallet_data.get_item("name")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: name")),
        };
        
        let seed_phrase = match wallet_data.get_item("seed_phrase")? {
            Some(v) => Some(v.extract::<String>()?),
            None => None,
        };
        
        let view_key_hex = match wallet_data.get_item("view_key_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: view_key_hex")),
        };
        
        let spend_key_hex = match wallet_data.get_item("spend_key_hex")? {
            Some(v) => Some(v.extract::<String>()?),
            None => None,
        };
        
        let birthday_block = match wallet_data.get_item("birthday_block")? {
            Some(v) => v.extract::<u64>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: birthday_block")),
        };

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
                        "Storage not initialized - call initialize() first".into()
                    )
                })?;

            // Create StoredWallet from data
            let stored_wallet = if let Some(seed) = seed_phrase {
                // Parse keys from hex
                let view_key_bytes = hex::decode(&view_key_hex)
                    .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                        format!("Invalid view key hex: {}", e)
                    ))?;
                let spend_key_bytes = if let Some(ref spend_hex) = spend_key_hex {
                    hex::decode(spend_hex)
                        .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                            format!("Invalid spend key hex: {}", e)
                        ))?
                } else {
                    return Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
                        argument: "spend_key_hex".into(),
                        value: "None".into(),
                        message: "spend_key_hex required when seed_phrase provided".into()
                    });
                };

                if view_key_bytes.len() != 32 {
                    return Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
                        argument: "view_key_hex".into(),
                        value: format!("{} bytes", view_key_bytes.len()),
                        message: "view_key must be 32 bytes".into()
                    });
                }
                if spend_key_bytes.len() != 32 {
                    return Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
                        argument: "spend_key_hex".into(),
                        value: format!("{} bytes", spend_key_bytes.len()),
                        message: "spend_key must be 32 bytes".into()
                    });
                }

                let mut view_key = [0u8; 32];
                let mut spend_key = [0u8; 32];
                view_key.copy_from_slice(&view_key_bytes);
                spend_key.copy_from_slice(&spend_key_bytes);

                StoredWallet::from_seed_phrase(
                    name,
                    seed,
                    PrivateKey::new(view_key),
                    PrivateKey::new(spend_key),
                    birthday_block,
                )
            } else if let Some(spend_hex) = spend_key_hex {
                // Keys-only wallet
                let view_key_bytes = hex::decode(&view_key_hex)
                    .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                        format!("Invalid view key hex: {}", e)
                    ))?;
                let spend_key_bytes = hex::decode(&spend_hex)
                    .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                        format!("Invalid spend key hex: {}", e)
                    ))?;

                if view_key_bytes.len() != 32 || spend_key_bytes.len() != 32 {
                    return Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
                        argument: "keys".into(),
                        value: format!("view:{}, spend:{}", view_key_bytes.len(), spend_key_bytes.len()),
                        message: "Both view_key and spend_key must be 32 bytes".into()
                    });
                }

                let mut view_key = [0u8; 32];
                let mut spend_key = [0u8; 32];
                view_key.copy_from_slice(&view_key_bytes);
                spend_key.copy_from_slice(&spend_key_bytes);

                StoredWallet::from_keys(
                    name,
                    PrivateKey::new(view_key),
                    PrivateKey::new(spend_key),
                    birthday_block,
                )
            } else {
                // View-only wallet
                let view_key_bytes = hex::decode(&view_key_hex)
                    .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                        format!("Invalid view key hex: {}", e)
                    ))?;

                if view_key_bytes.len() != 32 {
                    return Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
                        argument: "view_key_hex".into(),
                        value: format!("{} bytes", view_key_bytes.len()),
                        message: "view_key must be 32 bytes".into()
                    });
                }

                let mut view_key = [0u8; 32];
                view_key.copy_from_slice(&view_key_bytes);

                StoredWallet::view_only(name, PrivateKey::new(view_key), birthday_block)
            };

            // Validate wallet
            stored_wallet.validate()
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Wallet validation failed: {}", e)
                ))?;

            // Save to storage
            let wallet_id = storage.save_wallet(&stored_wallet).await?;

            Ok(wallet_id)
        })
    }

    /// Get a wallet by ID
    /// 
    /// Args:
    ///     wallet_id: int - Wallet ID to retrieve
    /// 
    /// Returns:
    ///     dict or None: Wallet data or None if not found
    fn get_wallet_by_id(&self, wallet_id: u32) -> PyResult<Option<PyObject>> {
        let storage_arc = Arc::clone(&self.inner);
        
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
                        "Storage not initialized - call initialize() first".into()
                    )
                })?;

            let wallet = storage.get_wallet_by_id(wallet_id).await?;

            let result = Python::with_gil(|py| {
                if let Some(w) = wallet {
                    let dict = PyDict::new(py);
                    dict.set_item("id", w.id)?;
                    dict.set_item("name", &w.name)?;
                    dict.set_item("seed_phrase", &w.seed_phrase)?;
                    dict.set_item("view_key_hex", &w.view_key_hex)?;
                    dict.set_item("spend_key_hex", &w.spend_key_hex)?;
                    dict.set_item("birthday_block", w.birthday_block)?;
                    dict.set_item("latest_scanned_block", w.latest_scanned_block)?;
                    dict.set_item("created_at", &w.created_at)?;
                    dict.set_item("updated_at", &w.updated_at)?;
                    Ok(Some(dict.into()))
                } else {
                    Ok(None)
                }
            }).map_err(|e: PyErr| {
                lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Failed to convert wallet to Python dict: {}", e)
                )
            })?;

            Ok(result)
        })
    }

    /// Get a wallet by name
    /// 
    /// Args:
    ///     name: str - Wallet name to retrieve
    /// 
    /// Returns:
    ///     dict or None: Wallet data or None if not found
    fn get_wallet_by_name(&self, name: String) -> PyResult<Option<PyObject>> {
        let storage_arc = Arc::clone(&self.inner);
        
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
                        "Storage not initialized - call initialize() first".into()
                    )
                })?;

            let wallet = storage.get_wallet_by_name(&name).await?;

            let result = Python::with_gil(|py| {
                if let Some(w) = wallet {
                    let dict = PyDict::new(py);
                    dict.set_item("id", w.id)?;
                    dict.set_item("name", &w.name)?;
                    dict.set_item("seed_phrase", &w.seed_phrase)?;
                    dict.set_item("view_key_hex", &w.view_key_hex)?;
                    dict.set_item("spend_key_hex", &w.spend_key_hex)?;
                    dict.set_item("birthday_block", w.birthday_block)?;
                    dict.set_item("latest_scanned_block", w.latest_scanned_block)?;
                    dict.set_item("created_at", &w.created_at)?;
                    dict.set_item("updated_at", &w.updated_at)?;
                    Ok(Some(dict.into()))
                } else {
                    Ok(None)
                }
            }).map_err(|e: PyErr| {
                lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Failed to convert wallet to Python dict: {}", e)
                )
            })?;

            Ok(result)
        })
    }

    /// List all wallets
    /// 
    /// Returns:
    ///     list: List of wallet dictionaries
    fn list_wallets(&self) -> PyResult<PyObject> {
        let storage_arc = Arc::clone(&self.inner);
        
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
                        "Storage not initialized - call initialize() first".into()
                    )
                })?;

            let wallets = storage.list_wallets().await?;

            let result = Python::with_gil(|py| {
                let list = PyList::empty(py);
                for w in wallets {
                    let dict = PyDict::new(py);
                    dict.set_item("id", w.id)?;
                    dict.set_item("name", &w.name)?;
                    dict.set_item("seed_phrase", &w.seed_phrase)?;
                    dict.set_item("view_key_hex", &w.view_key_hex)?;
                    dict.set_item("spend_key_hex", &w.spend_key_hex)?;
                    dict.set_item("birthday_block", w.birthday_block)?;
                    dict.set_item("latest_scanned_block", w.latest_scanned_block)?;
                    dict.set_item("created_at", &w.created_at)?;
                    dict.set_item("updated_at", &w.updated_at)?;
                    list.append(dict)?;
                }
                Ok(list.into())
            }).map_err(|e: PyErr| {
                lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Failed to convert wallets to Python list: {}", e)
                )
            })?;

            Ok(result)
        })
    }

    /// Delete a wallet and all its transactions
    /// 
    /// Args:
    ///     wallet_id: int - Wallet ID to delete
    /// 
    /// Returns:
    ///     bool: True if wallet was deleted, False if not found
    fn delete_wallet(&self, wallet_id: u32) -> PyResult<bool> {
        let storage_arc = Arc::clone(&self.inner);
        
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
                        "Storage not initialized - call initialize() first".into()
                    )
                })?;

            let deleted = storage.delete_wallet(wallet_id).await?;

            Ok(deleted)
        })
    }

    /// Check if a wallet name exists
    /// 
    /// Args:
    ///     name: str - Wallet name to check
    /// 
    /// Returns:
    ///     bool: True if name exists, False otherwise
    fn wallet_name_exists(&self, name: String) -> PyResult<bool> {
        let storage_arc = Arc::clone(&self.inner);
        
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
                        "Storage not initialized - call initialize() first".into()
                    )
                })?;

            let exists = storage.wallet_name_exists(&name).await?;

            Ok(exists)
        })
    }

    // === Transaction Management Methods ===

    /// Save a transaction to storage
    /// 
    /// Args:
    ///     wallet_id: int - ID of wallet this transaction belongs to
    ///     tx_data: dict - Transaction data with fields:
    ///         - block_height: int - Block height where transaction was found
    ///         - output_index: int or None - Output index if received output
    ///         - input_index: int or None - Input index if spent input
    ///         - commitment_hex: str - Transaction commitment as hex string
    ///         - output_hash_hex: str or None - Output hash as hex string  
    ///         - value: int - Value in microMinotari
    ///         - payment_id: dict - Payment ID data (type, value fields)
    ///         - transaction_status: str - "mined", "unconfirmed", "coinbase", etc.
    ///         - transaction_direction: str - "inbound" or "outbound"
    ///         - is_mature: bool - Whether transaction is mature
    /// 
    /// Returns:
    ///     None
    fn save_transaction(&self, wallet_id: u32, tx_data: &Bound<'_, PyDict>) -> PyResult<()> {
        let storage_arc = Arc::clone(&self.inner);
        
        // Extract transaction data from dictionary
        let block_height = match tx_data.get_item("block_height")? {
            Some(v) => v.extract::<u64>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: block_height")),
        };
        
        let output_index = match tx_data.get_item("output_index")? {
            Some(v) if !v.is_none() => Some(v.extract::<usize>()?),
            _ => None,
        };
        
        let input_index = match tx_data.get_item("input_index")? {
            Some(v) if !v.is_none() => Some(v.extract::<usize>()?),
            _ => None,
        };
        
        let commitment_hex = match tx_data.get_item("commitment_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: commitment_hex")),
        };
        
        let output_hash_hex = match tx_data.get_item("output_hash_hex")? {
            Some(v) if !v.is_none() => Some(v.extract::<String>()?),
            _ => None,
        };
        
        let value = match tx_data.get_item("value")? {
            Some(v) => v.extract::<u64>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: value")),
        };
        
        let _payment_id_data = match tx_data.get_item("payment_id")? {
            Some(_v) => {}, // Ignore for now, using Empty
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: payment_id")),
        };
        
        let transaction_status_str = match tx_data.get_item("transaction_status")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: transaction_status")),
        };
        
        let transaction_direction_str = match tx_data.get_item("transaction_direction")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: transaction_direction")),
        };
        
        let is_mature = match tx_data.get_item("is_mature")? {
            Some(v) => v.extract::<bool>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: is_mature")),
        };

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
                        "Storage not initialized - call initialize() first".into()
                    )
                })?;

            // Parse commitment from hex
            let commitment_bytes = hex::decode(&commitment_hex)
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Invalid commitment hex: {}", e)
                ))?;
            
            if commitment_bytes.len() != 32 {
                return Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
                    argument: "commitment_hex".into(),
                    value: format!("{} bytes", commitment_bytes.len()),
                    message: "commitment must be 32 bytes".into()
                });
            }
            
            let mut commitment_array = [0u8; 32];
            commitment_array.copy_from_slice(&commitment_bytes);
            let commitment = CompressedCommitment::new(commitment_array);

            // Parse output hash if provided
            let output_hash = if let Some(hash_hex) = output_hash_hex {
                Some(hex::decode(&hash_hex)
                    .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                        format!("Invalid output hash hex: {}", e)
                    ))?)
            } else {
                None
            };

            // Parse payment ID (simplified - assume Empty for now)
            let payment_id = PaymentId::Empty;

            // Parse transaction status
            let transaction_status = match transaction_status_str.as_str() {
                "minedconfirmed" => TransactionStatus::MinedConfirmed,
                "minedunconfirmed" => TransactionStatus::MinedUnconfirmed,
                "coinbase" => TransactionStatus::Coinbase,
                "rejected" => TransactionStatus::Rejected,
                "broadcast" => TransactionStatus::Broadcast,
                "pending" => TransactionStatus::Pending,
                _ => return Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
                    argument: "transaction_status".into(),
                    value: transaction_status_str,
                    message: "Invalid transaction status. Must be one of: minedconfirmed, minedunconfirmed, coinbase, rejected, broadcast, pending".into()
                }),
            };

            // Parse transaction direction
            let transaction_direction = match transaction_direction_str.as_str() {
                "inbound" => TransactionDirection::Inbound,
                "outbound" => TransactionDirection::Outbound,
                _ => return Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
                    argument: "transaction_direction".into(),
                    value: transaction_direction_str,
                    message: "Invalid transaction direction. Must be 'inbound' or 'outbound'".into()
                }),
            };

            // Create WalletTransaction
            let wallet_transaction = WalletTransaction::new(
                block_height,
                output_index,
                input_index,
                commitment,
                output_hash,
                value,
                payment_id,
                transaction_status,
                transaction_direction,
                is_mature,
            );

            // Save to storage
            storage.save_transaction(wallet_id, &wallet_transaction).await?;

            Ok(())
        })
    }

    /// Get transactions for a wallet with optional filtering
    /// 
    /// Args:
    ///     wallet_id: int or None - Wallet ID to filter by (None for all wallets)
    ///     filter_data: dict or None - Optional filter parameters:
    ///         - block_height_range: tuple (from, to) - Block height range
    ///         - direction: str - "inbound" or "outbound"
    ///         - status: str - Transaction status to filter by
    ///         - is_spent: bool - Filter by spent status
    ///         - is_mature: bool - Filter by maturity status
    ///         - limit: int - Maximum number of results
    ///         - offset: int - Pagination offset
    /// 
    /// Returns:
    ///     list: List of transaction dictionaries
    fn get_transactions(&self, wallet_id: Option<u32>, filter_data: Option<&Bound<'_, PyDict>>) -> PyResult<PyObject> {
        let storage_arc = Arc::clone(&self.inner);
        
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
                        "Storage not initialized - call initialize() first".into()
                    )
                })?;

            // Build filter
            let mut filter = TransactionFilter::new();
            
            if let Some(wid) = wallet_id {
                filter = filter.with_wallet_id(wid);
            }
            
            if let Some(filter_dict) = filter_data {
                // Parse filter parameters if provided (handle errors properly)
                if let Some(range_val) = filter_dict.get_item("block_height_range").map_err(|e| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Filter error: {}", e))
                })? {
                    let range_tuple: (u64, u64) = range_val.extract().map_err(|e| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Range extraction error: {}", e))
                    })?;
                    filter = filter.with_block_range(range_tuple.0, range_tuple.1);
                }
                
                if let Some(direction_val) = filter_dict.get_item("direction").map_err(|e| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Filter error: {}", e))
                })? {
                    let direction_str: String = direction_val.extract().map_err(|e| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Direction extraction error: {}", e))
                    })?;
                    let direction = match direction_str.as_str() {
                        "inbound" => TransactionDirection::Inbound,
                        "outbound" => TransactionDirection::Outbound,
                        _ => return Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
                            argument: "direction".into(),
                            value: direction_str,
                            message: "Invalid direction. Must be 'inbound' or 'outbound'".into()
                        }),
                    };
                    filter = filter.with_direction(direction);
                }
                
                if let Some(status_val) = filter_dict.get_item("status").map_err(|e| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Filter error: {}", e))
                })? {
                    let status_str: String = status_val.extract().map_err(|e| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Status extraction error: {}", e))
                    })?;
                    let status = match status_str.as_str() {
                        "minedconfirmed" => TransactionStatus::MinedConfirmed,
                        "minedunconfirmed" => TransactionStatus::MinedUnconfirmed,
                        "coinbase" => TransactionStatus::Coinbase,
                        "rejected" => TransactionStatus::Rejected,
                        "broadcast" => TransactionStatus::Broadcast,
                        "pending" => TransactionStatus::Pending,
                        _ => return Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
                            argument: "status".into(),
                            value: status_str,
                            message: "Invalid status. Must be one of: minedconfirmed, minedunconfirmed, coinbase, rejected, broadcast, pending".into()
                        }),
                    };
                    filter = filter.with_status(status);
                }
                
                if let Some(spent_val) = filter_dict.get_item("is_spent").map_err(|e| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Filter error: {}", e))
                })? {
                    let is_spent: bool = spent_val.extract().map_err(|e| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Boolean extraction error: {}", e))
                    })?;
                    filter = filter.with_spent_status(is_spent);
                }
                
                if let Some(mature_val) = filter_dict.get_item("is_mature").map_err(|e| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Filter error: {}", e))
                })? {
                    let is_mature: bool = mature_val.extract().map_err(|e| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Boolean extraction error: {}", e))
                    })?;
                    filter = filter.with_maturity(is_mature);
                }
                
                if let Some(limit_val) = filter_dict.get_item("limit").map_err(|e| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Filter error: {}", e))
                })? {
                    let limit: usize = limit_val.extract().map_err(|e| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Integer extraction error: {}", e))
                    })?;
                    filter = filter.with_limit(limit);
                }
                
                if let Some(offset_val) = filter_dict.get_item("offset").map_err(|e| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Filter error: {}", e))
                })? {
                    let offset: usize = offset_val.extract().map_err(|e| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Integer extraction error: {}", e))
                    })?;
                    filter = filter.with_offset(offset);
                }
            }

            // Get transactions from storage
            let transactions = storage.get_transactions(Some(filter)).await?;

            // Convert to Python objects
            let result = Python::with_gil(|py| {
                let list = PyList::empty(py);
                for tx in transactions {
                    let dict = PyDict::new(py);
                    dict.set_item("block_height", tx.block_height)?;
                    dict.set_item("output_index", tx.output_index)?;
                    dict.set_item("input_index", tx.input_index)?;
                    dict.set_item("commitment_hex", tx.commitment_hex())?;
                    dict.set_item("output_hash_hex", tx.output_hash.as_ref().map(|h| hex::encode(h)))?;
                    dict.set_item("value", tx.value)?;
                    dict.set_item("payment_id", format!("{:?}", tx.payment_id))?; // Simplified for now
                    dict.set_item("is_spent", tx.is_spent)?;
                    dict.set_item("spent_in_block", tx.spent_in_block)?;
                    dict.set_item("spent_in_input", tx.spent_in_input)?;
                    dict.set_item("transaction_status", format!("{:?}", tx.transaction_status).to_lowercase())?;
                    dict.set_item("transaction_direction", format!("{:?}", tx.transaction_direction).to_lowercase())?;
                    dict.set_item("is_mature", tx.is_mature)?;
                    list.append(dict)?;
                }
                Ok(list.into())
            }).map_err(|e: PyErr| {
                lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Failed to convert transactions to Python list: {}", e)
                )
            })?;

            Ok(result)
        })
    }

    /// Mark a transaction as spent by commitment
    /// 
    /// Args:
    ///     commitment_hex: str - Transaction commitment as hex string
    ///     spent_in_block: int - Block height where spent
    ///     spent_in_input: int - Input index where spent
    /// 
    /// Returns:
    ///     bool: True if transaction was found and marked as spent
    fn mark_transaction_spent(&self, commitment_hex: String, spent_in_block: u64, spent_in_input: usize) -> PyResult<bool> {
        let storage_arc = Arc::clone(&self.inner);
        
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
                        "Storage not initialized - call initialize() first".into()
                    )
                })?;

            // Parse commitment from hex
            let commitment_bytes = hex::decode(&commitment_hex)
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Invalid commitment hex: {}", e)
                ))?;
            
            if commitment_bytes.len() != 32 {
                return Err(lightweight_wallet_libs::errors::LightweightWalletError::InvalidArgument {
                    argument: "commitment_hex".into(),
                    value: format!("{} bytes", commitment_bytes.len()),
                    message: "commitment must be 32 bytes".into()
                });
            }
            
            let mut commitment_array = [0u8; 32];
            commitment_array.copy_from_slice(&commitment_bytes);
            let commitment = CompressedCommitment::new(commitment_array);

            // Mark as spent
            let marked = storage.mark_transaction_spent(&commitment, spent_in_block, spent_in_input).await?;

            Ok(marked)
        })
    }

    /// Load wallet state for a wallet (all transactions and balance)
    /// 
    /// Args:
    ///     wallet_id: int - Wallet ID to load state for
    /// 
    /// Returns:
    ///     dict: Wallet state with balance and transaction information
    fn load_wallet_state(&self, wallet_id: u32) -> PyResult<PyObject> {
        let storage_arc = Arc::clone(&self.inner);
        
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
                        "Storage not initialized - call initialize() first".into()
                    )
                })?;

            // Load wallet state
            let wallet_state = storage.load_wallet_state(wallet_id).await?;

            // Convert to Python dict
            let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
            let result = Python::with_gil(|py| {
                let dict = PyDict::new(py);
                dict.set_item("balance", balance)?;
                dict.set_item("total_received", total_received)?;
                dict.set_item("total_spent", total_spent)?;
                dict.set_item("unspent_count", unspent_count)?;
                dict.set_item("spent_count", spent_count)?;
                dict.set_item("total_transactions", wallet_state.transactions.len())?;
                
                // Convert transactions to list
                let tx_list = PyList::empty(py);
                for tx in wallet_state.transactions {
                    let tx_dict = PyDict::new(py);
                    tx_dict.set_item("block_height", tx.block_height)?;
                    tx_dict.set_item("commitment_hex", tx.commitment_hex())?;
                    tx_dict.set_item("value", tx.value)?;
                    tx_dict.set_item("is_spent", tx.is_spent)?;
                    tx_dict.set_item("transaction_direction", format!("{:?}", tx.transaction_direction).to_lowercase())?;
                    tx_dict.set_item("is_mature", tx.is_mature)?;
                    tx_list.append(tx_dict)?;
                }
                dict.set_item("transactions", tx_list)?;
                
                Ok(dict.into())
            }).map_err(|e: PyErr| {
                lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Failed to convert wallet state to Python dict: {}", e)
                )
            })?;

            Ok(result)
        })
    }

    // === UTXO Management Methods ===

    /// Save a UTXO output to storage
    /// 
    /// Args:
    ///     output_data: dict - Output data with required fields:
    ///         - wallet_id: int - Wallet ID this output belongs to
    ///         - commitment_hex: str - Output commitment as hex string
    ///         - hash_hex: str - Output hash as hex string
    ///         - value: int - Output value in microMinotari
    ///         - spending_key_hex: str - Private key to spend this output
    ///         - script_private_key_hex: str - Private key for script execution
    ///         - script_hex: str - Script that governs spending (as hex)
    ///         - input_data_hex: str - Execution stack data (as hex)
    ///         - covenant_hex: str - Covenant restrictions (as hex)
    ///         - output_type: int - Output type (0=Payment, 1=Coinbase, etc.)
    ///         - features_json: str - Serialized output features as JSON
    ///         - maturity: int - Block height when spendable
    ///         - script_lock_height: int - Script lock height
    ///         - sender_offset_public_key_hex: str - Sender offset public key (hex)
    ///         - metadata_signature_ephemeral_commitment_hex: str - Ephemeral commitment (hex)
    ///         - metadata_signature_ephemeral_pubkey_hex: str - Ephemeral public key (hex)
    ///         - metadata_signature_u_a_hex: str - Signature component u_a (hex)
    ///         - metadata_signature_u_x_hex: str - Signature component u_x (hex)
    ///         - metadata_signature_u_y_hex: str - Signature component u_y (hex)
    ///         - encrypted_data_hex: str - Encrypted payment information (hex)
    ///         - minimum_value_promise: int - Minimum value promise
    ///         - rangeproof_hex: str or None - Range proof bytes (hex, optional)
    ///         - status: int - Output status (0=Unspent, 1=Spent, etc.)
    ///         - mined_height: int or None - Block height when mined
    /// 
    /// Returns:
    ///     int: Output ID assigned by storage
    fn save_output(&self, output_data: &Bound<'_, PyDict>) -> PyResult<u32> {
        let storage_arc = Arc::clone(&self.inner);
        
        // Extract required fields from dictionary
        let wallet_id = match output_data.get_item("wallet_id")? {
            Some(v) => v.extract::<u32>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: wallet_id")),
        };
        
        let commitment_hex = match output_data.get_item("commitment_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: commitment_hex")),
        };
        
        let hash_hex = match output_data.get_item("hash_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: hash_hex")),
        };
        
        let value = match output_data.get_item("value")? {
            Some(v) => v.extract::<u64>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: value")),
        };
        
        let spending_key_hex = match output_data.get_item("spending_key_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: spending_key_hex")),
        };
        
        let script_private_key_hex = match output_data.get_item("script_private_key_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: script_private_key_hex")),
        };

        let script_hex = match output_data.get_item("script_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: script_hex")),
        };

        let input_data_hex = match output_data.get_item("input_data_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: input_data_hex")),
        };

        let covenant_hex = match output_data.get_item("covenant_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: covenant_hex")),
        };

        let output_type = match output_data.get_item("output_type")? {
            Some(v) => v.extract::<u32>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: output_type")),
        };

        let features_json = match output_data.get_item("features_json")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: features_json")),
        };

        let maturity = match output_data.get_item("maturity")? {
            Some(v) => v.extract::<u64>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: maturity")),
        };

        let script_lock_height = match output_data.get_item("script_lock_height")? {
            Some(v) => v.extract::<u64>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: script_lock_height")),
        };

        // Extract metadata signature components
        let sender_offset_public_key_hex = match output_data.get_item("sender_offset_public_key_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: sender_offset_public_key_hex")),
        };

        let metadata_signature_ephemeral_commitment_hex = match output_data.get_item("metadata_signature_ephemeral_commitment_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: metadata_signature_ephemeral_commitment_hex")),
        };

        let metadata_signature_ephemeral_pubkey_hex = match output_data.get_item("metadata_signature_ephemeral_pubkey_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: metadata_signature_ephemeral_pubkey_hex")),
        };

        let metadata_signature_u_a_hex = match output_data.get_item("metadata_signature_u_a_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: metadata_signature_u_a_hex")),
        };

        let metadata_signature_u_x_hex = match output_data.get_item("metadata_signature_u_x_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: metadata_signature_u_x_hex")),
        };

        let metadata_signature_u_y_hex = match output_data.get_item("metadata_signature_u_y_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: metadata_signature_u_y_hex")),
        };

        let encrypted_data_hex = match output_data.get_item("encrypted_data_hex")? {
            Some(v) => v.extract::<String>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: encrypted_data_hex")),
        };

        let minimum_value_promise = match output_data.get_item("minimum_value_promise")? {
            Some(v) => v.extract::<u64>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: minimum_value_promise")),
        };

        let rangeproof_hex = match output_data.get_item("rangeproof_hex")? {
            Some(v) if !v.is_none() => Some(v.extract::<String>()?),
            _ => None,
        };

        let status = match output_data.get_item("status")? {
            Some(v) => v.extract::<u32>()?,
            None => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing required field: status")),
        };

        let mined_height = match output_data.get_item("mined_height")? {
            Some(v) if !v.is_none() => Some(v.extract::<u64>()?),
            _ => None,
        };

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
                        "Storage not initialized - call initialize() first".into()
                    )
                })?;

            // Parse hex fields to bytes
            let commitment = hex::decode(&commitment_hex)
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Invalid commitment hex: {}", e)
                ))?;

            let hash = hex::decode(&hash_hex)
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Invalid hash hex: {}", e)
                ))?;

            let script = hex::decode(&script_hex)
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Invalid script hex: {}", e)
                ))?;

            let input_data = hex::decode(&input_data_hex)
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Invalid input_data hex: {}", e)
                ))?;

            let covenant = hex::decode(&covenant_hex)
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Invalid covenant hex: {}", e)
                ))?;

            let sender_offset_public_key = hex::decode(&sender_offset_public_key_hex)
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Invalid sender_offset_public_key hex: {}", e)
                ))?;

            let metadata_signature_ephemeral_commitment = hex::decode(&metadata_signature_ephemeral_commitment_hex)
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Invalid metadata_signature_ephemeral_commitment hex: {}", e)
                ))?;

            let metadata_signature_ephemeral_pubkey = hex::decode(&metadata_signature_ephemeral_pubkey_hex)
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Invalid metadata_signature_ephemeral_pubkey hex: {}", e)
                ))?;

            let metadata_signature_u_a = hex::decode(&metadata_signature_u_a_hex)
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Invalid metadata_signature_u_a hex: {}", e)
                ))?;

            let metadata_signature_u_x = hex::decode(&metadata_signature_u_x_hex)
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Invalid metadata_signature_u_x hex: {}", e)
                ))?;

            let metadata_signature_u_y = hex::decode(&metadata_signature_u_y_hex)
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Invalid metadata_signature_u_y hex: {}", e)
                ))?;

            let encrypted_data = hex::decode(&encrypted_data_hex)
                .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Invalid encrypted_data hex: {}", e)
                ))?;

            let rangeproof = if let Some(rp_hex) = rangeproof_hex {
                Some(hex::decode(&rp_hex)
                    .map_err(|e| lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                        format!("Invalid rangeproof hex: {}", e)
                    ))?)
            } else {
                None
            };

            // Create StoredOutput
            let stored_output = StoredOutput {
                id: None, // Will be assigned by storage
                wallet_id,
                commitment,
                hash,
                value,
                spending_key: spending_key_hex,
                script_private_key: script_private_key_hex,
                script,
                input_data,
                covenant,
                output_type,
                features_json,
                maturity,
                script_lock_height,
                sender_offset_public_key,
                metadata_signature_ephemeral_commitment,
                metadata_signature_ephemeral_pubkey,
                metadata_signature_u_a,
                metadata_signature_u_x,
                metadata_signature_u_y,
                encrypted_data,
                minimum_value_promise,
                rangeproof,
                status,
                mined_height,
                spent_in_tx_id: None, // Not spent initially
                created_at: None, // Will be set by storage
                updated_at: None, // Will be set by storage
            };

            // Save to storage
            let output_id = storage.save_output(&stored_output).await?;

            Ok(output_id)
        })
    }

    /// Get outputs with optional filtering
    /// 
    /// Args:
    ///     filter_data: dict or None - Optional filter parameters:
    ///         - wallet_id: int - Filter by wallet ID
    ///         - status: int - Filter by output status (0=Unspent, 1=Spent, etc.)
    ///         - min_value: int - Filter by minimum value
    ///         - max_value: int - Filter by maximum value
    ///         - maturity_range: tuple (min, max) - Filter by maturity range
    ///         - mined_height_range: tuple (min, max) - Filter by mined height range
    ///         - spendable_at_height: int - Only outputs spendable at given height
    ///         - limit: int - Maximum number of results
    ///         - offset: int - Pagination offset
    /// 
    /// Returns:
    ///     list: List of output dictionaries
    fn get_outputs(&self, filter_data: Option<&Bound<'_, PyDict>>) -> PyResult<PyObject> {
        let storage_arc = Arc::clone(&self.inner);
        
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
                        "Storage not initialized - call initialize() first".into()
                    )
                })?;

            // Build filter
            let mut filter = OutputFilter::new();
            
            if let Some(filter_dict) = filter_data {
                // Parse filter parameters
                if let Some(wallet_id_val) = filter_dict.get_item("wallet_id").map_err(|e| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Filter error: {}", e))
                })? {
                    let wallet_id: u32 = wallet_id_val.extract().map_err(|e| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Integer extraction error: {}", e))
                    })?;
                    filter = filter.with_wallet_id(wallet_id);
                }
                
                if let Some(status_val) = filter_dict.get_item("status").map_err(|e| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Filter error: {}", e))
                })? {
                    let status_int: u32 = status_val.extract().map_err(|e| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Integer extraction error: {}", e))
                    })?;
                    let status = OutputStatus::from(status_int);
                    filter = filter.with_status(status);
                }
                
                if let Some(min_val) = filter_dict.get_item("min_value").map_err(|e| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Filter error: {}", e))
                })? {
                    let min_value: u64 = min_val.extract().map_err(|e| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Integer extraction error: {}", e))
                    })?;
                    if let Some(max_val) = filter_dict.get_item("max_value").map_err(|e| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Filter error: {}", e))
                    })? {
                        let max_value: u64 = max_val.extract().map_err(|e| {
                            lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Integer extraction error: {}", e))
                        })?;
                        filter = filter.with_value_range(min_value, max_value);
                    }
                }
                
                if let Some(spendable_val) = filter_dict.get_item("spendable_at_height").map_err(|e| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Filter error: {}", e))
                })? {
                    let spendable_height: u64 = spendable_val.extract().map_err(|e| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Integer extraction error: {}", e))
                    })?;
                    filter = filter.spendable_at(spendable_height);
                }
                
                if let Some(limit_val) = filter_dict.get_item("limit").map_err(|e| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Filter error: {}", e))
                })? {
                    let limit: usize = limit_val.extract().map_err(|e| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Integer extraction error: {}", e))
                    })?;
                    filter = filter.with_limit(limit);
                }
                
                if let Some(offset_val) = filter_dict.get_item("offset").map_err(|e| {
                    lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Filter error: {}", e))
                })? {
                    let offset: usize = offset_val.extract().map_err(|e| {
                        lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(format!("Integer extraction error: {}", e))
                    })?;
                    filter = filter.with_offset(offset);
                }
            }

            // Get outputs from storage
            let outputs = storage.get_outputs(Some(filter)).await?;

            // Convert to Python objects
            let result = Python::with_gil(|py| {
                let list = PyList::empty(py);
                for output in outputs {
                    let dict = PyDict::new(py);
                    dict.set_item("id", output.id)?;
                    dict.set_item("wallet_id", output.wallet_id)?;
                    dict.set_item("commitment_hex", hex::encode(&output.commitment))?;
                    dict.set_item("hash_hex", hex::encode(&output.hash))?;
                    dict.set_item("value", output.value)?;
                    dict.set_item("spending_key_hex", &output.spending_key)?;
                    dict.set_item("script_private_key_hex", &output.script_private_key)?;
                    dict.set_item("script_hex", hex::encode(&output.script))?;
                    dict.set_item("input_data_hex", hex::encode(&output.input_data))?;
                    dict.set_item("covenant_hex", hex::encode(&output.covenant))?;
                    dict.set_item("output_type", output.output_type)?;
                    dict.set_item("features_json", &output.features_json)?;
                    dict.set_item("maturity", output.maturity)?;
                    dict.set_item("script_lock_height", output.script_lock_height)?;
                    dict.set_item("sender_offset_public_key_hex", hex::encode(&output.sender_offset_public_key))?;
                    dict.set_item("metadata_signature_ephemeral_commitment_hex", hex::encode(&output.metadata_signature_ephemeral_commitment))?;
                    dict.set_item("metadata_signature_ephemeral_pubkey_hex", hex::encode(&output.metadata_signature_ephemeral_pubkey))?;
                    dict.set_item("metadata_signature_u_a_hex", hex::encode(&output.metadata_signature_u_a))?;
                    dict.set_item("metadata_signature_u_x_hex", hex::encode(&output.metadata_signature_u_x))?;
                    dict.set_item("metadata_signature_u_y_hex", hex::encode(&output.metadata_signature_u_y))?;
                    dict.set_item("encrypted_data_hex", hex::encode(&output.encrypted_data))?;
                    dict.set_item("minimum_value_promise", output.minimum_value_promise)?;
                    dict.set_item("rangeproof_hex", output.rangeproof.as_ref().map(|rp| hex::encode(rp)))?;
                    dict.set_item("status", output.status)?;
                    dict.set_item("mined_height", output.mined_height)?;
                    dict.set_item("spent_in_tx_id", output.spent_in_tx_id)?;
                    dict.set_item("created_at", &output.created_at)?;
                    dict.set_item("updated_at", &output.updated_at)?;
                    list.append(dict)?;
                }
                Ok(list.into())
            }).map_err(|e: PyErr| {
                lightweight_wallet_libs::errors::LightweightWalletError::ConversionError(
                    format!("Failed to convert outputs to Python list: {}", e)
                )
            })?;

            Ok(result)
        })
    }

    /// Get spendable balance for a wallet at a specific block height
    /// 
    /// Args:
    ///     wallet_id: int - Wallet ID to calculate balance for
    ///     block_height: int - Block height to check spendability at
    /// 
    /// Returns:
    ///     int: Total value of spendable outputs in microMinotari
    fn get_spendable_balance(&self, wallet_id: u32, block_height: u64) -> PyResult<u64> {
        let storage_arc = Arc::clone(&self.inner);
        
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
                        "Storage not initialized - call initialize() first".into()
                    )
                })?;

            // Get spendable balance
            let balance = storage.get_spendable_balance(wallet_id, block_height).await?;

            Ok(balance)
        })
    }

    /// Mark an output as spent
    /// 
    /// Args:
    ///     output_id: int - Output ID to mark as spent
    ///     spent_in_tx_id: int - Transaction ID where this output was spent
    /// 
    /// Returns:
    ///     None
    fn mark_output_spent(&self, output_id: u32, spent_in_tx_id: u64) -> PyResult<()> {
        let storage_arc = Arc::clone(&self.inner);
        
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
                        "Storage not initialized - call initialize() first".into()
                    )
                })?;

            // Mark output as spent
            storage.mark_output_spent(output_id, spent_in_tx_id).await?;

            Ok(())
        })
    }

    /// String representation
    fn __str__(&self) -> String {
        match &self.path {
            Some(path) => format!("TariWalletStorage(path='{}')", path.display()),
            None => "TariWalletStorage(in_memory=True)".to_string(),
        }
    }

    /// Representation
    fn __repr__(&self) -> String {
        self.__str__()
    }
}

impl TariWalletStorage {
    /// Get a shared storage Arc for use with UTXO manager
    /// Internal method not exposed to Python
    pub(crate) fn get_shared_storage(&self) -> PyResult<Arc<Mutex<Option<SqliteStorage>>>> {
        // Check if storage is initialized
        {
            let storage_guard = self.inner.lock()
                .map_err(|_| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Failed to lock storage"))?;
            
            if storage_guard.is_none() {
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Storage not initialized - call initialize() first"));
            }
        }

        // Return the shared Arc for use by UTXO manager
        Ok(Arc::clone(&self.inner))
    }
}
