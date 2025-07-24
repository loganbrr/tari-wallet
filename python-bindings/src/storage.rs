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
    storage_trait::StoredWallet,
};
use lightweight_wallet_libs::data_structures::types::PrivateKey;
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
