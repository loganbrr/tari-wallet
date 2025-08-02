//! Python bindings for blockchain scanning functionality wrapping HttpBlockchainScanner

use pyo3::prelude::*;

use std::sync::{Arc, Mutex};
use lightweight_wallet_libs::wallet::Wallet;
use lightweight_wallet_libs::scanning::BlockchainScanner;
use lightweight_wallet_libs::errors::LightweightWalletError;
use crate::runtime::{execute_async, get_or_create_scanner};
use crate::stealth_types::StealthScanResult;
use crate::stealth_address::TariStealthAddress;
use crate::utils::{derive_view_spend_keys_from_master_key, get_stealth_info_from_master_key};
use tari_utilities::ByteArray;
use hex;
use tari_utilities::hex::from_hex;

/// Python wrapper for blockchain scanner wrapping HttpBlockchainScanner
#[pyclass]
pub struct TariScanner {
    base_url: String,
    wallet: Arc<Mutex<Wallet>>,
}

/// Scan result containing transactions and metadata
#[pyclass]
#[derive(Clone)]
pub struct ScanResult {
    #[pyo3(get)]
    transaction_count: u64,
    #[pyo3(get)]
    total_scanned: u64,
    #[pyo3(get)]
    current_height: u64,
}



/// Scan progress information
#[pyclass]
#[derive(Clone)]
pub struct ScanProgress {
    #[pyo3(get)]
    current_height: u64,
    #[pyo3(get)]
    total_blocks: u64,
    #[pyo3(get)]
    percentage: f64,
}

#[pymethods]
impl TariScanner {
    /// Create a new scanner with the given base node URL
    /// 
    /// Args:
    ///     base_node_url: The base node URL for blockchain connections (e.g., "http://localhost:18142")
    ///     wallet: TariWallet instance for key derivation and address generation
    /// 
    /// Returns:
    ///     TariScanner: A new scanner instance configured for the specified base node
    /// 
    /// Example:
    ///     >>> wallet = TariWallet.generate_new_with_seed_phrase(None)
    ///     >>> scanner = TariScanner("http://localhost:18142", wallet)
    #[new]
    #[pyo3(signature = (base_node_url, wallet), text_signature = "(base_node_url, wallet)")]
    fn new(base_node_url: String, wallet: &crate::TariWallet) -> PyResult<Self> {
        Ok(TariScanner {
            base_url: base_node_url,
            wallet: Arc::clone(&wallet.inner),
        })
    }

    /// Get the current tip height from the blockchain
    fn get_tip_height(&self) -> PyResult<u64> {
        let base_url = self.base_url.clone();
        
        execute_async(async move {
            let scanner_arc = get_or_create_scanner(&base_url).await?;
            let mut scanner = scanner_arc.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner".into()))?;
            let tip_info = scanner.get_tip_info().await?;
            Ok(tip_info.best_block_height)
        })
    }

    /// Scan a range of blocks for transactions
    fn scan_blocks(&self, from_height: u64, to_height: Option<u64>) -> PyResult<ScanResult> {
        let base_url = self.base_url.clone();
        let wallet = Arc::clone(&self.wallet);
        
        execute_async(async move {
            let scanner_arc = get_or_create_scanner(&base_url).await?;
            let mut scanner = scanner_arc.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner".into()))?;
            
            // Get wallet for key derivation
            let wallet_guard = wallet.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock wallet".into()))?;
            
            // Create scan config using the existing method
            let scan_config = scanner.create_scan_config_with_wallet_keys(&*wallet_guard, from_height, to_height)?;
            drop(wallet_guard);
            
            // Perform the actual scan
            let block_results = scanner.scan_blocks(scan_config).await?;
            
            let total_wallet_outputs = block_results.iter()
                .map(|block| block.wallet_outputs.len() as u64)
                .sum();
            
            let end_height = to_height.unwrap_or(from_height + 100);
            
            Ok(ScanResult {
                transaction_count: total_wallet_outputs,
                total_scanned: end_height - from_height + 1,
                current_height: end_height,
            })
        })
    }

    /// Get wallet balance - requires storage for proper balance calculation
    /// Note: This method requires storage integration to work properly
    fn get_balance(&self, storage: &crate::storage::TariWalletStorage, wallet_id: u32) -> PyResult<crate::balance::TariBalance> {
        crate::balance::TariBalance::new(storage, wallet_id)
    }

    /// Get a single block by height
    fn get_block_by_height(&self, height: u64) -> PyResult<Option<String>> {
        let base_url = self.base_url.clone();
        
        execute_async(async move {
            let scanner_arc = get_or_create_scanner(&base_url).await?;
            let mut scanner = scanner_arc.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner".into()))?;
            
            let block_info = scanner.get_block_by_height(height).await?;
            Ok(block_info.map(|b| format!("Block {} with {} outputs", b.height, b.outputs.len())))
        })
    }

    /// Search for specific UTXOs by commitment (hex-encoded)
    fn search_utxos(&self, commitment_hexes: Vec<String>) -> PyResult<ScanResult> {
        let base_url = self.base_url.clone();
        
        execute_async(async move {
            let scanner_arc = get_or_create_scanner(&base_url).await?;
            let mut scanner = scanner_arc.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner".into()))?;
            
            // Convert hex strings to bytes
            let commitments: Result<Vec<Vec<u8>>, LightweightWalletError> = commitment_hexes
                .iter()
                .map(|hex_str| {
                    from_hex(hex_str)
                        .map_err(|e| LightweightWalletError::ConversionError(format!("Hex decode error: {}", e)))
                })
                .collect();
            let commitments = commitments?;
            
            let block_results = scanner.search_utxos(commitments).await?;
            
            let total_wallet_outputs = block_results.iter()
                .map(|block| block.wallet_outputs.len() as u64)
                .sum();
                
            Ok(ScanResult {
                transaction_count: total_wallet_outputs,
                total_scanned: block_results.len() as u64,
                current_height: block_results.iter()
                    .map(|b| b.height)
                    .max()
                    .unwrap_or(0),
            })
        })
    }

    /// Scan blocks for stealth addresses using wallet's view key
    /// 
    /// Args:
    ///     start_height: Starting block height for scanning
    ///     end_height: Ending block height for scanning  
    /// 
    /// Returns:
    ///     StealthScanResult: Scanning results with found stealth addresses
    /// 
    /// Example:
    ///     result = scanner.scan_for_stealth_addresses(1000, 2000)
    fn scan_for_stealth_addresses(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> PyResult<StealthScanResult> {
        let base_url = self.base_url.clone();
        let wallet = self.wallet.clone();
        
        execute_async(async move {
            // Get wallet view key using shared utility
            let view_key_hex = {
                let wallet_guard = wallet.lock()
                    .map_err(|e| LightweightWalletError::ConversionError(format!("Failed to lock wallet: {}", e)))?;
                let master_key_bytes = wallet_guard.master_key_bytes();
                drop(wallet_guard);
                
                let (view_key, _) = derive_view_spend_keys_from_master_key(&master_key_bytes)
                    .map_err(|e| LightweightWalletError::ConversionError(format!("Failed to derive view key: {}", e)))?;
                
                hex::encode(view_key.as_bytes())
            };

            // Get blockchain scanner
            let scanner_arc = get_or_create_scanner(&base_url).await?;
            let mut scanner = scanner_arc.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner".into()))?;

            // Collect outputs from actual blockchain blocks
            let mut outputs = Vec::new();
            for height in start_height..=end_height {
                if let Some(block_info) = scanner.get_block_by_height(height).await? {
                    for output in block_info.outputs {
                        // Extract required fields for stealth address scanning
                        Python::with_gil(|py| {
                            let output_dict = pyo3::types::PyDict::new(py);
                            output_dict.set_item("sender_offset", hex::encode(output.sender_offset_public_key.as_bytes())).unwrap();
                            output_dict.set_item("script_key", hex::encode(&output.script.bytes)).unwrap();
                            outputs.push(output_dict.into());
                        });
                    }
                }
            }

            // Use TariStealthAddress to scan the real outputs
            let stealth_scanner = TariStealthAddress::new();
            stealth_scanner.scan_for_outputs(&view_key_hex, outputs)
                .map_err(|e| LightweightWalletError::ConversionError(format!("Stealth scan failed: {}", e)))
        })
    }

    /// Scan specific outputs for stealth addresses
    /// 
    /// Args:
    ///     outputs: List of output dictionaries with 'sender_offset' and 'script_key' fields
    ///     chunk_size: Optional chunk size for processing
    /// 
    /// Returns:
    ///     StealthScanResult: Scanning results with found stealth addresses
    /// 
    /// Example:
    ///     outputs = [{"sender_offset": "abc...", "script_key": "def..."}]
    ///     result = scanner.scan_outputs_for_stealth_addresses(outputs)
    #[pyo3(signature = (outputs, _chunk_size=None))]
    fn scan_outputs_for_stealth_addresses(
        &self,
        outputs: Vec<PyObject>,
        _chunk_size: Option<usize>,
    ) -> PyResult<StealthScanResult> {
        // Get wallet view key using shared utility
        let wallet_guard = self.wallet.lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        let master_key_bytes = wallet_guard.master_key_bytes();
        drop(wallet_guard);

        let (view_key, _) = derive_view_spend_keys_from_master_key(&master_key_bytes)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("View key derivation failed: {}", e)))?;

        let view_key_hex = hex::encode(view_key.as_bytes());

        // Use TariStealthAddress to scan the outputs
        let stealth_scanner = TariStealthAddress::new();
        stealth_scanner.scan_for_outputs(&view_key_hex, outputs)
    }

    /// Get stealth address information for the wallet
    /// 
    /// Returns:
    ///     dict: Dictionary with wallet's stealth address public keys
    /// 
    /// Example:
    ///     info = scanner.get_stealth_address_info()
    ///     view_public = info['view_public_key']
    fn get_stealth_address_info(&self) -> PyResult<PyObject> {
        let wallet_guard = self.wallet.lock()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to lock wallet: {}", e)))?;
        let master_key_bytes = wallet_guard.master_key_bytes();
        drop(wallet_guard);

        // Use shared utility for key derivation
        let (view_key, spend_key, view_public_key, spend_public_key) = get_stealth_info_from_master_key(&master_key_bytes)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("Key derivation failed: {}", e)))?;

        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("view_public_key", hex::encode(view_public_key.as_bytes()))?;
            dict.set_item("spend_public_key", hex::encode(spend_public_key.as_bytes()))?;
            dict.set_item("view_private_key", hex::encode(view_key.as_bytes()))?;
            dict.set_item("spend_private_key", hex::encode(spend_key.as_bytes()))?;
            Ok(dict.into())
        })
    }
}

#[pymethods]
impl ScanResult {
    fn __repr__(&self) -> String {
        format!(
            "ScanResult(transaction_count={}, total_scanned={}, current_height={})",
            self.transaction_count,
            self.total_scanned,
            self.current_height
        )
    }
}



#[pymethods]
impl ScanProgress {
    fn __repr__(&self) -> String {
        format!(
            "ScanProgress(current_height={}, total_blocks={}, percentage={:.1}%)",
            self.current_height,
            self.total_blocks,
            self.percentage
        )
    }
}
