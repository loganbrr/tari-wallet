//! Python bindings for blockchain scanning functionality wrapping HttpBlockchainScanner

use pyo3::prelude::*;

use std::sync::{Arc, Mutex};
use lightweight_wallet_libs::wallet::Wallet;
use lightweight_wallet_libs::scanning::BlockchainScanner;
use lightweight_wallet_libs::errors::LightweightWalletError;
use crate::runtime::{execute_async, get_or_create_scanner};
use tari_utilities::hex;

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

/// Balance information
#[pyclass]
#[derive(Clone)]
pub struct Balance {
    #[pyo3(get)]
    available: u64,
    #[pyo3(get)]
    pending: u64,
    #[pyo3(get)]
    immature: u64,
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
    #[new]
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

    /// Get wallet balance by performing a quick scan from wallet birthday
    fn get_balance(&self) -> PyResult<Balance> {
        let base_url = self.base_url.clone();
        let wallet = Arc::clone(&self.wallet);
        
        execute_async(async move {
            let scanner_arc = get_or_create_scanner(&base_url).await?;
            let mut scanner = scanner_arc.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock scanner".into()))?;
            
            // Get wallet birthday for scan start
            let start_height = {
                let wallet_guard = wallet.lock()
                    .map_err(|_| LightweightWalletError::ConversionError("Failed to lock wallet".into()))?;
                wallet_guard.birthday()
            };
            
            // Create wallet scan config and perform scan
            let wallet_guard = wallet.lock()
                .map_err(|_| LightweightWalletError::ConversionError("Failed to lock wallet".into()))?;
            let scan_config = scanner.create_scan_config_with_wallet_keys(&*wallet_guard, start_height, None)?;
            drop(wallet_guard);
            
            // Perform the scan
            let block_results = scanner.scan_blocks(scan_config).await?;
            
            // Calculate balance from results
            let total_value: u64 = block_results.iter()
                .flat_map(|block| &block.wallet_outputs)
                .map(|output| output.value().as_u64())
                .sum();
            
            Ok(Balance {
                available: total_value,
                pending: 0,    // Could be enhanced to track pending transactions
                immature: 0,   // Could be enhanced to track coinbase maturity
            })
        })
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
                    hex::from_hex(hex_str)
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
impl Balance {
    fn total(&self) -> u64 {
        self.available + self.pending + self.immature
    }
    
    fn __repr__(&self) -> String {
        format!(
            "Balance(available={}, pending={}, immature={}, total={})",
            self.available,
            self.pending,
            self.immature,
            self.total()
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
