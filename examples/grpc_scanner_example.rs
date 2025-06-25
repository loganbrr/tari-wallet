// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Example demonstrating how to use the GRPC blockchain scanner
//! 
//! This example shows how to connect to a Tari base node via GRPC
//! and scan for wallet outputs using wallet keys.
//!
//! ## Prerequisites
//!
//! 1. **Tari Base Node**: You need a running Tari base node with GRPC enabled
//!    - Download from: https://github.com/tari-project/tari/releases
//!    - Enable GRPC in the configuration
//!    - Default GRPC port: 18142
//!
//! ## Running the Example
//!
//! ```bash
//! # Basic usage with defaults (generates random wallet, scans last 100 blocks)
//! cargo run --example grpc_scanner_example --features grpc
//!
//! # Using a specific seed phrase
//! TEST_SEED_PHRASE="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
//! cargo run --example grpc_scanner_example --features grpc
//!
//! # Using specific block range
//! FROM_BLOCK=1000 TO_BLOCK=1100 \
//! cargo run --example grpc_scanner_example --features grpc
//!
//! # Using both seed phrase and block range
//! TEST_SEED_PHRASE="your seed phrase here" FROM_BLOCK=950 TO_BLOCK=1000 \
//! cargo run --example grpc_scanner_example --features grpc
//! ```
//!
//! ## Environment Variables
//!
//! - `TEST_SEED_PHRASE`: Seed phrase to create the wallet from (optional, generates random if not provided)
//! - `FROM_BLOCK`: Starting block height for scanning (optional, defaults to tip - 100)
//! - `TO_BLOCK`: Ending block height for scanning (optional, defaults to current tip)
//!
//! ## What This Example Demonstrates
//!
//! 1. **Simple Wallet Key Integration**: Using the `create_scan_config_with_wallet_keys()` helper method
//!    - Extracts wallet's master key and uses it as the scanning key
//!    - Demonstrates basic wallet output detection
//!
//! 2. **Advanced Key Management**: Using a custom `KeyManager` implementation with `KeyStore`
//!    - Shows how to implement the `KeyManager` trait for custom key derivation
//!    - Demonstrates importing private keys and scanning with multiple key sources
//!    - Uses entropy-based key derivation matching Tari's specification
//!
//! 3. **Basic Block Scanning**: Scanning blocks without wallet-specific functionality
//!    - Shows how to scan blocks for transaction outputs
//!    - Useful for general blockchain analysis
//!
//! ## Expected Output
//!
//! ```text
//! # With environment variables:
//! TEST_SEED_PHRASE="abandon abandon abandon..." FROM_BLOCK=950 TO_BLOCK=1000 \
//! cargo run --example grpc_scanner_example --features grpc
//!
//! GRPC Wallet Scanner Example
//! ===========================
//! Creating wallet from provided seed phrase
//! Wallet birthday: 15847
//! Wallet seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
//! Connected to base node successfully!
//! Current tip height: 567890
//! Current tip hash: a1b2c3d4e5f6...
//! Scan range: 950 to 1000 (51 blocks)
//! 
//! === Method 1: Simple Wallet Key Scanning ===
//! Scanning blocks 950 to 1000 with wallet keys...
//! Found 0 wallet outputs in 51 blocks
//! 
//! === Method 2: Advanced Wallet Scanning ===
//! Imported example key successfully
//! Advanced wallet scanning from block 950 to 1000 (51 blocks)
//! Progress: 1000/1000 blocks (0 outputs, 0 MicroMinotari) - 2.34s elapsed
//! 
//! === Method 3: Basic Block Scanning ===
//! Basic scanning blocks 996 to 1000 (no key management)
//! Basic scan found 0 wallet outputs (without key management)
//! 
//! === Example Summary ===
//! Configuration:
//!   Seed Phrase: Provided via TEST_SEED_PHRASE
//!   Scan Range: 950 to 1000 (51 blocks)
//!   Block Source: FROM_BLOCK env var
//!   Block End: TO_BLOCK env var
//! 
//! Results:
//! 1. Method 1 (Simple): Found 0 outputs using wallet keys
//! 2. Method 2 (Advanced): Found 0 outputs using KeyManager+KeyStore
//! 3. Method 3 (Basic): Found 0 outputs without key management
//! 
//! Environment Variables Used:
//! - TEST_SEED_PHRASE: ✓ Used
//! - FROM_BLOCK: ✓ Used (950)
//! - TO_BLOCK: ✓ Used (1000)
//! ```
//!
//! If no base node is running, you'll get a connection error with helpful instructions.
//!
//! ## Architecture Notes
//!
//! This example demonstrates the integration between:
//! - `GrpcBlockchainScanner`: Connects to Tari base node via GRPC
//! - `SimpleKeyManager`: Custom key manager implementation for wallet key derivation
//! - `Wallet`: Core wallet functionality for key management
//! - `KeyStore`: Storage for imported private keys
//! - Progress tracking and error handling

#[cfg(feature = "grpc")]
use lightweight_wallet_libs::{
    scanning::{GrpcScannerBuilder, WalletScanConfig, WalletScanner, BlockchainScanner, ProgressCallback, ScanProgress, ScanConfig},
    extraction::ExtractionConfig,
    key_management::{KeyManager, KeyStore, KeyDerivationPath, DerivedKeyPair},
    wallet::Wallet,
    errors::LightweightWalletResult,
    KeyManagementError,
    data_structures::types::{PrivateKey, CompressedPublicKey},
    crypto::keys::ByteArray,
};
use tracing_subscriber;

/// Simple KeyManager implementation for the example
#[cfg(feature = "grpc")]
#[derive(Debug)]
struct SimpleKeyManager {
    entropy: [u8; 16],
    current_index: u64,
}

#[cfg(feature = "grpc")]
impl SimpleKeyManager {
    pub fn new(entropy: [u8; 16]) -> Self {
        Self {
            entropy,
            current_index: 0,
        }
    }
    
    pub fn from_wallet(wallet: &Wallet) -> LightweightWalletResult<Self> {
        // Extract entropy from wallet's master key (first 16 bytes)
        let master_key_bytes = wallet.master_key_bytes();
        let mut entropy = [0u8; 16];
        entropy.copy_from_slice(&master_key_bytes[..16]);
        Ok(Self::new(entropy))
    }
}

#[cfg(feature = "grpc")]
impl KeyManager for SimpleKeyManager {
    fn derive_key_pair(&self, path: &KeyDerivationPath) -> Result<DerivedKeyPair, KeyManagementError> {
        let private_key = self.derive_private_key(path)?;
        let public_key = CompressedPublicKey::from_private_key(&private_key);
        
        Ok(DerivedKeyPair::new(
            private_key,
            public_key,
            path.key_index,
            path.clone(),
        ))
    }
    
    fn derive_private_key(&self, path: &KeyDerivationPath) -> Result<PrivateKey, KeyManagementError> {
        let ristretto_key = lightweight_wallet_libs::key_management::key_derivation::derive_private_key_from_entropy(
            &self.entropy,
            &path.branch_seed,
            path.key_index,
        )?;
        
        // Convert RistrettoSecretKey to PrivateKey using byte conversion
        let key_bytes = ristretto_key.as_bytes();
        let mut bytes_array = [0u8; 32];
        bytes_array.copy_from_slice(key_bytes);
        Ok(PrivateKey::new(bytes_array))
    }
    
    fn derive_public_key(&self, path: &KeyDerivationPath) -> Result<CompressedPublicKey, KeyManagementError> {
        let private_key = self.derive_private_key(path)?;
        Ok(CompressedPublicKey::from_private_key(&private_key))
    }
    
    fn next_key_pair(&mut self) -> Result<DerivedKeyPair, KeyManagementError> {
        let path = KeyDerivationPath::new("spending".to_string(), self.current_index);
        let result = self.derive_key_pair(&path)?;
        self.current_index += 1;
        Ok(result)
    }
    
    fn current_key_index(&self) -> u64 {
        self.current_index
    }
    
    fn update_key_index(&mut self, new_index: u64) {
        self.current_index = new_index;
    }
}

#[cfg(feature = "grpc")]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("GRPC Wallet Scanner Example");
    println!("===========================");

    // Get configuration from environment variables
    let seed_phrase = std::env::var("TEST_SEED_PHRASE").unwrap_or_else(|_| {
        println!("No TEST_SEED_PHRASE provided, generating a new wallet");
        String::new()
    });

    let from_block = std::env::var("FROM_BLOCK")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());

    let to_block = std::env::var("TO_BLOCK")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());

    // Create a wallet - either from seed phrase or generate new
    let wallet = if !seed_phrase.is_empty() {
        println!("Creating wallet from provided seed phrase");
        Wallet::new_from_seed_phrase(&seed_phrase, None)?
    } else {
        println!("Generating new wallet with random seed phrase");
        Wallet::generate_new_with_seed_phrase(None)?
    };

    println!("Wallet birthday: {}", wallet.birthday());
    
    // Export and display the seed phrase for reference
    match wallet.export_seed_phrase() {
        Ok(phrase) => {
            println!("Wallet seed phrase: {}", phrase);
            println!("(Save this if you want to reproduce the same wallet)");
        },
        Err(_) => {
            println!("Wallet was created without a seed phrase");
        }
    }

    // Create a GRPC scanner builder
    let builder = GrpcScannerBuilder::new()
        .with_base_url("http://127.0.0.1:18142".to_string())
        .with_timeout(std::time::Duration::from_secs(30));

    // Build the scanner
    let mut scanner = match builder.build().await {
        Ok(scanner) => scanner,
        Err(e) => {
            eprintln!("Failed to create GRPC scanner: {}", e);
            eprintln!("Make sure a Tari base node is running with GRPC enabled on port 18142");
            return Err(e);
        }
    };

    println!("Connected to base node successfully!");

    // Get tip information
    let tip_info = scanner.get_tip_info().await?;
    println!("Current tip height: {}", tip_info.best_block_height);
    println!("Current tip hash: {}", hex::encode(&tip_info.best_block_hash));

    // Determine scan range from environment variables or use defaults
    let scan_start = from_block.unwrap_or_else(|| {
        let default_start = tip_info.best_block_height.saturating_sub(100);
        println!("No FROM_BLOCK specified, using default: {} (tip - 100)", default_start);
        default_start
    });

    let scan_end = to_block.unwrap_or_else(|| {
        println!("No TO_BLOCK specified, using current tip: {}", tip_info.best_block_height);
        tip_info.best_block_height
    });

    println!("Scan range: {} to {} ({} blocks)", scan_start, scan_end, scan_end.saturating_sub(scan_start) + 1);

    // Method 1: Simple scanning with wallet keys (using the new helper method)
    println!("\n=== Method 1: Simple Wallet Key Scanning ===");
    
    let scan_config = scanner.create_scan_config_with_wallet_keys(&wallet, scan_start, Some(scan_end))?;
    
    println!("Scanning blocks {} to {} with wallet keys...", scan_start, scan_end);
    let scan_results = scanner.scan_blocks(scan_config).await?;
    
    let total_wallet_outputs: usize = scan_results.iter().map(|r| r.wallet_outputs.len()).sum();
    println!("Found {} wallet outputs in {} blocks", total_wallet_outputs, scan_results.len());

    // Method 2: Advanced scanning with KeyManager and KeyStore
    println!("\n=== Method 2: Advanced Wallet Scanning ===");
    
    // Create a key manager from the wallet
    let key_manager = SimpleKeyManager::from_wallet(&wallet)?;
    
    // Create a key store with some imported keys
    let mut key_store = KeyStore::new();
    
    // Example: Import a key from hex (in real usage, this would be a user-provided key)
    let example_key_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    if let Ok(()) = key_store.import_private_key_from_hex(example_key_hex, Some("example_key".to_string())) {
        println!("Imported example key successfully");
    }

    // Use a smaller range for advanced scanning to demonstrate efficiently
    let advanced_scan_start = scan_start;
    let advanced_scan_end = std::cmp::min(scan_start + 50, scan_end); // Max 50 blocks for demo
    
    // Configure wallet scanning with more options
    let wallet_scan_config = WalletScanConfig::new(advanced_scan_start)
        .with_key_manager(Box::new(key_manager))
        .with_key_store(key_store)
        .with_stealth_address_scanning(true)
        .with_max_addresses_per_account(10) // Scan first 10 addresses per account
        .with_imported_key_scanning(true)
        .with_end_height(advanced_scan_end)
        .with_batch_size(25)
        .with_request_timeout(std::time::Duration::from_secs(30));

    println!("Advanced wallet scanning from block {} to {} ({} blocks)", 
        advanced_scan_start, advanced_scan_end, advanced_scan_end.saturating_sub(advanced_scan_start) + 1);

    // Create a progress callback
    let progress_callback: ProgressCallback = Box::new(|progress: ScanProgress| {
        println!(
            "Progress: {}/{} blocks ({} outputs, {} MicroMinotari) - {:.2}s elapsed",
            progress.current_height,
            progress.target_height,
            progress.outputs_found,
            progress.total_value,
            progress.elapsed.as_secs_f64()
        );
    });

    // Scan for wallet outputs with progress reporting
    let wallet_result = scanner.scan_wallet_with_progress(
        wallet_scan_config,
        Some(&progress_callback)
    ).await?;
    
    println!("\nAdvanced wallet scan completed!");
    println!("===============================");
    println!("Total blocks scanned: {}", wallet_result.block_results.len());
    println!("Total wallet outputs found: {}", wallet_result.total_wallet_outputs);
    println!("Total value found: {} MicroMinotari", wallet_result.total_value);
    println!("Addresses scanned: {}", wallet_result.addresses_scanned);
    println!("Accounts scanned: {}", wallet_result.accounts_scanned);
    println!("Scan duration: {:.2}s", wallet_result.scan_duration.as_secs_f64());

    // Print details of blocks with wallet outputs
    let blocks_with_outputs: Vec<_> = wallet_result.block_results
        .iter()
        .filter(|r| !r.wallet_outputs.is_empty())
        .collect();

    if !blocks_with_outputs.is_empty() {
        println!("\nBlocks with wallet outputs:");
        println!("===========================");
        for result in blocks_with_outputs {
            let block_value: u64 = result.wallet_outputs.iter()
                .map(|wo| wo.value().as_u64())
                .sum();
            
            println!("Block {}: {} outputs, {} MicroMinotari", 
                result.height, 
                result.wallet_outputs.len(),
                block_value
            );
            
            // Print details of each wallet output
            for (i, wallet_output) in result.wallet_outputs.iter().enumerate() {
                println!("  Output {}: {} MicroMinotari, Payment ID: {:?}", 
                    i + 1,
                    wallet_output.value().as_u64(),
                    wallet_output.payment_id()
                );
            }
        }
    } else {
        println!("\nNo wallet outputs found in the scanned range.");
        println!("This could mean:");
        println!("1. The wallet has no outputs in this block range");
        println!("2. The keys provided don't match any outputs");
        println!("3. The wallet birthday is set too high");
        println!("4. The base node doesn't have the required blocks");
    }

    // Method 3: Demonstrate basic scanning without key management (for comparison)
    println!("\n=== Method 3: Basic Block Scanning ===");
    
    let basic_extraction_config = ExtractionConfig {
        enable_key_derivation: false,
        validate_range_proofs: false,
        validate_signatures: false,
        handle_special_outputs: true,
        detect_corruption: false,
        private_key: None,
        public_key: None,
    };

    // Use a small subset for basic scanning (last 5 blocks of our range)
    let basic_start = std::cmp::max(scan_end.saturating_sub(5), scan_start);
    let basic_scan_config = ScanConfig {
        start_height: basic_start,
        end_height: Some(scan_end),
        batch_size: 5,
        request_timeout: std::time::Duration::from_secs(30),
        extraction_config: basic_extraction_config,
    };

    println!("Basic scanning blocks {} to {} (no key management)", basic_start, scan_end);
    let basic_results = scanner.scan_blocks(basic_scan_config).await?;
    let basic_total_outputs: usize = basic_results.iter().map(|r| r.wallet_outputs.len()).sum();
    
    println!("Basic scan found {} wallet outputs (without key management)", basic_total_outputs);
    println!("Note: Without proper keys, most outputs cannot be extracted as wallet outputs.");

    println!("\n=== Example Summary ===");
    println!("Configuration:");
    println!("  Seed Phrase: {}", if !seed_phrase.is_empty() { "Provided via TEST_SEED_PHRASE" } else { "Generated randomly" });
    println!("  Scan Range: {} to {} ({} blocks)", scan_start, scan_end, scan_end.saturating_sub(scan_start) + 1);
    println!("  Block Source: {}", if from_block.is_some() { "FROM_BLOCK env var" } else { "Default (tip - 100)" });
    println!("  Block End: {}", if to_block.is_some() { "TO_BLOCK env var" } else { "Default (current tip)" });
    println!();
    println!("Results:");
    println!("1. Method 1 (Simple): Found {} outputs using wallet keys", total_wallet_outputs);
    println!("2. Method 2 (Advanced): Found {} outputs using KeyManager+KeyStore", wallet_result.total_wallet_outputs);
    println!("3. Method 3 (Basic): Found {} outputs without key management", basic_total_outputs);
    println!();
    println!("The example demonstrates three different ways to scan for wallet outputs:");
    println!("- Simple wallet key integration using helper methods");
    println!("- Advanced scanning with full key management features");  
    println!("- Basic block scanning without wallet-specific functionality");
    println!();
    println!("Environment Variables Used:");
    println!("- TEST_SEED_PHRASE: {} ", if !seed_phrase.is_empty() { "✓ Used" } else { "✗ Not provided (generated random)" });
    println!("- FROM_BLOCK: {}", if from_block.is_some() { format!("✓ Used ({})", scan_start) } else { format!("✗ Not provided (used default {})", scan_start) });
    println!("- TO_BLOCK: {}", if to_block.is_some() { format!("✓ Used ({})", scan_end) } else { format!("✗ Not provided (used current tip {})", scan_end) });

    Ok(())
}

#[cfg(not(feature = "grpc"))]
fn main() {
    eprintln!("This example requires the 'grpc' feature to be enabled.");
    eprintln!("Run with: cargo run --example grpc_scanner_example --features grpc");
    std::process::exit(1);
} 