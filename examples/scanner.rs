//! Enhanced Tari Wallet Scanner
//! 
//! A comprehensive wallet scanner that tracks all transactions across blocks,
//! maintains complete transaction history, and provides accurate running balances.
//!
//! ## Features
//! - Cross-block transaction tracking
//! - Complete wallet state management
//! - Running balance calculation
//! - Clean, user-friendly output with bash-style progress bars
//! - Automatic scan from wallet birthday to chain tip
//! - **Graceful error handling with resume functionality**
//!
//! ## Error Handling
//! When GRPC errors occur (e.g., "message length too large"), the scanner will:
//! - Display the exact block height and error details
//! - Offer interactive options: Continue (y), Skip block (s), or Abort (n)
//! - Provide resume commands for easy restart from the failed point
//! - Example: `cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --from-block 25000 --to-block 30000`
//!
//! ## Usage
//! ```bash
//! # Scan with wallet from birthday to tip
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase here"
//!
//! # Scan specific range
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --from-block 34920 --to-block 34930
//!
//! # Use custom base node URL
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --base-url "http://192.168.1.100:18142"
//!
//! # Resume from a specific block after error with custom batch size
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --from-block 25000 --to-block 30000 --batch-size 5
//!
//! # Show help
//! cargo run --example scanner --features grpc -- --help
//! ```

#[cfg(feature = "grpc")]
use lightweight_wallet_libs::{
    scanning::{GrpcScannerBuilder, GrpcBlockchainScanner, BlockchainScanner},
    key_management::{key_derivation, seed_phrase::{mnemonic_to_bytes, CipherSeed}, StealthAddressService},
    extraction::RangeProofRewindService,
    wallet::Wallet,
    errors::{LightweightWalletResult},
    KeyManagementError,
    data_structures::{
        types::{PrivateKey, CompressedCommitment},
        encrypted_data::EncryptedData,
        payment_id::PaymentId,
        wallet_transaction::WalletState,
        transaction::{TransactionStatus, TransactionDirection},
    },
};
#[cfg(feature = "grpc")]
use tari_utilities::ByteArray;
#[cfg(feature = "grpc")]
use tari_crypto::ristretto::RistrettoPublicKey;
#[cfg(feature = "grpc")]
use std::sync::{Arc, Mutex, RwLock};
#[cfg(feature = "grpc")]
use std::collections::HashMap;
#[cfg(feature = "grpc")]
use std::time::{Duration, Instant};
// Removed unused async imports for now
#[cfg(feature = "grpc")]
use clap::Parser;

/// Enhanced Tari Wallet Scanner CLI
#[cfg(feature = "grpc")]
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Seed phrase for the wallet (required)
    #[arg(short, long, help = "Seed phrase for the wallet")]
    seed_phrase: String,

    /// Base URL for the Tari base node GRPC endpoint
    #[arg(short, long, default_value = "http://127.0.0.1:18142", help = "Base URL for Tari base node GRPC")]
    base_url: String,

    /// Starting block height for scanning
    #[arg(long, help = "Starting block height (defaults to last 1000 blocks from tip)")]
    from_block: Option<u64>,

    /// Ending block height for scanning
    #[arg(long, help = "Ending block height (defaults to current tip)")]
    to_block: Option<u64>,

    /// Enable caching for better performance on repeated scans
    #[arg(long, default_value = "true", help = "Enable result caching to speed up repeated operations")]
    enable_cache: bool,

    /// GRPC batch size for fetching multiple blocks at once
    #[arg(long, default_value = "100", help = "Number of blocks to fetch in a single GRPC call")]
    grpc_batch_size: usize,

    /// Specific blocks to scan (comma-separated list, e.g., "1234,3455,5643,4535")
    #[arg(long, help = "Scan only specific blocks instead of a range", value_delimiter = ',')]
    blocks: Option<Vec<u64>>,
}

/// Performance configuration for optimized scanning
#[cfg(feature = "grpc")]
#[derive(Clone, Debug)]
struct PerformanceConfig {
    pub grpc_batch_size: usize,
    pub enable_caching: bool,
}

#[cfg(feature = "grpc")]
impl PerformanceConfig {
    fn from_cli_args(args: &CliArgs) -> Self {
        Self {
            grpc_batch_size: args.grpc_batch_size,
            enable_caching: args.enable_cache,
        }
    }
}

/// Performance metrics tracking
#[cfg(feature = "grpc")]
#[derive(Debug)]
struct PerformanceMetrics {
    pub blocks_processed: u64,
    pub outputs_analyzed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub grpc_calls: u64,
    pub parallel_efficiency: f64,
    pub processing_time: Duration,
    pub start_time: Instant,
}

#[cfg(feature = "grpc")]
impl PerformanceMetrics {
    fn new() -> Self {
        Self {
            blocks_processed: 0,
            outputs_analyzed: 0,
            cache_hits: 0,
            cache_misses: 0,
            grpc_calls: 0,
            parallel_efficiency: 0.0,
            processing_time: Duration::from_secs(0),
            start_time: Instant::now(),
        }
    }

    fn print_summary(&self) {
        if self.processing_time.is_zero() {
            return;
        }

        println!("\n🎯 PERFORMANCE SUMMARY");
        println!("=====================");
        println!("⏱️  Total time: {:.2}s", self.processing_time.as_secs_f64());
        println!("🔢 Blocks processed: {}", self.blocks_processed);
        println!("🎯 Outputs analyzed: {}", self.outputs_analyzed);
        println!("📞 GRPC calls: {}", self.grpc_calls);
        
        if self.cache_hits + self.cache_misses > 0 {
            let cache_hit_rate = self.cache_hits as f64 / (self.cache_hits + self.cache_misses) as f64 * 100.0;
            println!("💾 Cache hits: {} ({:.1}%)", self.cache_hits, cache_hit_rate);
        }
        
        if self.parallel_efficiency > 0.0 {
            println!("⚡ Parallel efficiency: {:.1}x", self.parallel_efficiency);
        }
        
        if self.blocks_processed > 0 {
            let blocks_per_second = self.blocks_processed as f64 / self.processing_time.as_secs_f64();
            println!("🚀 Throughput: {:.1} blocks/second", blocks_per_second);
        }
    }
}

/// Cache for expensive operations
#[cfg(feature = "grpc")]
type ResultCache = Arc<RwLock<HashMap<Vec<u8>, CachedResult>>>;

#[cfg(feature = "grpc")]
#[derive(Clone, Debug)]
struct CachedResult {
    pub success: bool,
    pub value: Option<u64>,
    pub payment_id: Option<PaymentId>,
    pub timestamp: Instant,
}

// WalletTransaction and WalletState are now imported from the library

// WalletState implementation is now in the library

#[cfg(feature = "grpc")]
async fn scan_wallet_across_blocks(
    scanner: &mut GrpcBlockchainScanner,
    wallet: &Wallet,
    from_block: u64,
    to_block: u64,
    perf_config: &PerformanceConfig,
    specific_blocks: Option<Vec<u64>>,
) -> LightweightWalletResult<WalletState> {
    // Initialize performance metrics
    let mut metrics = PerformanceMetrics::new();
    
    // Initialize caches if enabled
    let range_proof_cache: ResultCache = Arc::new(RwLock::new(HashMap::new()));
    let _decryption_cache: ResultCache = Arc::new(RwLock::new(HashMap::new()));
    
    // Setup wallet keys
    let seed_phrase = wallet.export_seed_phrase()?;
    let encrypted_bytes = mnemonic_to_bytes(&seed_phrase)?;
    let cipher_seed = CipherSeed::from_enciphered_bytes(&encrypted_bytes, None)?;
    let entropy = cipher_seed.entropy();
    
    let entropy_array: [u8; 16] = entropy.try_into()
        .map_err(|_| KeyManagementError::key_derivation_failed("Invalid entropy length"))?;
    
    let view_key_raw = key_derivation::derive_private_key_from_entropy(
        &entropy_array, 
        "data encryption", 
        0
    )?;
    let view_key = PrivateKey::new(view_key_raw.as_bytes().try_into().expect("Should convert to array"));
    
    // Initialize range proof rewinding service
    let range_proof_service = RangeProofRewindService::new()?;
    
    // Initialize stealth address service for detecting stealth outputs
    let stealth_service = StealthAddressService::new();
    
    // Use Arc<Mutex<WalletState>> for thread safety
    let wallet_state = Arc::new(Mutex::new(WalletState::new()));
    
    // Determine which blocks to scan
    let blocks_to_scan: Vec<u64> = if let Some(specific_blocks) = specific_blocks {
        println!("🔍 Scanning {} specific blocks: {:?}", specific_blocks.len(), specific_blocks);
        specific_blocks
    } else {
        let block_range = to_block - from_block + 1;
        println!("🔍 Scanning block range {} to {} ({} blocks total)...", from_block, to_block, block_range);
        
        // Warning about scanning limitations
        if from_block > 1 {
            println!("⚠️  WARNING: Starting scan from block {} (not genesis)", from_block);
            println!("   📍 This will MISS any wallet outputs received before block {}", from_block);
            println!("   💡 For complete transaction history, consider scanning from genesis (--from-block 1)");
            println!("   🔄 Spent transactions may not be detected if their outputs were received earlier");
        }
        
        (from_block..=to_block).collect()
    };
    
    let total_blocks = blocks_to_scan.len();
    println!();
    
    
    let scan_start_time = Instant::now();
    
    // Process blocks using efficient batched GRPC calls
    println!("🚀 Using batched GRPC calls for optimal performance");
    println!("  • Batch size: {} blocks per GRPC call", perf_config.grpc_batch_size);
    println!("  • Caching: {}", if perf_config.enable_caching { "enabled" } else { "disabled" });
    println!("  • Single unified scan (output discovery + spending detection)");
    
    // Process blocks in batches
    for batch_start in (0..blocks_to_scan.len()).step_by(perf_config.grpc_batch_size) {
        let batch_end = std::cmp::min(batch_start + perf_config.grpc_batch_size, blocks_to_scan.len());
        let batch_heights: Vec<u64> = blocks_to_scan[batch_start..batch_end].to_vec();

        // Batch GRPC call - much more efficient!
        let blocks_info = match scanner.get_blocks_by_heights(batch_heights.clone()).await {
            Ok(blocks) => blocks,
            Err(e) => {
                println!("\n❌ Error fetching batch of blocks {:?}: {}", batch_heights, e);
                println!("   Error details: {:?}", e);
                
                // Ask user if they want to continue
                print!("   Continue with next batch? (y/n): ");
                std::io::Write::flush(&mut std::io::stdout()).unwrap();
                
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
                let choice = input.trim().to_lowercase();
                
                match choice.as_str() {
                    "y" | "yes" => {
                        println!("   ✅ Continuing with next batch...");
                        continue;
                    },
                    _ => {
                        println!("   🛑 Scan aborted by user");
                        return Err(e);
                    }
                }
            }
        };
        
        // Update metrics for batched call
        metrics.grpc_calls += 1; // One call for the entire batch!
        
        // Process each block in the batch with UNIFIED scanning
        for (block_index, block_info) in blocks_info.iter().enumerate() {
            let block_height = block_info.height;
            
            // Show enhanced progress with balance info for each block
            let global_block_index = batch_start + block_index + 1;
            {
                let state = wallet_state.lock().unwrap();
                let progress_bar = state.format_progress_bar(global_block_index as u64, total_blocks as u64, block_height, "🔄");
                print!("\r{}", progress_bar);
                std::io::Write::flush(&mut std::io::stdout()).unwrap();
            }
            
            // PHASE 1: Process outputs for wallet discovery (optimized order)
            for (output_index, output) in block_info.outputs.iter().enumerate() {
                let mut found_output = false;

                // STEP 1: Try one-sided detection first (most common output type)
                if let Some((value, payment_id)) = try_detect_one_sided_output(output, &view_key) {
                    {
                        let mut state = wallet_state.lock().unwrap();
                        state.add_received_output(
                            block_height,
                            output_index,
                            output.commitment().clone(),
                            value,
                            payment_id,
                            TransactionStatus::OneSidedConfirmed,
                            TransactionDirection::Inbound,
                            true, // One-sided payments are always mature
                        );
                    }
                    found_output = true;
                }
                
                if found_output {
                    continue;
                }
                
                // STEP 2: Try regular encrypted data decryption (standard wallet outputs)
                if let Some((value, payment_id)) = try_detect_regular_output(output, &view_key) {
                    {
                        let mut state = wallet_state.lock().unwrap();
                        state.add_received_output(
                            block_height,
                            output_index,
                            output.commitment().clone(),
                            value,
                            payment_id,
                            TransactionStatus::MinedConfirmed,
                            TransactionDirection::Inbound,
                            true, // Regular payments are always mature
                        );
                    }
                    found_output = true;
                }
                
                if found_output {
                    continue;
                }
                
                // STEP 3: Try stealth address detection (one-sided payments)
                if let Some((value, payment_id)) = try_detect_stealth_output(output, &view_key, &stealth_service) {
                    println!("\n🎭 Found STEALTH ADDRESS output in block {}, output {}: {} μT", 
                        block_height, output_index, value);
                    {
                        let mut state = wallet_state.lock().unwrap();
                        state.add_received_output(
                            block_height,
                            output_index,
                            output.commitment().clone(),
                            value,
                            payment_id,
                            TransactionStatus::OneSidedConfirmed, // Stealth addresses are one-sided
                            TransactionDirection::Inbound,
                            true, // One-sided payments are always mature
                        );
                    }
                    found_output = true;
                }
                
                if found_output {
                    continue;
                }
                
                // STEP 4: Range Proof Rewinding with caching optimization
                if let Some(value) = try_detect_range_proof_output(output, &entropy, &range_proof_service, &range_proof_cache, &perf_config, &mut metrics) {
                    {
                        let mut state = wallet_state.lock().unwrap();
                        state.add_received_output(
                            block_height,
                            output_index,
                            output.commitment().clone(),
                            value,
                            PaymentId::Empty,
                            TransactionStatus::OneSidedConfirmed,
                            TransactionDirection::Inbound,
                            true,
                        );
                    }
                    found_output = true;
                }
                
                if found_output {
                    continue;
                }
                
                // STEP 5: Check for coinbase outputs
                if let Some((coinbase_value, is_mature)) = try_detect_coinbase_output(output, &view_key, block_height) {
                    {
                        let mut state = wallet_state.lock().unwrap();
                        state.add_received_output(
                            block_height,
                            output_index,
                            output.commitment().clone(),
                            coinbase_value,
                            PaymentId::Empty,
                            if is_mature { 
                                TransactionStatus::CoinbaseConfirmed 
                            } else { 
                                TransactionStatus::CoinbaseUnconfirmed 
                            },
                            TransactionDirection::Inbound,
                            is_mature,
                        );
                    }
                    found_output = true;
                }
                
                if found_output {
                    continue;
                }
                
                // STEP 6: Try imported key derivation (for imported outputs)
                if let Some((value, payment_id)) = try_detect_imported_output_wrapper(output, block_height, output_index, &entropy_array) {
                    println!("\n💎 Found IMPORTED output in block {}, output {}: {} μT", 
                        block_height, output_index, value);
                    {
                        let mut state = wallet_state.lock().unwrap();
                        state.add_received_output(
                            block_height,
                            output_index,
                            output.commitment().clone(),
                            value,
                            payment_id,
                            TransactionStatus::Imported,
                            TransactionDirection::Inbound,
                            true, // Imported outputs are always mature
                        );
                    }
                }
            }
            
            // PHASE 2: Process inputs for spending detection (in the SAME block scan!)
            for (input_index, input) in block_info.inputs.iter().enumerate() {
                // Input commitment is already [u8; 32], convert directly to CompressedCommitment
                let input_commitment = CompressedCommitment::new(input.commitment);
                
                // Try to mark as spent in a thread-safe way
                {
                    let mut state = wallet_state.lock().unwrap();
                    if state.mark_output_spent(&input_commitment, block_height, input_index) {
                        // Successfully marked an output as spent and created outbound transaction
                        // No need to print for each one - just update the progress bar
                    }
                }
            }
            
            // Update metrics
            metrics.outputs_analyzed += block_info.outputs.len() as u64;
        }
    } // End of batch processing loop
    
    let scan_elapsed = scan_start_time.elapsed();
    
    // Update metrics
    metrics.processing_time = scan_elapsed;
    metrics.blocks_processed = total_blocks as u64;
    
    println!("\n✅ Unified scan complete in {:.2}s!", scan_elapsed.as_secs_f64());
    metrics.print_summary();
    
    // Show summary of what was found
    {
        let state = wallet_state.lock().unwrap();
        let (inbound_count, outbound_count, _) = state.get_direction_counts();
        println!("🎯 SCAN RESULTS:");
        println!("  📥 Found {} wallet outputs (inbound transactions)", inbound_count);
        println!("  📤 Found {} spending transactions (outbound transactions)", outbound_count);
        println!("  💰 Current balance: {:.6} T", state.get_balance() as f64 / 1_000_000.0);
    }
    
    // Extract the final wallet state
    let final_state = Arc::try_unwrap(wallet_state).unwrap().into_inner().unwrap();
    Ok(final_state)
}

#[cfg(feature = "grpc")]
fn display_wallet_activity(wallet_state: &WalletState, from_block: u64, to_block: u64) {
    let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
    let total_count = wallet_state.transactions.len();
    
    if total_count == 0 {
        println!("💡 No wallet activity found in blocks {} to {}", from_block, to_block);
        if from_block > 1 {
            println!("   ⚠️  Note: Scanning from block {} - wallet history before this block was not checked", from_block);
            println!("   💡 For complete history, try: cargo run --example scanner --features grpc -- --seed-phrase \"your seed phrase\" --from-block 1");
        }
        return;
    }
    
    println!("🏦 WALLET ACTIVITY SUMMARY");
    println!("========================");
    println!("Scan range: Block {} to {} ({} blocks)", from_block, to_block, to_block - from_block + 1);
    
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();
    println!("📥 Inbound:  {} transactions, {} μT ({:.6} T)", inbound_count, total_received, total_received as f64 / 1_000_000.0);
    println!("📤 Outbound: {} transactions, {} μT ({:.6} T)", outbound_count, total_spent, total_spent as f64 / 1_000_000.0);
    println!("💰 Current balance: {} μT ({:.6} T)", balance, balance as f64 / 1_000_000.0);
    println!("📊 Total activity: {} transactions", total_count);
    println!();
    
    if !wallet_state.transactions.is_empty() {
        println!("📋 TRANSACTION HISTORY (Chronological)");
        println!("=====================================");
        
        // Sort transactions by block height for chronological order
        let mut sorted_transactions: Vec<_> = wallet_state.transactions.iter().enumerate().collect();
        sorted_transactions.sort_by_key(|(_, tx)| tx.block_height);
        
        for (original_index, tx) in sorted_transactions {
            let direction_symbol = match tx.transaction_direction {
                TransactionDirection::Inbound => "📥",
                TransactionDirection::Outbound => "📤",
                TransactionDirection::Unknown => "❓",
            };
            
            let amount_display = match tx.transaction_direction {
                TransactionDirection::Inbound => format!("+{} μT", tx.value),
                TransactionDirection::Outbound => format!("-{} μT", tx.value),
                TransactionDirection::Unknown => format!("±{} μT", tx.value),
            };
            
            let maturity_indicator = if tx.transaction_status.is_coinbase() && !tx.is_mature {
                " (IMMATURE)"
            } else {
                ""
            };
            
            // Different display format for inbound vs outbound
            match tx.transaction_direction {
                TransactionDirection::Inbound => {
                    let status = if tx.is_spent {
                        format!("LATER SPENT in block {}", tx.spent_in_block.unwrap_or(0))
                    } else {
                        "UNSPENT".to_string()
                    };
                    
                    println!("{}. {} Block {}, Output #{}: {} ({:.6} T) - {} [{}{}]", 
                        original_index + 1,
                        direction_symbol,
                        tx.block_height,
                        tx.output_index.unwrap_or(0),
                        amount_display,
                        tx.value as f64 / 1_000_000.0,
                        status,
                        tx.transaction_status,
                        maturity_indicator
                    );
                },
                TransactionDirection::Outbound => {
                    println!("{}. {} Block {}, Input #{}: {} ({:.6} T) - SPENT [{}]", 
                        original_index + 1,
                        direction_symbol,
                        tx.block_height,
                        tx.input_index.unwrap_or(0),
                        amount_display,
                        tx.value as f64 / 1_000_000.0,
                        tx.transaction_status
                    );
                },
                TransactionDirection::Unknown => {
                    println!("{}. {} Block {}: {} ({:.6} T) - UNKNOWN [{}]", 
                        original_index + 1,
                        direction_symbol,
                        tx.block_height,
                        amount_display,
                        tx.value as f64 / 1_000_000.0,
                        tx.transaction_status
                    );
                }
            }
            
            // Show payment ID if not empty
            match &tx.payment_id {
                PaymentId::Empty => {},
                PaymentId::Open { user_data, .. } if !user_data.is_empty() => {
                    // Try to decode as UTF-8 string
                    if let Ok(text) = std::str::from_utf8(user_data) {
                        if text.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                            println!("   💬 Payment ID: \"{}\"", text);
                        } else {
                            println!("   💬 Payment ID (hex): {}", hex::encode(user_data));
                        }
                    } else {
                        println!("   💬 Payment ID (hex): {}", hex::encode(user_data));
                    }
                },
                PaymentId::TransactionInfo { user_data, .. } if !user_data.is_empty() => {
                    // Convert the binary data to utf8 string if possible otherwise print as hex    
                    if let Ok(text) = std::str::from_utf8(user_data) {
                        println!("   💬 Payment ID: \"{}\"", text);
                    } else {
                        println!("   💬 Payment ID (hex): {}", hex::encode(user_data));
                    }
                },
                _ => {
                    println!("   💬 Payment ID: {:#?}", tx.payment_id.user_data_as_string());
                }
            }
        }
        println!();
    }
    
    // Show balance breakdown
    let unspent_value = wallet_state.get_unspent_value();
        
    println!("💰 BALANCE BREAKDOWN");
    println!("===================");
    println!("Unspent outputs: {} ({:.6} T)", unspent_count, unspent_value as f64 / 1_000_000.0);
    println!("Spent outputs: {} ({:.6} T)", spent_count, total_spent as f64 / 1_000_000.0);
    println!("Total wallet activity: {} transactions", total_count);
    
    if from_block > 1 {
        println!();
        println!("⚠️  SCAN LIMITATION NOTE");
        println!("=======================");
        println!("Scanned from block {} (not genesis) - transactions before this may be missing", from_block);
        println!("For complete wallet history, scan from genesis: --from-block 1");
    }
    
    // Show detailed transaction analysis
    let (inbound_count, outbound_count, unknown_count) = wallet_state.get_direction_counts();
    let inbound_transactions = wallet_state.get_inbound_transactions();
    let outbound_transactions = wallet_state.get_outbound_transactions();
    
    // Calculate values for inbound and outbound
    let total_inbound_value: u64 = inbound_transactions.iter().map(|tx| tx.value).sum();
    let total_outbound_value: u64 = outbound_transactions.iter().map(|tx| tx.value).sum();
    
    if !wallet_state.transactions.is_empty() {
        println!();
        println!("📊 TRANSACTION FLOW ANALYSIS");
        println!("============================");
        println!("📥 Inbound:  {} transactions, {:.6} T total", inbound_count, total_inbound_value as f64 / 1_000_000.0);
        println!("📤 Outbound: {} transactions, {:.6} T total", outbound_count, total_outbound_value as f64 / 1_000_000.0);
        if unknown_count > 0 {
            println!("❓ Unknown:  {} transactions", unknown_count);
        }
        
        // Show transaction status breakdown
        let mut status_counts = std::collections::HashMap::new();
        let mut coinbase_immature = 0;
        for tx in &wallet_state.transactions {
            *status_counts.entry(tx.transaction_status).or_insert(0) += 1;
            if tx.transaction_status.is_coinbase() && !tx.is_mature {
                coinbase_immature += 1;
            }
        }
        
        println!();
        println!("📊 TRANSACTION STATUS BREAKDOWN");
        println!("==============================");
        for (status, count) in status_counts {
            if status.is_coinbase() && coinbase_immature > 0 {
                println!("{}: {} ({} immature)", status, count, coinbase_immature);
            } else {
                println!("{}: {}", status, count);
            }
        }
        
        // Show net flow
        let net_flow = total_inbound_value as i64 - total_outbound_value as i64;
        println!();
        println!("📊 NET FLOW SUMMARY");
        println!("==================");
        println!("Net flow: {:.6} T ({})", net_flow as f64 / 1_000_000.0, 
            if net_flow > 0 { "📈 Positive" } else if net_flow < 0 { "📉 Negative" } else { "⚖️  Neutral" });
        println!("Current balance: {:.6} T", wallet_state.get_balance() as f64 / 1_000_000.0);
    }
}

// Enhanced imported output detection function
#[cfg(feature = "grpc")]
fn try_detect_imported_output(
    output: &lightweight_wallet_libs::data_structures::transaction_output::LightweightTransactionOutput,
    block_height: u64,
    output_index: usize,
    entropy_array: &[u8; 16],
) -> Option<(u64, PaymentId, PrivateKey)> {
    // Try multiple import detection strategies
    
    // Strategy 1: Basic imported domain with indices - use IMPORTED_KEY_BRANCH constant
    for index in 0..20 {
        if let Ok(imported_key_raw) = key_derivation::derive_private_key_from_entropy(
            entropy_array,
            "imported", // Use the imported branch constant
            index
        ) {
            let imported_view_key = PrivateKey::new(imported_key_raw.as_bytes().try_into().ok()?);
            
            if !output.encrypted_data().as_bytes().is_empty() {
                // Try regular decryption
                if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_data(&imported_view_key, output.commitment(), output.encrypted_data()) {
                    return Some((value.as_u64(), payment_id, imported_view_key));
                }
                
                // Try one-sided decryption
                if !output.sender_offset_public_key().as_bytes().is_empty() {
                    if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_one_sided_data(&imported_view_key, output.commitment(), output.sender_offset_public_key(), output.encrypted_data()) {
                        return Some((value.as_u64(), payment_id, imported_view_key));
                    }
                }
            }
        }
    }
    
    // Strategy 2: Hash-based patterns (trying different hash sources)
    let commitment_hex = hex::encode(output.commitment().as_bytes());
    let potential_hashes = vec![
        commitment_hex,
        format!("{:x}", block_height),
        format!("{:x}", output_index),
        format!("{:016x}", block_height * 1000 + output_index as u64), // Composite hash - fix type mismatch
    ];
    
    for hash in potential_hashes {
        let pattern = format!("imported.{}", hash);
        for index in 0..5 {
            if let Ok(imported_key_raw) = key_derivation::derive_private_key_from_entropy(
                entropy_array,
                &pattern,
                index
            ) {
                let imported_view_key = PrivateKey::new(imported_key_raw.as_bytes().try_into().ok()?);
                
                if !output.encrypted_data().as_bytes().is_empty() {
                    // Try regular decryption
                    if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_data(&imported_view_key, output.commitment(), output.encrypted_data()) {
                        return Some((value.as_u64(), payment_id, imported_view_key));
                    }
                    
                    // Try one-sided decryption
                    if !output.sender_offset_public_key().as_bytes().is_empty() {
                        if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_one_sided_data(&imported_view_key, output.commitment(), output.sender_offset_public_key(), output.encrypted_data()) {
                            return Some((value.as_u64(), payment_id, imported_view_key));
                        }
                    }
                }
            }
        }
    }
    
    None
}

/// Try to detect one-sided transaction outputs (most common output type)
#[cfg(feature = "grpc")]
fn try_detect_one_sided_output(
    output: &lightweight_wallet_libs::data_structures::transaction_output::LightweightTransactionOutput,
    view_key: &PrivateKey,
) -> Option<(u64, PaymentId)> {
    // Skip if no encrypted data or sender offset
    if output.encrypted_data().as_bytes().is_empty() || output.sender_offset_public_key().as_bytes().is_empty() {
        return None;
    }
    
    // Try one-sided decryption (non-stealth one-sided payments)
    if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_one_sided_data(view_key, output.commitment(), output.sender_offset_public_key(), output.encrypted_data()) {
        return Some((value.as_u64(), payment_id));
    }
    
    None
}

/// Try to detect regular encrypted data outputs (standard wallet outputs)
#[cfg(feature = "grpc")]
fn try_detect_regular_output(
    output: &lightweight_wallet_libs::data_structures::transaction_output::LightweightTransactionOutput,
    view_key: &PrivateKey,
) -> Option<(u64, PaymentId)> {
    // Skip if no encrypted data
    if output.encrypted_data().as_bytes().is_empty() {
        return None;
    }
    
    // Try regular decryption
    if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_data(view_key, output.commitment(), output.encrypted_data()) {
        return Some((value.as_u64(), payment_id));
    }
    
    None
}

/// Try to detect stealth address outputs
#[cfg(feature = "grpc")]
fn try_detect_stealth_output(
    output: &lightweight_wallet_libs::data_structures::transaction_output::LightweightTransactionOutput,
    view_key: &PrivateKey,
    stealth_service: &StealthAddressService,
) -> Option<(u64, PaymentId)> {
    // Skip if no sender offset public key
    if output.sender_offset_public_key().as_bytes().is_empty() {
        return None;
    }
    
    // Try to recover stealth address spending key using view key and sender offset
    // This detects one-sided payments sent to stealth addresses
    if let Ok(shared_secret) = stealth_service.generate_shared_secret(view_key, output.sender_offset_public_key()) {
        // Try to derive encryption key from shared secret
        if let Ok(encryption_key) = stealth_service.shared_secret_to_output_encryption_key(&shared_secret) {
            // Try decryption with stealth-derived key
            if !output.encrypted_data().as_bytes().is_empty() {
                if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_data(&encryption_key, output.commitment(), output.encrypted_data()) {
                    return Some((value.as_u64(), payment_id));
                }
                
                // Also try one-sided decryption with stealth encryption key
                if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_one_sided_data(&encryption_key, output.commitment(), output.sender_offset_public_key(), output.encrypted_data()) {
                    return Some((value.as_u64(), payment_id));
                }
            }
        }
    }
    
    None
}

/// Try to detect range proof rewinding (with caching optimization)
#[cfg(feature = "grpc")]
fn try_detect_range_proof_output(
    output: &lightweight_wallet_libs::data_structures::transaction_output::LightweightTransactionOutput,
    entropy: &[u8],
    range_proof_service: &RangeProofRewindService,
    range_proof_cache: &ResultCache,
    perf_config: &PerformanceConfig,
    metrics: &mut PerformanceMetrics,
) -> Option<u64> {
    // Range Proof Rewinding with caching optimization
    if let Some(ref range_proof) = output.proof() {
        if !range_proof.bytes.is_empty() {
            let commitment_bytes = output.commitment().as_bytes().to_vec();
            
            // Check cache first if enabled
            if perf_config.enable_caching {
                let check_cache = |cache: &ResultCache, key: &[u8]| -> Option<CachedResult> {
                    let cache_read = cache.read().unwrap();
                    cache_read.get(key).cloned()
                };
                
                if let Some(cached) = check_cache(range_proof_cache, &commitment_bytes) {
                    if cached.success && cached.value.is_some() {
                        metrics.cache_hits += 1;
                        return cached.value;
                    }
                }
            }
            
            // Try rewinding with optimized nonce selection
            let nonce_count = 5;
            for nonce_index in 0..nonce_count {
                // Generate a rewind nonce from wallet entropy
                if let Ok(seed_nonce) = range_proof_service.generate_rewind_nonce(entropy, nonce_index) {
                    if let Ok(Some(rewind_result)) = range_proof_service.attempt_rewind(
                        &range_proof.bytes,
                        output.commitment(),
                        &seed_nonce,
                        Some(output.minimum_value_promise().as_u64())
                    ) {
                        // Cache the successful result
                        if perf_config.enable_caching {
                            let cache_result = |cache: &ResultCache, key: Vec<u8>, success: bool, value: Option<u64>, payment_id: Option<PaymentId>| {
                                let mut cache_write = cache.write().unwrap();
                                cache_write.insert(key, CachedResult {
                                    success,
                                    value,
                                    payment_id,
                                    timestamp: Instant::now(),
                                });
                            };
                            cache_result(range_proof_cache, commitment_bytes.clone(), true, Some(rewind_result.value), None);
                            metrics.cache_misses += 1;
                        }
                        
                        return Some(rewind_result.value);
                    }
                }
            }
        }
    }
    
    None
}

/// Try to detect coinbase outputs
#[cfg(feature = "grpc")]
fn try_detect_coinbase_output(
    output: &lightweight_wallet_libs::data_structures::transaction_output::LightweightTransactionOutput,
    view_key: &PrivateKey,
    block_height: u64,
) -> Option<(u64, bool)> {
    // Check for coinbase outputs
    if matches!(output.features().output_type, lightweight_wallet_libs::data_structures::wallet_output::LightweightOutputType::Coinbase) {
        let coinbase_value = output.minimum_value_promise().as_u64();
        if coinbase_value > 0 {
            let mut is_ours = false;
            
            if !output.encrypted_data().as_bytes().is_empty() {
                // Try regular decryption for ownership verification
                if let Ok((_value, _mask, _payment_id)) = EncryptedData::decrypt_data(view_key, output.commitment(), output.encrypted_data()) {
                    is_ours = true;
                }
                // Try one-sided decryption for ownership verification
                else if !output.sender_offset_public_key().as_bytes().is_empty() {
                    if let Ok((_value, _mask, _payment_id)) = EncryptedData::decrypt_one_sided_data(view_key, output.commitment(), output.sender_offset_public_key(), output.encrypted_data()) {
                        is_ours = true;
                    }
                }
            }
            
            // Only add to wallet if we can prove ownership through decryption
            if is_ours {
                let is_mature = block_height >= output.features().maturity;
                return Some((coinbase_value, is_mature));
            }
        }
    }
    
    None
}

/// Try to detect imported outputs
#[cfg(feature = "grpc")]
fn try_detect_imported_output_wrapper(
    output: &lightweight_wallet_libs::data_structures::transaction_output::LightweightTransactionOutput,
    block_height: u64,
    output_index: usize,
    entropy_array: &[u8; 16],
) -> Option<(u64, PaymentId)> {
    if let Some((value, payment_id, _imported_key)) = try_detect_imported_output(output, block_height, output_index, entropy_array) {
        return Some((value, payment_id));
    }
    None
}

#[cfg(feature = "grpc")]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🚀 Enhanced Tari Wallet Scanner");
    println!("===============================");

    // Parse CLI arguments
    let args = CliArgs::parse();

    // Create performance configuration from CLI args
    let mut perf_config = PerformanceConfig::from_cli_args(&args);

    println!("🔨 Creating wallet from seed phrase...");
    let wallet = Wallet::new_from_seed_phrase(&args.seed_phrase, None)?;
    println!("✅ Wallet created successfully");

    println!("🌐 Connecting to Tari base node...");
    let mut scanner = match GrpcScannerBuilder::new()
            .with_base_url(args.base_url.clone())
        .with_timeout(std::time::Duration::from_secs(30))
        .build().await 
    {
        Ok(scanner) => {
            println!("✅ Connected to Tari base node successfully");
            scanner
        },
        Err(e) => {
            eprintln!("❌ Failed to connect to Tari base node: {}", e);
            eprintln!("💡 Make sure tari_base_node is running with GRPC enabled on port 18142");
            return Err(e);
        }
    };

    // Get blockchain tip
    let tip_info = scanner.get_tip_info().await?;
    println!("📊 Current blockchain tip: block {}", tip_info.best_block_height);

    // Determine scan strategy and blocks
    let (from_block, to_block, specific_blocks) = if let Some(blocks) = args.blocks {
        // Scanning specific blocks
        let min_block = *blocks.iter().min().unwrap_or(&0);
        let max_block = *blocks.iter().max().unwrap_or(&0);
        println!("🎯 Scanning {} specific blocks (range {} to {})", blocks.len(), min_block, max_block);
        perf_config.grpc_batch_size = 1;
        (min_block, max_block, Some(blocks))
    } else {
        // Scanning block range
        let to_block = args.to_block.unwrap_or(tip_info.best_block_height);
        let wallet_birthday = args.from_block.unwrap_or(wallet.birthday());
        let from_block = std::cmp::max(wallet_birthday, 0);
        
        println!("📅 Wallet birthday: block {} (estimated)", from_block);
        println!("🎯 Scan range: blocks {} to {}", from_block, to_block);
        (from_block, to_block, None)
    };
    println!();

    // Perform the comprehensive scan
    let wallet_state = scan_wallet_across_blocks(&mut scanner, &wallet, from_block, to_block, &perf_config, specific_blocks).await?;
    
    // Display results
    display_wallet_activity(&wallet_state, from_block, to_block);
    
    println!("✅ Scan completed successfully!");
    
    Ok(())
}

#[cfg(not(feature = "grpc"))]
fn main() {
    eprintln!("This example requires the 'grpc' feature to be enabled.");
    eprintln!("Run with: cargo run --example scanner --features grpc");
    std::process::exit(1);
} 