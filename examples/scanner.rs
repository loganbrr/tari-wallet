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
//! - **Batch processing for improved performance (up to 100 blocks per batch)**
//! - **Graceful error handling with resume functionality**
//! - **Detailed performance profiling for optimization**
//!
//! ## Error Handling & Interruption
//! When GRPC errors occur (e.g., "message length too large"), the scanner will:
//! - Display the exact block height and error details
//! - Offer interactive options: Continue (y), Skip block (s), or Abort (n)
//! - Provide resume commands for easy restart from the failed point
//! - Example: `cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --from-block 25000 --to-block 30000`
//!
//! **Graceful Ctrl+C Support:**
//! - Press Ctrl+C to cleanly interrupt any scan
//! - Profiling data and partial results are preserved and displayed
//! - Automatic resume command generation for continuing from interruption point
//!
//! ## Usage
//! ```bash
//! # Scan with wallet from birthday to tip using seed phrase
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase here"
//!
//! # Scan using private view key (hex format, 64 characters)
//! cargo run --example scanner --features grpc -- --view-key "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab"
//!
//! # Scan specific range with view key
//! cargo run --example scanner --features grpc -- --view-key "your_view_key_here" --from-block 34920 --to-block 34930
//!
//! # Scan specific blocks only
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --blocks 1000,2000,5000,10000
//!
//! # Use custom base node URL
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --base-url "http://192.168.1.100:18142"
//!
//! # Quiet mode with JSON output (script-friendly)
//! cargo run --example scanner --features grpc -- --view-key "your_view_key" --quiet --format json
//!
//! # Summary output with minimal progress updates
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --format summary --progress-frequency 50
//!
//! # Enable detailed profiling output
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --profile
//!
//! # Resume from a specific block after error
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --from-block 25000 --to-block 30000
//!
//! # Show help
//! cargo run --example scanner --features grpc -- --help
//! ```
//!
//! ## View Key vs Seed Phrase
//! 
//! **Seed Phrase Mode:**
//! - Full wallet functionality
//! - Automatic wallet birthday detection
//! - Requires seed phrase security
//! 
//! **View Key Mode:**
//! - View-only access with encrypted data decryption
//! - Starts from genesis by default (can be overridden)
//! - More secure for monitoring purposes
//! - View key format: 64-character hex string (32 bytes)

#[cfg(feature = "grpc")]
use lightweight_wallet_libs::{
    scanning::{GrpcScannerBuilder, GrpcBlockchainScanner, BlockchainScanner},
    key_management::{key_derivation, seed_phrase::{mnemonic_to_bytes, CipherSeed}},
    wallet::Wallet,
    errors::{LightweightWalletResult},
    KeyManagementError,
    data_structures::{
        types::PrivateKey,
        payment_id::PaymentId,
        wallet_transaction::WalletState,
        transaction::TransactionDirection,
        block::Block,
    },
    utils::number::format_number,
};
#[cfg(feature = "grpc")]
use tari_utilities::ByteArray;
#[cfg(feature = "grpc")]
use tokio::time::Instant;
#[cfg(feature = "grpc")]
use tokio::signal;
#[cfg(feature = "grpc")]
use clap::Parser;
#[cfg(feature = "grpc")]
use num_cpus;


/// Enhanced Tari Wallet Scanner CLI
#[cfg(feature = "grpc")]
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Seed phrase for the wallet (required unless --view-key is provided)
    #[arg(short, long, help = "Seed phrase for the wallet")]
    seed_phrase: Option<String>,

    /// Private view key in hex format (alternative to seed phrase)
    #[arg(long, help = "Private view key in hex format (64 characters). Alternative to --seed-phrase")]
    view_key: Option<String>,

    /// Base URL for the Tari base node GRPC endpoint
    #[arg(short, long, default_value = "http://127.0.0.1:18142", help = "Base URL for Tari base node GRPC")]
    base_url: String,

    /// Starting block height for scanning
    #[arg(long, help = "Starting block height (defaults to wallet birthday or 0 for view-key mode)")]
    from_block: Option<u64>,

    /// Ending block height for scanning
    #[arg(long, help = "Ending block height (defaults to current tip)")]
    to_block: Option<u64>,

    /// Specific block heights to scan (comma-separated)
    #[arg(long, help = "Specific block heights to scan (comma-separated). If provided, overrides from-block and to-block", value_delimiter = ',')]
    blocks: Option<Vec<u64>>,

    /// Batch size for scanning
    #[arg(long, default_value = "10", help = "Batch size for scanning")]
    batch_size: usize,

    /// Progress update frequency
    #[arg(long, default_value = "10", help = "Update progress every N blocks")]
    progress_frequency: usize,

    /// Quiet mode - minimal output
    #[arg(short, long, help = "Quiet mode - only show essential information")]
    quiet: bool,

    /// Output format
    #[arg(long, default_value = "summary", help = "Output format: detailed, summary, json")]
    format: String,

    /// Enable detailed profiling output
    #[arg(long, help = "Enable detailed performance profiling")]
    profile: bool,
}

/// Configuration for wallet scanning
#[cfg(feature = "grpc")]
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub from_block: u64,
    pub to_block: u64,
    pub block_heights: Option<Vec<u64>>,
    pub progress_frequency: usize,
    pub quiet: bool,
    pub output_format: OutputFormat,
    pub batch_size: usize,
    pub enable_profiling: bool,
}

/// Output format options
#[cfg(feature = "grpc")]
#[derive(Debug, Clone)]
pub enum OutputFormat {
    Detailed,
    Summary,
    Json,
}

#[cfg(feature = "grpc")]
impl std::str::FromStr for OutputFormat {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "detailed" => Ok(OutputFormat::Detailed),
            "summary" => Ok(OutputFormat::Summary),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!("Invalid output format: {}. Valid options: detailed, summary, json", s)),
        }
    }
}

/// Wallet scanning context
#[cfg(feature = "grpc")]
pub struct ScanContext {
    pub view_key: PrivateKey,
    pub entropy: [u8; 16],
}

#[cfg(feature = "grpc")]
impl ScanContext {
    pub fn from_wallet(wallet: &Wallet) -> LightweightWalletResult<Self> {
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
        
        Ok(Self {
            view_key,
            entropy: entropy_array,
        })
    }

    pub fn from_view_key(view_key_hex: &str) -> LightweightWalletResult<Self> {
        // Parse the hex view key
        let view_key_bytes = hex::decode(view_key_hex)
            .map_err(|_| KeyManagementError::key_derivation_failed("Invalid hex format for view key"))?;
        
        if view_key_bytes.len() != 32 {
            return Err(KeyManagementError::key_derivation_failed(
                "View key must be exactly 32 bytes (64 hex characters)"
            ).into());
        }

        let view_key_array: [u8; 32] = view_key_bytes.try_into()
            .map_err(|_| KeyManagementError::key_derivation_failed("Failed to convert view key to array"))?;
        
        let view_key = PrivateKey::new(view_key_array);
        
        let entropy = [0u8; 16];
        
        Ok(Self {
            view_key,
            entropy,
        })
    }

    pub fn has_entropy(&self) -> bool {
        self.entropy != [0u8; 16]
    }
}

/// Progress tracking for scanning
#[cfg(feature = "grpc")]
pub struct ScanProgress {
    pub current_block: u64,
    pub total_blocks: usize,
    pub blocks_processed: usize,
    pub outputs_found: usize,
    pub inputs_found: usize,
    pub start_time: Instant,
}

#[cfg(feature = "grpc")]
impl ScanProgress {
    pub fn new(total_blocks: usize) -> Self {
        Self {
            current_block: 0,
            total_blocks,
            blocks_processed: 0,
            outputs_found: 0,
            inputs_found: 0,
            start_time: Instant::now(),
        }
    }

    pub fn update(&mut self, block_height: u64, found_outputs: usize, spent_outputs: usize) {
        self.current_block = block_height;
        self.blocks_processed += 1;
        self.outputs_found += found_outputs;
        self.inputs_found += spent_outputs;
    }

    pub fn display_progress(&self, quiet: bool, frequency: usize) {
        if quiet || self.blocks_processed % frequency != 0 {
            return;
        }

        let progress_percent = (self.blocks_processed as f64 / self.total_blocks as f64) * 100.0;
        let elapsed = self.start_time.elapsed();
        let blocks_per_sec = self.blocks_processed as f64 / elapsed.as_secs_f64();
        
        print!("\r🔍 Progress: {:.1}% ({}/{}) | Block {} | {:.1} blocks/s | Found: {} outputs, {} spent   ",
            progress_percent,
            self.blocks_processed,
            self.total_blocks,
            self.current_block,
            blocks_per_sec,
            self.outputs_found,
            self.inputs_found
        );
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
    }
}

#[cfg(feature = "grpc")]
pub struct BlockHeightRange {
    pub from_block: u64,
    pub to_block: u64,
    pub block_heights: Option<Vec<u64>>,
}

#[cfg(feature = "grpc")]
impl BlockHeightRange {
    pub fn new(from_block: u64, to_block: u64, block_heights: Option<Vec<u64>>) -> Self {
        Self { from_block, to_block, block_heights }
    }

    pub fn into_scan_config(self, args: &CliArgs) -> LightweightWalletResult<ScanConfig> {
        let output_format = args.format.parse()
            .map_err(|e: String| KeyManagementError::key_derivation_failed(&e))?;

        Ok(ScanConfig {
            from_block: self.from_block,
            to_block: self.to_block,
            block_heights: self.block_heights,
            progress_frequency: args.progress_frequency,
            quiet: args.quiet,
            output_format,
            batch_size: args.batch_size,
            enable_profiling: args.profile,
        })
    }
}

/// Handle errors during block scanning (updated for batch processing)
#[cfg(feature = "grpc")]
fn handle_scan_error(
    error_block_height: u64,
    remaining_blocks: &[u64],
    has_specific_blocks: bool,
    to_block: u64,
) -> bool {
    // Ask user if they want to continue
    print!("   Continue scanning remaining blocks? (y/n/s=skip this batch/block): ");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false; // Abort on input error
    }
    let choice = input.trim().to_lowercase();
    
    match choice.as_str() {
        "y" | "yes" => {
            println!("   ✅ Continuing scan from next batch/block...");
            true // Continue
        },
        "s" | "skip" => {
            println!("   ⏭️  Skipping problematic batch/block and continuing...");
            true // Continue (skip this batch/block)
        },
        _ => {
            println!("   🛑 Scan aborted by user at block {}", format_number(error_block_height));
            println!("\n💡 To resume from this point, run:");
            if has_specific_blocks {
                let remaining_blocks_str: Vec<String> = remaining_blocks.iter().map(|b| b.to_string()).collect();
                if remaining_blocks_str.len() <= 20 {
                    println!("   cargo run --example scanner --features grpc -- --seed-phrase \"your seed phrase\" --blocks {}", 
                        remaining_blocks_str.join(","));
                } else {
                    // For large lists, show range instead
                    let first_block = remaining_blocks.first().unwrap_or(&error_block_height);
                    let last_block = remaining_blocks.last().unwrap_or(&to_block);
                    println!("   cargo run --example scanner --features grpc -- --seed-phrase \"your seed phrase\" --from-block {} --to-block {}", format_number(*first_block), format_number(*last_block));
                }
            } else {
                println!("   cargo run --example scanner --features grpc -- --seed-phrase \"your seed phrase\" --from-block {} --to-block {}", format_number(error_block_height), format_number(to_block));
            }
            false // Abort
        }
    }
}

/// Result type that can indicate if scan was interrupted
#[cfg(feature = "grpc")]
pub enum ScanResult {
    Completed(WalletState, ProfileData),
    Interrupted(WalletState, ProfileData),
}

/// Core scanning logic - simplified and focused with batch processing
#[cfg(feature = "grpc")]
async fn scan_wallet_across_blocks_with_cancellation(
    scanner: &mut GrpcBlockchainScanner,
    scan_context: &ScanContext,
    config: &ScanConfig,
    cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> LightweightWalletResult<ScanResult> {
    let has_specific_blocks = config.block_heights.is_some();
    let block_heights = config.block_heights.clone().unwrap_or_else(|| {
        (config.from_block..=config.to_block).collect()
    });

    if !config.quiet {
        display_scan_info(&config, &block_heights, has_specific_blocks);
    }

    let mut wallet_state = WalletState::new();
    let _progress = ScanProgress::new(block_heights.len());
    let batch_size = config.batch_size;
    
    // Initialize profiling
    let mut profile_data = ProfileData::new();
    let scan_start_time = Instant::now();

    // Process blocks in batches
    for (batch_index, batch_heights) in block_heights.chunks(batch_size).enumerate() {
        // Check for cancellation at the start of each batch
        if *cancel_rx.borrow() {
            if !config.quiet {
                println!("\n🛑 Scan cancelled - returning partial results...");
            }
            profile_data.total_scan_time = scan_start_time.elapsed();
            return Ok(ScanResult::Interrupted(wallet_state, profile_data));
        }
        
        let batch_start_index = batch_index * batch_size;
        let batch_start_time = Instant::now();
        
        // Record memory usage if profiling is enabled
        if config.enable_profiling {
            profile_data.record_memory_usage();
        }
        
        // Display progress at the start of each batch
        if !config.quiet && batch_index % config.progress_frequency == 0 {
            let progress_bar = wallet_state.format_progress_bar(
                batch_start_index as u64 + 1,
                block_heights.len() as u64,
                batch_heights[0],
                "Scanning"
            );
            print!("\r{}", progress_bar);
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
        }
        
        // Time the GRPC call to fetch blocks
        let grpc_start_time = Instant::now();
        let batch_results = match scanner.get_blocks_by_heights(batch_heights.to_vec()).await {
            Ok(blocks) => {
                let grpc_duration = grpc_start_time.elapsed();
                if config.enable_profiling {
                    profile_data.add_grpc_time(grpc_duration);
                    if !config.quiet {
                        println!("\n⏱️  GRPC batch fetch: {:.3}s for {} blocks", 
                            grpc_duration.as_secs_f64(), format_number(batch_heights.len()));
                    }
                }
                blocks
            },
            Err(e) => {
                let grpc_duration = grpc_start_time.elapsed();
                if config.enable_profiling {
                    profile_data.add_grpc_time(grpc_duration);
                }
                println!("\n❌ Error scanning batch starting at block {}: {}", batch_heights[0], e);
                println!("   Batch heights: {:?}", batch_heights);
                println!("   Error details: {:?}", e);
                println!("   GRPC call took: {:.3}s before failing", grpc_duration.as_secs_f64());
                
                let remaining_blocks = &block_heights[batch_start_index..];
                if handle_scan_error(batch_heights[0], remaining_blocks, has_specific_blocks, config.to_block) {
                    // Check for cancellation before continuing
                    if *cancel_rx.borrow() {
                        profile_data.total_scan_time = scan_start_time.elapsed();
                        return Ok(ScanResult::Interrupted(wallet_state, profile_data));
                    }
                    continue;  // Continue to next batch
                } else {
                    profile_data.total_scan_time = scan_start_time.elapsed();
                    return Err(e); // Abort
                }
            }
        };

        // Process each block in the batch
        for (block_index_in_batch, block_height) in batch_heights.iter().enumerate() {
            let global_block_index = batch_start_index + block_index_in_batch;
            
            // Find the corresponding block info from the batch results
            let block_info = match batch_results.iter().find(|b| b.height == *block_height) {
                Some(block) => block.clone(),
                None => {
                    if !config.quiet {
                        println!("\n⚠️  Block {} not found in batch, skipping...", block_height);
                    }
                    continue;
                }
            };
            
            // Time block processing with detailed breakdown
            let block_start_time = Instant::now();
            
            // Process block using the Block struct
            let block = Block::from_block_info(block_info);
            
            // Time output processing separately
            let output_start_time = Instant::now();
            let found_outputs = block.process_outputs(&scan_context.view_key, &scan_context.entropy, &mut wallet_state);
            let output_duration = output_start_time.elapsed();
            
            // Time input processing separately
            let input_start_time = Instant::now();
            let spent_outputs = block.process_inputs(&mut wallet_state);
            let input_duration = input_start_time.elapsed();
            
            let scan_result = match (found_outputs, spent_outputs) {
                (Ok(found), Ok(spent)) => Ok((found, spent)),
                (Err(e), _) | (_, Err(e)) => Err(e),
            };
            
            let (_found_outputs, _spent_outputs) = match scan_result {
                Ok(result) => {
                    let block_duration = block_start_time.elapsed();
                    if config.enable_profiling {
                        profile_data.add_block_processing_time(*block_height, block_duration);
                        if !config.quiet && (result.0 > 0 || result.1 > 0 || block_duration.as_secs_f64() > 0.05) {
                            // let parallel_indicator = if cfg!(feature = "parallel") { "⚡" } else { "🔄" };
                            // println!("\n🎯 Block {}: {} outputs found, {} outputs spent ({}s total)", 
                            //     block_height, result.0, result.1, block_duration.as_secs_f64());
                            // println!("   {} {} outputs in {:.3}s, {} inputs in {:.3}s (parallel: {})", 
                            //     parallel_indicator,
                            //     block.output_count(), 
                            //     output_duration.as_secs_f64(),
                            //     block.input_count(),
                            //     input_duration.as_secs_f64(),
                            //     cfg!(feature = "parallel")
                            // );
                        }
                    } else if !config.quiet && (result.0 > 0 || result.1 > 0) {
                            // println!("\n🎯 Block {}: {} outputs found, {} outputs spent", 
                            //     block_height, result.0, result.1);
                    }
                    result
                },
                Err(e) => {
                    let block_duration = block_start_time.elapsed();
                    if config.enable_profiling {
                        profile_data.add_block_processing_time(*block_height, block_duration);
                    }
                    println!("\n❌ Error processing block {}: {}", block_height, e);
                    println!("   Block height: {}", block_height);
                    println!("   Error details: {:?}", e);
                    println!("   Block processing took: {:.3}s before failing", block_duration.as_secs_f64());
                    
                    let remaining_blocks = &block_heights[global_block_index..];
                    if handle_scan_error(*block_height, remaining_blocks, has_specific_blocks, config.to_block) {
                        // Check for cancellation before continuing
                        if *cancel_rx.borrow() {
                            profile_data.total_scan_time = scan_start_time.elapsed();
                            return Ok(ScanResult::Interrupted(wallet_state, profile_data));
                        }
                        continue;  // Continue to next block
                    } else {
                        profile_data.total_scan_time = scan_start_time.elapsed();
                        return Err(e); // Abort
                    }
                }
            };
        }

        // Record batch processing time
        let batch_duration = batch_start_time.elapsed();
        if config.enable_profiling {
            profile_data.add_batch_time(batch_duration);
            if !config.quiet {
                        println!("\n⏱️  Batch {}: {:.3}s total ({} blocks, avg: {:.3}s per block)", 
            format_number(batch_index + 1), 
            batch_duration.as_secs_f64(),
            format_number(batch_heights.len()),
            batch_duration.as_secs_f64() / batch_heights.len() as f64
        );
            }
        }

        // Update progress display after processing each batch
        if !config.quiet {
            let processed_blocks = std::cmp::min(batch_start_index + batch_size, block_heights.len());
            let progress_bar = wallet_state.format_progress_bar(
                processed_blocks as u64,
                block_heights.len() as u64,
                batch_heights.last().cloned().unwrap_or(0),
                if processed_blocks == block_heights.len() { "Complete" } else { "Scanning" }
            );
            print!("\r{}", progress_bar);
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
        }
    }

    // Record total scan time
    profile_data.total_scan_time = scan_start_time.elapsed();

    if !config.quiet {
        // Ensure final progress bar shows 100%
        let final_progress_bar = wallet_state.format_progress_bar(
            block_heights.len() as u64,
            block_heights.len() as u64,
            block_heights.last().cloned().unwrap_or(0),
            "Complete"
        );
        println!("\r{}", final_progress_bar);
        
        let scan_elapsed = profile_data.total_scan_time;
        let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();
        println!("\n✅ Scan complete in {:.2}s!", scan_elapsed.as_secs_f64());
        println!("📊 Total: {} outputs found, {} outputs spent", format_number(inbound_count), format_number(outbound_count));
    }

    Ok(ScanResult::Completed(wallet_state, profile_data))
}

/// Display scan configuration information
#[cfg(feature = "grpc")]
fn display_scan_info(config: &ScanConfig, block_heights: &[u64], has_specific_blocks: bool) {
    if has_specific_blocks {
        println!("🔍 Scanning {} specific blocks: {:?}", format_number(block_heights.len()), 
            if block_heights.len() <= 10 { 
                block_heights.iter().map(|h| format_number(*h)).collect::<Vec<_>>().join(", ")
            } else {
                format!("{}..{} and {} others", format_number(block_heights[0]), format_number(*block_heights.last().unwrap()), format_number(block_heights.len() - 2))
            });
    } else {
        let block_range = config.to_block - config.from_block + 1;
        println!("🔍 Scanning blocks {} to {} ({} blocks total)...", 
            format_number(config.from_block), format_number(config.to_block), format_number(block_range));
    }

    // Warning about scanning limitations
    if config.from_block > 1 && !has_specific_blocks {
        println!("⚠️  WARNING: Starting scan from block {} (not genesis)", format_number(config.from_block));
        println!("   📍 This will MISS any wallet outputs received before block {}", format_number(config.from_block));
        println!("   💡 For complete transaction history, consider scanning from genesis (--from-block 1)");
    }
    println!();
}

#[cfg(feature = "grpc")]
fn display_wallet_activity(wallet_state: &WalletState, from_block: u64, to_block: u64) {
    let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
    let total_count = wallet_state.transactions.len();
    
    if total_count == 0 {
        println!("💡 No wallet activity found in blocks {} to {}", format_number(from_block), format_number(to_block));
        if from_block > 1 {
            println!("   ⚠️  Note: Scanning from block {} - wallet history before this block was not checked", format_number(from_block));
            println!("   💡 For complete history, try: cargo run --example scanner --features grpc -- --seed-phrase \"your seed phrase\" --from-block 1");
        }
        return;
    }
    
    println!("🏦 WALLET ACTIVITY SUMMARY");
    println!("========================");
    println!("Scan range: Block {} to {} ({} blocks)", format_number(from_block), format_number(to_block), format_number(to_block - from_block + 1));
    
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();
    println!("📥 Inbound:  {} transactions, {} μT ({:.6} T)", format_number(inbound_count), format_number(total_received), total_received as f64 / 1_000_000.0);
    println!("📤 Outbound: {} transactions, {} μT ({:.6} T)", format_number(outbound_count), format_number(total_spent), total_spent as f64 / 1_000_000.0);
    println!("💰 Current balance: {} μT ({:.6} T)", format_number(balance), balance as f64 / 1_000_000.0);
    println!("📊 Total activity: {} transactions", format_number(total_count));
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
                    
                    // println!("{}. {} Block {}, Output #{}: {} ({:.6} T) - {} [{}{}]", 
                    //     original_index + 1,
                    //     direction_symbol,
                    //     tx.block_height,
                    //     tx.output_index.unwrap_or(0),
                    //     amount_display,
                    //     tx.value as f64 / 1_000_000.0,
                    //     status,
                    //     tx.transaction_status,
                    //     maturity_indicator
                    // );
                },
                TransactionDirection::Outbound => {
                    println!("{}. {} Block {}, Input #{}: {} ({:.6} T) - SPENT [{}]", 
                        format_number(original_index + 1),
                        direction_symbol,
                        format_number(tx.block_height),
                        format_number(tx.input_index.unwrap_or(0)),
                        amount_display,
                        tx.value as f64 / 1_000_000.0,
                        tx.transaction_status
                    );
                },
                TransactionDirection::Unknown => {
                    println!("{}. {} Block {}: {} ({:.6} T) - UNKNOWN [{}]", 
                        format_number(original_index + 1),
                        direction_symbol,
                        format_number(tx.block_height),
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
    println!("Unspent outputs: {} ({:.6} T)", format_number(unspent_count), unspent_value as f64 / 1_000_000.0);
    println!("Spent outputs: {} ({:.6} T)", format_number(spent_count), total_spent as f64 / 1_000_000.0);
    println!("Total wallet activity: {} transactions", format_number(total_count));
    
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
        println!("📥 Inbound:  {} transactions, {:.6} T total", format_number(inbound_count), total_inbound_value as f64 / 1_000_000.0);
        println!("📤 Outbound: {} transactions, {:.6} T total", format_number(outbound_count), total_outbound_value as f64 / 1_000_000.0);
        if unknown_count > 0 {
            println!("❓ Unknown:  {} transactions", format_number(unknown_count));
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
                println!("{}: {} ({} immature)", status, format_number(count), format_number(coinbase_immature));
            } else {
                println!("{}: {}", status, format_number(count));
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

#[cfg(feature = "grpc")]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = CliArgs::parse();

    // Validate input arguments
    match (&args.seed_phrase, &args.view_key) {
        (Some(_), Some(_)) => {
            eprintln!("❌ Error: Cannot specify both --seed-phrase and --view-key. Choose one.");
            std::process::exit(1);
        },
        (None, None) => {
            eprintln!("❌ Error: Must specify either --seed-phrase or --view-key.");
            eprintln!("💡 Use --help for usage information.");
            std::process::exit(1);
        },
        _ => {} // Valid: exactly one is provided
    }

    if !args.quiet {
        println!("🚀 Enhanced Tari Wallet Scanner");
        println!("===============================");
    }

    // Create scan context based on input method
    let (scan_context, default_from_block) = if let Some(seed_phrase) = &args.seed_phrase {
        if !args.quiet {
            println!("🔨 Creating wallet from seed phrase...");
        }
        let wallet = Wallet::new_from_seed_phrase(seed_phrase, None)?;
        let scan_context = ScanContext::from_wallet(&wallet)?;
        let default_from_block = wallet.birthday();
        (scan_context, default_from_block)
    } else if let Some(view_key_hex) = &args.view_key {
        if !args.quiet {
            println!("🔑 Creating scan context from view key...");
            if !args.quiet {
                println!("⚠️  Note: Range proof rewinding will be limited without seed entropy");
            }
        }
        let scan_context = ScanContext::from_view_key(view_key_hex)?;
        let default_from_block = 0; // Start from genesis when using view key only
        (scan_context, default_from_block)
    } else {
        unreachable!("Validation above ensures exactly one option is provided");
    };

    // Connect to base node
    if !args.quiet {
        println!("🌐 Connecting to Tari base node...");
    }
    let mut scanner = GrpcScannerBuilder::new()
        .with_base_url(args.base_url.clone())
        .with_timeout(std::time::Duration::from_secs(30))
        .build().await
        .map_err(|e| {
            if !args.quiet {
                eprintln!("❌ Failed to connect to Tari base node: {}", e);
                eprintln!("💡 Make sure tari_base_node is running with GRPC enabled on port 18142");
            }
            e
        })?;

    if !args.quiet {
        println!("✅ Connected to Tari base node successfully");
    }

    // Get blockchain tip and determine scan range
    let tip_info = scanner.get_tip_info().await?;
    if !args.quiet {
        println!("📊 Current blockchain tip: block {}", format_number(tip_info.best_block_height));
    }

    let to_block = args.to_block.unwrap_or(tip_info.best_block_height);
    let from_block = args.from_block.unwrap_or(default_from_block);

    let block_height_range = BlockHeightRange::new(from_block, to_block, args.blocks.clone());
    let config = block_height_range.into_scan_config(&args)?;

    // Setup cancellation mechanism
    let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
    
    // Setup ctrl-c handling  
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
        let _ = cancel_tx.send(true);
    };
    
    // Perform the scan with cancellation support
    let scan_result = tokio::select! {
        result = scan_wallet_across_blocks_with_cancellation(&mut scanner, &scan_context, &config, &mut cancel_rx) => {
            Some(result)
        }
        _ = ctrl_c => {
            if !args.quiet {
                println!("\n\n🛑 Scan interrupted by user (Ctrl+C)");
                println!("📊 Waiting for current batch to complete...\n");
            }
            // Give a moment for the scan to notice the cancellation
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            None
        }
    };
    
    match scan_result {
        Some(Ok(ScanResult::Completed(wallet_state, profile_data))) => {
            // Display results based on output format
            match config.output_format {
                OutputFormat::Json => display_json_results(&wallet_state),
                OutputFormat::Summary => display_summary_results(&wallet_state, &config),
                OutputFormat::Detailed => display_wallet_activity(&wallet_state, config.from_block, config.to_block),
            }
            
            // Display profiling information if enabled
            if config.enable_profiling {
                profile_data.display_profile(config.quiet);
                profile_data.display_recommendations(config.quiet);
            }
            
            if !args.quiet {
                println!("✅ Scan completed successfully!");
            }
        }
        Some(Ok(ScanResult::Interrupted(wallet_state, profile_data))) => {
            if !args.quiet {
                println!("⚠️  Scan was interrupted but collected partial data:\n");
            }
            
            // Display partial results based on output format
            match config.output_format {
                OutputFormat::Json => display_json_results(&wallet_state),
                OutputFormat::Summary => display_summary_results(&wallet_state, &config),
                OutputFormat::Detailed => display_wallet_activity(&wallet_state, config.from_block, config.to_block),
            }
            
            // Display profiling information (especially valuable for interrupted scans)
            if config.enable_profiling {
                profile_data.display_profile(config.quiet);
                profile_data.display_recommendations(config.quiet);
                if !args.quiet {
                    println!("\n💡 This partial profiling data can help optimize future scans!");
                }
            }
            
            if !args.quiet {
                println!("\n🔄 To resume scanning from where you left off, use:");
                println!("   cargo run --example scanner --features grpc -- <your-options> --from-block {}", 
                    format_number(wallet_state.transactions.iter()
                        .map(|tx| tx.block_height)
                        .max()
                        .map(|h| h + 1)
                        .unwrap_or(config.from_block))
                );
            }
            std::process::exit(130); // Standard exit code for SIGINT
        }
        Some(Err(e)) => {
            if !args.quiet {
                eprintln!("❌ Scan failed: {}", e);
            }
            return Err(e);
        }
        None => {
            // Should not happen with our new implementation, but handle gracefully
            if !args.quiet {
                println!("💡 Scan was interrupted before completion.");
                println!("⚡ To resume, use the same command with appropriate --from-block parameter.");
            }
            std::process::exit(130); // Standard exit code for SIGINT
        }
    }
    
    Ok(())
}

/// Display results in JSON format
#[cfg(feature = "grpc")]
fn display_json_results(wallet_state: &WalletState) {
    // Simple JSON-like output for now
    let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();
    
        println!("{{");
    println!("  \"summary\": {{");
    println!("    \"total_transactions\": {},", format_number(wallet_state.transactions.len()));
    println!("    \"inbound_count\": {},", format_number(inbound_count));
    println!("    \"outbound_count\": {},", format_number(outbound_count));
    println!("    \"total_received\": {},", format_number(total_received));
    println!("    \"total_spent\": {},", format_number(total_spent));
    println!("    \"current_balance\": {},", format_number(balance));
    println!("    \"unspent_outputs\": {},", format_number(unspent_count));
    println!("    \"spent_outputs\": {}", format_number(spent_count));
    println!("  }}");
    println!("}}"); 
}

/// Display summary results
#[cfg(feature = "grpc")]
fn display_summary_results(wallet_state: &WalletState, config: &ScanConfig) {
    let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();
    
    println!("📊 WALLET SCAN SUMMARY");
    println!("=====================");
    println!("Scan range: Block {} to {}", format_number(config.from_block), format_number(config.to_block));
    println!("Total transactions: {}", format_number(wallet_state.transactions.len()));
    println!("Inbound: {} transactions ({:.6} T)", format_number(inbound_count), total_received as f64 / 1_000_000.0);
    println!("Outbound: {} transactions ({:.6} T)", format_number(outbound_count), total_spent as f64 / 1_000_000.0);
    println!("Current balance: {:.6} T", balance as f64 / 1_000_000.0);
    println!("Unspent outputs: {}", format_number(unspent_count));
    println!("Spent outputs: {}", format_number(spent_count));
}

/// Performance profiling data
#[cfg(feature = "grpc")]
#[derive(Debug, Default)]
pub struct ProfileData {
    pub total_scan_time: std::time::Duration,
    pub grpc_call_times: Vec<std::time::Duration>,
    pub block_processing_times: Vec<(u64, std::time::Duration)>,
    pub batch_processing_times: Vec<std::time::Duration>,
    pub total_grpc_time: std::time::Duration,
    pub total_processing_time: std::time::Duration,
    pub memory_usage: Vec<usize>,
}

#[cfg(feature = "grpc")]
impl ProfileData {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_grpc_time(&mut self, duration: std::time::Duration) {
        self.grpc_call_times.push(duration);
        self.total_grpc_time += duration;
    }

    pub fn add_block_processing_time(&mut self, block_height: u64, duration: std::time::Duration) {
        self.block_processing_times.push((block_height, duration));
        self.total_processing_time += duration;
    }

    pub fn add_batch_time(&mut self, duration: std::time::Duration) {
        self.batch_processing_times.push(duration);
    }

    pub fn record_memory_usage(&mut self) {
        // Simple memory estimation based on current process
        #[cfg(target_os = "linux")]
        {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("VmRSS:") {
                        if let Some(kb_str) = line.split_whitespace().nth(1) {
                            if let Ok(kb) = kb_str.parse::<usize>() {
                                self.memory_usage.push(kb * 1024); // Convert to bytes
                                break;
                            }
                        }
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Fallback for non-Linux systems - just record timestamp
            self.memory_usage.push(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as usize);
        }
    }

    pub fn display_profile(&self, quiet: bool) {
        if quiet {
            return;
        }

        println!("\n📊 PERFORMANCE PROFILE");
        println!("======================");
        println!("Total scan time: {:.3}s", self.total_scan_time.as_secs_f64());
        println!("Total GRPC time: {:.3}s ({:.1}%)", 
            self.total_grpc_time.as_secs_f64(),
            (self.total_grpc_time.as_secs_f64() / self.total_scan_time.as_secs_f64()) * 100.0
        );
        println!("Total processing time: {:.3}s ({:.1}%)", 
            self.total_processing_time.as_secs_f64(),
            (self.total_processing_time.as_secs_f64() / self.total_scan_time.as_secs_f64()) * 100.0
        );

        if !self.grpc_call_times.is_empty() {
            let avg_grpc = self.total_grpc_time.as_secs_f64() / self.grpc_call_times.len() as f64;
            let max_grpc = self.grpc_call_times.iter().max().unwrap().as_secs_f64();
            let min_grpc = self.grpc_call_times.iter().min().unwrap().as_secs_f64();
            println!("GRPC calls: {} total, avg: {:.3}s, min: {:.3}s, max: {:.3}s", 
                format_number(self.grpc_call_times.len()), avg_grpc, min_grpc, max_grpc);
        }

        if !self.block_processing_times.is_empty() {
            let avg_processing = self.total_processing_time.as_secs_f64() / self.block_processing_times.len() as f64;
            let max_processing = self.block_processing_times.iter().map(|(_, d)| d).max().unwrap().as_secs_f64();
            let min_processing = self.block_processing_times.iter().map(|(_, d)| d).min().unwrap().as_secs_f64();
            println!("Block processing: {} blocks, avg: {:.3}s, min: {:.3}s, max: {:.3}s", 
                format_number(self.block_processing_times.len()), avg_processing, min_processing, max_processing);

            // Show slowest blocks
            let mut sorted_blocks = self.block_processing_times.clone();
            sorted_blocks.sort_by(|a, b| b.1.cmp(&a.1));
            if sorted_blocks.len() > 5 {
                println!("Slowest blocks:");
                for (block_height, duration) in sorted_blocks.iter().take(5) {
                    println!("  Block {}: {:.3}s", format_number(*block_height), duration.as_secs_f64());
                }
            }
        }

        if !self.batch_processing_times.is_empty() {
            let avg_batch = self.batch_processing_times.iter().sum::<std::time::Duration>().as_secs_f64() / self.batch_processing_times.len() as f64;
            let max_batch = self.batch_processing_times.iter().max().unwrap().as_secs_f64();
            let min_batch = self.batch_processing_times.iter().min().unwrap().as_secs_f64();
            println!("Batch processing: {} batches, avg: {:.3}s, min: {:.3}s, max: {:.3}s", 
                format_number(self.batch_processing_times.len()), avg_batch, min_batch, max_batch);
        }

        // Calculate overhead (time not accounted for by GRPC or processing)
        let accounted_time = self.total_grpc_time + self.total_processing_time;
        let overhead = self.total_scan_time.saturating_sub(accounted_time);
        if overhead.as_secs_f64() > 0.1 {
            println!("Overhead/Other: {:.3}s ({:.1}%)", 
                overhead.as_secs_f64(),
                (overhead.as_secs_f64() / self.total_scan_time.as_secs_f64()) * 100.0
            );
        }

        if !self.memory_usage.is_empty() && cfg!(target_os = "linux") {
            let max_mem = self.memory_usage.iter().max().unwrap_or(&0);
            let min_mem = self.memory_usage.iter().min().unwrap_or(&0);
            println!("Memory usage: min: {:.1} MB, max: {:.1} MB", 
                *min_mem as f64 / 1024.0 / 1024.0,
                *max_mem as f64 / 1024.0 / 1024.0
            );
        }
    }

    pub fn display_recommendations(&self, quiet: bool) {
        if quiet {
            return;
        }

        println!("\n💡 PERFORMANCE RECOMMENDATIONS");
        println!("==============================");

        let grpc_percentage = (self.total_grpc_time.as_secs_f64() / self.total_scan_time.as_secs_f64()) * 100.0;
        let processing_percentage = (self.total_processing_time.as_secs_f64() / self.total_scan_time.as_secs_f64()) * 100.0;

        if grpc_percentage > 60.0 {
            println!("🌐 GRPC calls are the main bottleneck ({:.1}% of time)", grpc_percentage);
            println!("   → Consider increasing --batch-size to reduce number of GRPC calls");
            println!("   → Made {} GRPC calls total", format_number(self.grpc_call_times.len()));
            println!("   → Check network latency to the base node");
            println!("   → Consider using a local base node for faster access");
        } else if processing_percentage > 60.0 {
            println!("⚙️  Block processing is the main bottleneck ({:.1}% of time)", processing_percentage);
            
            #[cfg(feature = "parallel")]
            {
                println!("   ⚡ Parallel processing is ENABLED - good!");
                println!("   → Consider increasing --batch-size to give parallel workers more work");
                println!("   → Ensure running on a multi-core CPU for maximum benefit");
                println!("   → Large blocks with many outputs benefit most from parallelization");
            }
            
            #[cfg(not(feature = "parallel"))]
            {
                println!("   🔄 Parallel processing is DISABLED");
                println!("   → Compile with --features parallel for up to {}x speedup", format_number(num_cpus::get()));
                println!("   → Example: cargo run --example scanner --features 'grpc,parallel'");
                println!("   → Single-threaded crypto operations are CPU-intensive");
            }
            
            println!("   → Check if running on a fast CPU with good single-thread performance");
        } else {
            println!("⚖️  Balanced performance - no major bottlenecks detected");
            println!("   → GRPC: {:.1}%, Processing: {:.1}%", grpc_percentage, processing_percentage);
        }

        if !self.block_processing_times.is_empty() {
            let avg_processing = self.total_processing_time.as_secs_f64() / self.block_processing_times.len() as f64;
            if avg_processing > 0.1 {
                println!("🐌 Block processing is slow (avg: {:.3}s per block)", avg_processing);
                println!("   → Large blocks with many transactions take longer to process");
                println!("   → Consider scanning smaller ranges or using view-key mode");
            }
        }

        if !self.grpc_call_times.is_empty() {
            let avg_grpc = self.total_grpc_time.as_secs_f64() / self.grpc_call_times.len() as f64;
            if avg_grpc > 2.0 {
                println!("🌐 GRPC calls are very slow (avg: {:.3}s per batch)", avg_grpc);
                println!("   → Network issues or base node performance problems");
                println!("   → Try reducing --batch-size or using a different base node");
            }
        }
    }
}

#[cfg(not(feature = "grpc"))]
fn main() {
    eprintln!("This example requires the 'grpc' feature to be enabled.");
    eprintln!("Run with: cargo run --example scanner --features grpc");
    std::process::exit(1);
} 