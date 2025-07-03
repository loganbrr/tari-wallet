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
//! # Scan specific blocks only
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --blocks 1000,2000,5000,10000
//!
//! # Use custom base node URL
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --base-url "http://192.168.1.100:18142"
//!
//! # Resume from a specific block after error
//! cargo run --example scanner --features grpc -- --seed-phrase "your seed phrase" --from-block 25000 --to-block 30000
//!
//! # Show help
//! cargo run --example scanner --features grpc -- --help
//! ```

#[cfg(feature = "grpc")]
use lightweight_wallet_libs::{
    scanning::{GrpcScannerBuilder, GrpcBlockchainScanner, BlockchainScanner},
    key_management::{key_derivation, seed_phrase::{mnemonic_to_bytes, CipherSeed}},
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
use std::sync::{Arc, Mutex};
#[cfg(feature = "grpc")]
use tokio::time::Instant;
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

    /// Specific block heights to scan (comma-separated)
    #[arg(long, help = "Specific block heights to scan (comma-separated). If provided, overrides from-block and to-block", value_delimiter = ',')]
    blocks: Option<Vec<u64>>,
}

pub struct BlockHeightRange {
    pub from_block: u64,
    pub to_block: u64,
    pub block_heights: Option<Vec<u64>>,
}

impl BlockHeightRange {
    pub fn new(from_block: u64, to_block: u64, block_heights: Option<Vec<u64>>) -> Self {
        Self { from_block, to_block, block_heights }
    }
}

#[cfg(feature = "grpc")]
async fn scan_wallet_across_blocks(
    scanner: &mut GrpcBlockchainScanner,
    wallet: &Wallet,
    block_height_range: BlockHeightRange,
) -> LightweightWalletResult<WalletState> {
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
    
    // Generate derived keys for script pattern matching
    // For this example, we'll derive a few keys from the wallet entropy  
    let _derived_keys: Vec<RistrettoPublicKey> = Vec::new();
    for i in 0..10 { // Generate 10 derived keys for testing
        let _derived_key_raw = key_derivation::derive_private_key_from_entropy(
            &entropy_array,
            "script_key", 
            i
        )?;
        let _derived_private_key = PrivateKey::new(_derived_key_raw.as_bytes().try_into().expect("Should convert to array"));
        
        // For now, we'll create a placeholder public key since we have type compatibility issues
        // TODO: Proper key derivation when ByteArray issues are resolved
        // let derived_public_key = RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::from_bytes(derived_private_key.as_bytes()).unwrap());
        // derived_keys.push(derived_public_key);
    }
    
    // Use Arc<Mutex<WalletState>> for thread safety
    let wallet_state = Arc::new(Mutex::new(WalletState::new()));
    let scan_start_time = Instant::now();
    
    // Extract values before any moves to avoid borrow checker issues
    let from_block = block_height_range.from_block;
    let to_block = block_height_range.to_block;
    let has_specific_blocks = block_height_range.block_heights.is_some();
    
    let block_heights = block_height_range.block_heights.unwrap_or_else(|| {
        (from_block..=to_block).collect()
    });

    // Display scan information
    if has_specific_blocks {
        println!("🔍 Scanning {} specific blocks: {:?}", block_heights.len(), block_heights);
    } else {
        let block_range = to_block - from_block + 1;
        println!("🔍 Scanning blocks {} to {} ({} blocks total)...", from_block, to_block, block_range);
    }
    println!();
    
    // Warning about scanning limitations
    if from_block > 1 && !has_specific_blocks {
        println!("⚠️  WARNING: Starting scan from block {} (not genesis)", from_block);
        println!("   📍 This will MISS any wallet outputs received before block {}", from_block);
        println!("   💡 For complete transaction history, consider scanning from genesis (--from-block 1)");
        println!("   🔄 Spent transactions may not be detected if their outputs were received earlier");
        println!();
    }
    
    println!("🔍 Unified scan: discovering outputs and tracking spending in single pass");

    let total_blocks = block_heights.len();
    for (block_index, block_height) in block_heights.iter().enumerate() {
        let current_progress = block_index + 1; // Sequential progress index (1, 2, 3...)
        
        // Show enhanced progress with balance info
        {
            let state = wallet_state.lock().unwrap();
            let progress_bar = state.format_progress_bar(current_progress as u64, total_blocks as u64, *block_height, "🔍");
            print!("\r{}", progress_bar);
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
        }
        
        let block_info = match scanner.get_block_by_height(*block_height).await {
            Ok(Some(block)) => block,
            Ok(None) => {
                println!("\n⚠️  Block {} not found, skipping...", block_height);
                continue;
            },
            Err(e) => {
                println!("\n❌ Error scanning block {}: {}", block_height, e);
                println!("   Block height: {}", block_height);
                println!("   Error details: {:?}", e);
                
                // Ask user if they want to continue
                print!("   Continue scanning remaining blocks? (y/n/s=skip this block): ");
                std::io::Write::flush(&mut std::io::stdout()).unwrap();
                
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
                let choice = input.trim().to_lowercase();
                
                match choice.as_str() {
                    "y" | "yes" => {
                        println!("   ✅ Continuing scan from next block...");
                        continue;
                    },
                    "s" | "skip" => {
                        println!("   ⏭️  Skipping block {} and continuing...", block_height);
                        continue;
                    },
                    _ => {
                        println!("   🛑 Scan aborted by user at block {}", block_height);
                        println!("\n💡 To resume from this point, run:");
                        if has_specific_blocks {
                            // For specific blocks, suggest using --blocks
                            let remaining_blocks: Vec<u64> = block_heights.iter().skip(block_index).copied().collect();
                            println!("   cargo run --example scanner --features grpc -- --seed-phrase \"your seed phrase\" --blocks {}", 
                                remaining_blocks.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(","));
                        } else {
                            // For range, suggest using --from-block
                            println!("   cargo run --example scanner --features grpc -- --seed-phrase \"your seed phrase\" --from-block {} --to-block {}", block_height, to_block);
                        }
                        return Err(e);
                    }
                }
            }
        };
        
        // PART 1: Process outputs for discovery (same as Phase 1 logic)
        for (output_index, output) in block_info.outputs.iter().enumerate() {
            let mut found_output = false;
            
            // STEP 4A: Script Pattern Matching (Disabled due to type compatibility)
            // Note: LightweightScript vs TariScript incompatibility
            
            // STEP 4C: Range Proof Rewinding (if we have a range proof)
            if let Some(ref range_proof) = output.proof {
                if !range_proof.bytes.is_empty() {
                    // Try rewinding with derived seed nonces
                    for nonce_index in 0..5 { // Try a few different nonces
                        // Generate a rewind nonce from wallet entropy
                        if let Ok(seed_nonce) = range_proof_service.generate_rewind_nonce(&entropy, nonce_index) {
                            if let Ok(Some(rewind_result)) = range_proof_service.attempt_rewind(
                                &range_proof.bytes,
                                &output.commitment,
                                &seed_nonce,
                                Some(output.minimum_value_promise.as_u64())
                            ) {
                                println!("\n🎯 Range proof rewind successful in block {}, output {}: {} μT", 
                                    block_height, output_index, rewind_result.value);
                                    
                                {
                                    let mut state = wallet_state.lock().unwrap();
                                    state.add_received_output(
                                        *block_height,
                                        output_index,
                                        output.commitment.clone(),
                                        rewind_result.value,
                                        PaymentId::Empty, // Range proof doesn't contain payment ID
                                        TransactionStatus::OneSidedConfirmed,
                                        TransactionDirection::Inbound,
                                        true,
                                    );
                                }
                                found_output = true;
                                break; // Found a successful rewind, move to next output
                            }
                        }
                    }
                }
            }
            
            // Skip further processing if we already found this output via range proof rewinding
            if found_output {
                continue;
            }
            
            // Check for coinbase outputs first (they don't use encrypted data for value, but we still need to verify ownership)
            if matches!(output.features.output_type, lightweight_wallet_libs::data_structures::wallet_output::LightweightOutputType::Coinbase) {
                // Coinbase outputs have their value revealed in minimum_value_promise
                let coinbase_value = output.minimum_value_promise.as_u64();
                if coinbase_value > 0 {
                    // For coinbase outputs, we still need to verify ownership
                    // Try to decrypt encrypted_data (even though value is public, encrypted_data may contain ownership proof)
                    let mut is_ours = false;
                    
                    if !output.encrypted_data.as_bytes().is_empty() {
                        // Try regular decryption for ownership verification
                        if let Ok((_value, _mask, _payment_id)) = EncryptedData::decrypt_data(&view_key, &output.commitment, &output.encrypted_data) {
                            is_ours = true;
                        }
                        // Try one-sided decryption for ownership verification
                        else if !output.sender_offset_public_key.as_bytes().is_empty() {
                            if let Ok((_value, _mask, _payment_id)) = EncryptedData::decrypt_one_sided_data(&view_key, &output.commitment, &output.sender_offset_public_key, &output.encrypted_data) {
                                is_ours = true;
                            }
                        }
                    }
                    
                    // Only add to wallet if we can prove ownership through decryption
                    if is_ours {
                        // Check if coinbase is mature (can be spent)
                        let is_mature = *block_height >= output.features.maturity;
                        
                        println!("\n💰 Found wallet coinbase reward: {} μT in block {} (mature: {})", 
                            coinbase_value, block_height, is_mature);
                        
                        {
                            let mut state = wallet_state.lock().unwrap();
                            state.add_received_output(
                                *block_height,
                                output_index,
                                output.commitment.clone(),
                                coinbase_value,
                                PaymentId::Empty, // Coinbase outputs typically have no payment ID
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
                }
            }
            
            // Skip encrypted data processing if we already found a coinbase output
            if found_output {
                continue;
            }
            
            // Skip if no encrypted data
            if output.encrypted_data.as_bytes().is_empty() {
                continue;
            }
            
            // Try regular decryption first
            if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_data(&view_key, &output.commitment, &output.encrypted_data) {
                let value_u64 = value.as_u64();
                {
                    let mut state = wallet_state.lock().unwrap();
                    state.add_received_output(
                        *block_height,
                        output_index,
                        output.commitment.clone(),
                        value_u64,
                        payment_id,
                        TransactionStatus::MinedConfirmed,
                        TransactionDirection::Inbound,
                        true, // Regular payments are always mature
                    );
                }
                continue;
            }
            
            // Try one-sided decryption
            if !output.sender_offset_public_key.as_bytes().is_empty() {
                if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_one_sided_data(&view_key, &output.commitment, &output.sender_offset_public_key, &output.encrypted_data) {
                    let value_u64 = value.as_u64();
                    {
                        let mut state = wallet_state.lock().unwrap();
                        state.add_received_output(
                            *block_height,
                            output_index,
                            output.commitment.clone(),
                            value_u64,
                            payment_id,
                            TransactionStatus::OneSidedConfirmed,
                            TransactionDirection::Inbound,
                            true, // One-sided payments are always mature
                        );
                    }
                }
            }
        }
        
        // PART 2: Process inputs for spending detection (same as Phase 2 logic)
        // This is now done in the same loop iteration, eliminating duplicate GRPC calls
        for (input_index, input) in block_info.inputs.iter().enumerate() {
            // Input commitment is already [u8; 32], convert directly to CompressedCommitment
            let input_commitment = CompressedCommitment::new(input.commitment);
            
            // Try to mark as spent in a thread-safe way
            {
                let mut state = wallet_state.lock().unwrap();
                if state.mark_output_spent(&input_commitment, *block_height, input_index) {
                    // Successfully marked an output as spent and created outbound transaction
                }
            }
        }
    }
    
    let scan_elapsed = scan_start_time.elapsed();
    println!("\n✅ Unified scan complete in {:.2}s!", scan_elapsed.as_secs_f64());
    
    // Summary of what was found
    {
        let state = wallet_state.lock().unwrap();
        let (inbound_count, outbound_count, _) = state.get_direction_counts();
        println!("📊 Scan results: {} inbound, {} outbound transactions discovered", inbound_count, outbound_count);
        
        if state.transactions.is_empty() {
            println!("⚠️  No wallet activity found in scan range");
            println!("   💡 Try scanning from an earlier block or from genesis (--from-block 1)");
        } else {
            println!("🔑 Found {} wallet transactions to display", state.transactions.len());
        }
    }
    
    println!();
    
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

#[cfg(feature = "grpc")]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    // Initialize logging

    tracing_subscriber::fmt::init();

    println!("🚀 Enhanced Tari Wallet Scanner");
    println!("===============================");

    // Parse CLI arguments
    let args = CliArgs::parse();

    println!("🔨 Creating wallet from seed phrase...");
    let wallet = Wallet::new_from_seed_phrase(&args.seed_phrase, None)?;

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

    // Determine scan range from CLI arguments
    let to_block = args.to_block.unwrap_or(tip_info.best_block_height);

    let wallet_birthday = args.from_block.unwrap_or(wallet.birthday());

    let from_block = std::cmp::max(wallet_birthday, 0);

    let block_height_range = BlockHeightRange::new(from_block, to_block, args.blocks);
  
    // Perform the comprehensive scan
    let wallet_state = scan_wallet_across_blocks(&mut scanner, &wallet, block_height_range).await?;
    
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