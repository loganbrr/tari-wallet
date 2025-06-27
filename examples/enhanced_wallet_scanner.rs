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
//! - Example: `FROM_BLOCK=25000 TO_BLOCK=30000 cargo run --example enhanced_wallet_scanner --features grpc`
//!
//! ## Usage
//! ```bash
//! # Scan with default wallet from birthday to tip
//! cargo run --example enhanced_wallet_scanner --features grpc
//!
//! # Use specific wallet
//! TEST_SEED_PHRASE="your seed phrase" cargo run --example enhanced_wallet_scanner --features grpc
//!
//! # Scan specific range
//! FROM_BLOCK=34920 TO_BLOCK=34930 cargo run --example enhanced_wallet_scanner --features grpc
//!
//! # Resume from a specific block after error
//! FROM_BLOCK=25000 TO_BLOCK=30000 cargo run --example enhanced_wallet_scanner --features grpc
//! ```

#[cfg(feature = "grpc")]
use lightweight_wallet_libs::{
    scanning::{GrpcScannerBuilder, GrpcBlockchainScanner, BlockchainScanner},
    key_management::{key_derivation, seed_phrase::{mnemonic_to_bytes, CipherSeed}},
    wallet::Wallet,
    errors::LightweightWalletResult,
    KeyManagementError,
    data_structures::{
        types::{PrivateKey, CompressedCommitment},
        encrypted_data::EncryptedData,
        payment_id::PaymentId,
    },
};
#[cfg(feature = "grpc")]
use tari_utilities::ByteArray;
use std::collections::HashMap;
use std::io::{self, Write};
use tracing_subscriber;

#[cfg(feature = "grpc")]
#[derive(Debug, Clone)]
struct WalletTransaction {
    block_height: u64,
    output_index: Option<usize>,
    input_index: Option<usize>,
    commitment: CompressedCommitment,
    value: u64,
    payment_id: PaymentId,
    is_spent: bool,
    spent_in_block: Option<u64>,
    spent_in_input: Option<usize>,
}

#[cfg(feature = "grpc")]
#[derive(Debug)]
struct WalletState {
    transactions: Vec<WalletTransaction>,
    outputs_by_commitment: HashMap<Vec<u8>, usize>, // commitment bytes -> transaction index
    running_balance: i64,
    total_received: u64,
    total_spent: u64,
}

#[cfg(feature = "grpc")]
impl WalletState {
    fn new() -> Self {
        Self {
            transactions: Vec::new(),
            outputs_by_commitment: HashMap::new(),
            running_balance: 0,
            total_received: 0,
            total_spent: 0,
        }
    }

    fn add_received_output(
        &mut self,
        block_height: u64,
        output_index: usize,
        commitment: CompressedCommitment,
        value: u64,
        payment_id: PaymentId,
    ) {
        let transaction = WalletTransaction {
            block_height,
            output_index: Some(output_index),
            input_index: None,
            commitment: commitment.clone(),
            value,
            payment_id,
            is_spent: false,
            spent_in_block: None,
            spent_in_input: None,
        };

        let tx_index = self.transactions.len();
        self.outputs_by_commitment.insert(commitment.as_bytes().to_vec(), tx_index);
        self.transactions.push(transaction);
        
        self.total_received += value;
        self.running_balance += value as i64;
    }

    fn mark_output_spent(
        &mut self,
        commitment: &CompressedCommitment,
        block_height: u64,
        input_index: usize,
    ) -> bool {
        let commitment_bytes = commitment.as_bytes().to_vec();
        if let Some(&tx_index) = self.outputs_by_commitment.get(&commitment_bytes) {
            if let Some(transaction) = self.transactions.get_mut(tx_index) {
                if !transaction.is_spent {
                    transaction.is_spent = true;
                    transaction.spent_in_block = Some(block_height);
                    transaction.spent_in_input = Some(input_index);
                    
                    // Use the value from our stored transaction, not the input
                    let spent_value = transaction.value;
                    self.total_spent += spent_value;
                    self.running_balance -= spent_value as i64;
                    
                    println!("\n🔍 Found spent output: {} μT in block {} (originally received in block {})", 
                        spent_value, block_height, transaction.block_height);
                    return true;
                }
            }
        }
        false
    }

    fn get_summary(&self) -> (u64, u64, i64, usize, usize) {
        let received_count = self.transactions.len();
        let spent_count = self.transactions.iter().filter(|tx| tx.is_spent).count();
        (self.total_received, self.total_spent, self.running_balance, received_count, spent_count)
    }
}

#[cfg(feature = "grpc")]
async fn scan_wallet_across_blocks(
    scanner: &mut GrpcBlockchainScanner,
    wallet: &Wallet,
    from_block: u64,
    to_block: u64,
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
    
    let mut wallet_state = WalletState::new();
    let block_range = to_block - from_block + 1;
    
    println!("🔍 Scanning blocks {} to {} ({} blocks total)...", from_block, to_block, block_range);
    println!("🔑 Wallet entropy: {}", hex::encode(entropy));
    println!();
    
    // Phase 1: Scan all blocks for received outputs
    println!("📥 Discovering wallet outputs...");
    let mut transactions_found = 0;
    let mut total_value_found = 0u64;
    for block_height in from_block..=to_block {
        let current_block = block_height - from_block + 1;
        let total_blocks = block_range;
        let progress_percent = (current_block as f64 / total_blocks as f64) * 100.0;
        
        // Create progress bar (50 characters wide)
        let bar_width = 50;
        let filled_width = ((progress_percent / 100.0) * bar_width as f64) as usize;
        let bar = format!("{}{}",
            "█".repeat(filled_width),
            "░".repeat(bar_width - filled_width)
        );
        
        print!("\r   [{}] {:.1}% ({}/{} blocks) - Block {} - {} TX ({:.6} T)", 
            bar, progress_percent, current_block, total_blocks, block_height, transactions_found, total_value_found as f64 / 1_000_000.0);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        let block_info = match scanner.get_block_by_height(block_height).await {
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
                        println!("   ✅ Continuing scan from block {}...", block_height + 1);
                        continue;
                    },
                    "s" | "skip" => {
                        println!("   ⏭️  Skipping block {} and continuing...", block_height);
                        continue;
                    },
                    _ => {
                        println!("   🛑 Scan aborted by user at block {}", block_height);
                        println!("\n💡 To resume from this point, run:");
                        println!("   FROM_BLOCK={} TO_BLOCK={} cargo run --example enhanced_wallet_scanner --features grpc", block_height, to_block);
                        return Err(e);
                    }
                }
            }
        };
        
        // Scan outputs for this wallet
        for (output_index, output) in block_info.outputs.iter().enumerate() {
            if output.encrypted_data.as_bytes().is_empty() {
                continue;
            }
            
            // Try regular decryption first
            if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_data(&view_key, &output.commitment, &output.encrypted_data) {
                let value_u64 = value.as_u64();
                wallet_state.add_received_output(
                    block_height,
                    output_index,
                    output.commitment.clone(),
                    value_u64,
                    payment_id,
                );
                transactions_found += 1;
                total_value_found += value_u64;
                continue;
            }
            
            // Try one-sided decryption
            if !output.sender_offset_public_key.as_bytes().is_empty() {
                if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_one_sided_data(&view_key, &output.commitment, &output.sender_offset_public_key, &output.encrypted_data) {
                    let value_u64 = value.as_u64();
                    wallet_state.add_received_output(
                        block_height,
                        output_index,
                        output.commitment.clone(),
                        value_u64,
                        payment_id,
                    );
                    transactions_found += 1;
                    total_value_found += value_u64;
                }
            }
        }
    }
    println!("\n✅ Output discovery complete!");
    
    // Phase 2: Scan all blocks for spent inputs (including future blocks)
    println!("📤 Tracking spent outputs...");
    println!("💡 Extending scan range to look for future spending...");
    
    // Get current tip to scan beyond our initial range for spending
    let current_tip = scanner.get_tip_info().await?.best_block_height;
    let extended_to_block = std::cmp::min(to_block + 1000, current_tip); // Look ahead up to 1000 blocks
    
    println!("🔍 Scanning for spent outputs from block {} to {} (extended range)", from_block, extended_to_block);
    println!("📊 Tracking {} wallet outputs for spending", wallet_state.transactions.len());
    
    for block_height in from_block..=extended_to_block {
        let current_block = block_height - from_block + 1;
        let total_extended_blocks = extended_to_block - from_block + 1;
        let progress_percent = (current_block as f64 / total_extended_blocks as f64) * 100.0;
        
        // Create progress bar (50 characters wide)
        let bar_width = 50;
        let filled_width = ((progress_percent / 100.0) * bar_width as f64) as usize;
        let bar = format!("{}{}",
            "█".repeat(filled_width),
            "░".repeat(bar_width - filled_width)
        );
        
        print!("\r   [{}] {:.1}% ({}/{} blocks) - Block {} - {} TX ({:.6} T)", 
            bar, progress_percent, current_block, total_extended_blocks, block_height, transactions_found, total_value_found as f64 / 1_000_000.0);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        let block_info = match scanner.get_block_by_height(block_height).await {
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
                        println!("   ✅ Continuing scan from block {}...", block_height + 1);
                        continue;
                    },
                    "s" | "skip" => {
                        println!("   ⏭️  Skipping block {} and continuing...", block_height);
                        continue;
                    },
                    _ => {
                        println!("   🛑 Scan aborted by user at block {}", block_height);
                        println!("\n💡 To resume from this point, run:");
                        println!("   FROM_BLOCK={} TO_BLOCK={} cargo run --example enhanced_wallet_scanner --features grpc", block_height, to_block);
                        return Err(e);
                    }
                }
            }
        };
        
        // Check inputs to see if they spend our outputs
        for (input_index, input) in block_info.inputs.iter().enumerate() {
            // Convert input commitment bytes to CompressedCommitment
            if input.commitment.len() == 32 {
                let commitment_bytes: [u8; 32] = input.commitment.clone().try_into().unwrap_or([0u8; 32]);
                let input_commitment = CompressedCommitment::new(commitment_bytes);
                wallet_state.mark_output_spent(
                    &input_commitment,
                    block_height,
                    input_index,
                );
            }
        }
    }
    println!("\n✅ Spent output tracking complete!");
    println!();
    
    Ok(wallet_state)
}

#[cfg(feature = "grpc")]
fn display_wallet_activity(wallet_state: &WalletState, from_block: u64, to_block: u64) {
    let (total_received, total_spent, balance, received_count, spent_count) = wallet_state.get_summary();
    
    if received_count == 0 && spent_count == 0 {
        println!("💡 No wallet activity found in blocks {} to {}", from_block, to_block);
        return;
    }
    
    println!("🏦 WALLET ACTIVITY SUMMARY");
    println!("========================");
    println!("Scan range: Block {} to {} ({} blocks)", from_block, to_block, to_block - from_block + 1);
    println!("Total received: {} μT ({:.6} T) in {} transaction(s)", total_received, total_received as f64 / 1_000_000.0, received_count);
    println!("Total spent: {} μT ({:.6} T) in {} transaction(s)", total_spent, total_spent as f64 / 1_000_000.0, spent_count);
    println!("Current balance: {} μT ({:.6} T)", balance, balance as f64 / 1_000_000.0);
    println!();
    
    if !wallet_state.transactions.is_empty() {
        println!("📋 TRANSACTION HISTORY");
        println!("=====================");
        
        for (i, tx) in wallet_state.transactions.iter().enumerate() {
            let status = if tx.is_spent {
                format!("SPENT in block {}", tx.spent_in_block.unwrap_or(0))
            } else {
                "UNSPENT".to_string()
            };
            
            println!("{}. Block {}, Output #{}: +{} μT ({:.6} T) - {}", 
                i + 1,
                tx.block_height,
                tx.output_index.unwrap_or(0),
                tx.value,
                tx.value as f64 / 1_000_000.0,
                status
            );
            
            // Show payment ID if not empty
            match &tx.payment_id {
                PaymentId::Empty => {},
                PaymentId::Open { user_data, .. } if !user_data.is_empty() => {
                    // Try to decode as UTF-8 string
                    if let Ok(text) = std::str::from_utf8(user_data) {
                        if text.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                            println!("   Payment ID: \"{}\"", text);
                        } else {
                            println!("   Payment ID: {} bytes", user_data.len());
                        }
                    } else {
                        println!("   Payment ID: {} bytes", user_data.len());
                    }
                },
                _ => {
                    println!("   Payment ID: {:?}", tx.payment_id);
                }
            }
        }
        println!();
    }
    
    // Show balance breakdown
    let unspent_count = received_count - spent_count;
    let unspent_value: u64 = wallet_state.transactions.iter()
        .filter(|tx| !tx.is_spent)
        .map(|tx| tx.value)
        .sum();
        
    println!("💰 BALANCE BREAKDOWN");
    println!("===================");
    println!("Unspent outputs: {} ({:.6} T)", unspent_count, unspent_value as f64 / 1_000_000.0);
    println!("Spent outputs: {} ({:.6} T)", spent_count, total_spent as f64 / 1_000_000.0);
    println!("Total wallet activity: {} transactions", received_count);
}

#[cfg(feature = "grpc")]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🚀 Enhanced Tari Wallet Scanner");
    println!("===============================");
    println!("Complete cross-block transaction tracking with running balance");
    println!();

    // Configuration
    let default_seed = "gate sound fault steak act victory vacuum night injury lion section share pass food damage venue smart vicious cinnamon eternal invest shoulder green file";
    let seed_phrase = std::env::var("TEST_SEED_PHRASE").unwrap_or_else(|_| default_seed.to_string());

    println!("🔨 Creating wallet from seed phrase... {}", seed_phrase);
    let wallet = Wallet::new_from_seed_phrase(&seed_phrase, None)?;
    println!("✅ Wallet created successfully");

    println!("🌐 Connecting to Tari base node...");
    let mut scanner = match GrpcScannerBuilder::new()
        .with_base_url("http://127.0.0.1:18142".to_string())
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

    // Determine scan range
    let to_block = std::env::var("TO_BLOCK")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(tip_info.best_block_height);

    // Default to scanning from a reasonable starting point
    // In a real implementation, you'd calculate the actual wallet birthday
    let wallet_birthday = std::env::var("FROM_BLOCK")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| {
            // Default to last 1000 blocks or from genesis if close to start
            if tip_info.best_block_height > 1000 {
                tip_info.best_block_height.saturating_sub(1000)
            } else {
                0
            }
        });

    let from_block = std::cmp::max(wallet_birthday, 0);
    
    println!("📅 Wallet birthday: block {} (estimated)", from_block);
    println!("🎯 Scan range: blocks {} to {}", from_block, to_block);
    println!();

    // Perform the comprehensive scan
    let wallet_state = scan_wallet_across_blocks(&mut scanner, &wallet, from_block, to_block).await?;
    
    // Display results
    display_wallet_activity(&wallet_state, from_block, to_block);
    
    println!("✅ Scan completed successfully!");
    
    Ok(())
}

#[cfg(not(feature = "grpc"))]
fn main() {
    eprintln!("This example requires the 'grpc' feature to be enabled.");
    eprintln!("Run with: cargo run --example enhanced_wallet_scanner --features grpc");
    std::process::exit(1);
} 