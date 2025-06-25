//! Simple test to verify GRPC scanner works with known wallet data
//!
//! This test uses the known seed phrase and block range from the user's test case
//! to verify that our wallet key integration can find the expected outputs.

#[cfg(feature = "grpc")]
use lightweight_wallet_libs::{
    scanning::{GrpcScannerBuilder, WalletScanner, BlockchainScanner},
    wallet::Wallet,
    errors::LightweightWalletResult,
};

#[cfg(feature = "grpc")]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    println!("Testing GRPC scanner with known wallet data");
    println!("============================================");

    // Known test data from user
    let seed_phrase = "scare pen great round cherry soul dismiss dance ghost hire color casino train execute awesome shield wire cruel mom depth enhance rough client aerobic";
    let from_block = 34923;
    let to_block = 34928;
    
    println!("Seed phrase: {}", seed_phrase);
    println!("Block range: {} to {} ({} blocks)", from_block, to_block, to_block - from_block + 1);
    
    // Create wallet from seed phrase
    let wallet = Wallet::new_from_seed_phrase(seed_phrase, None)?;
    println!("Wallet created successfully");
    
    // Create and connect GRPC scanner
    let builder = GrpcScannerBuilder::new()
        .with_base_url("http://127.0.0.1:18142".to_string())
        .with_timeout(std::time::Duration::from_secs(30));

    let mut scanner = match builder.build().await {
        Ok(scanner) => {
            println!("✓ Connected to GRPC node successfully");
            scanner
        },
        Err(e) => {
            println!("✗ Failed to connect to GRPC node: {}", e);
            println!("Make sure a Tari base node is running with GRPC enabled on port 18142");
            return Err(e);
        }
    };

    // Get tip info
    let tip_info = scanner.get_tip_info().await?;
    println!("Current tip height: {}", tip_info.best_block_height);
    
    // Test the wallet key derivation and scanning
    println!("\n=== Testing Wallet Scanning ===");
    
    // Create scan config using the fixed key derivation method
    let scan_config = scanner.create_scan_config_with_wallet_keys(&wallet, from_block, Some(to_block))?;
    
    println!("Scanning blocks {} to {}...", from_block, to_block);
    let scan_results = scanner.scan_blocks(scan_config).await?;
    
    println!("\n=== Scan Results ===");
    let total_outputs = scan_results.iter().map(|r| r.outputs.len()).sum::<usize>();
    let total_wallet_outputs = scan_results.iter().map(|r| r.wallet_outputs.len()).sum::<usize>();
    
    println!("Total blocks scanned: {}", scan_results.len());
    println!("Total transaction outputs found: {}", total_outputs);
    println!("Total wallet outputs extracted: {}", total_wallet_outputs);
    
    if total_wallet_outputs > 0 {
        println!("\n🎉 SUCCESS: Found {} wallet outputs!", total_wallet_outputs);
        
        for (block_index, result) in scan_results.iter().enumerate() {
            if !result.wallet_outputs.is_empty() {
                let block_value: u64 = result.wallet_outputs.iter()
                    .map(|wo| wo.value().as_u64())
                    .sum();
                    
                println!("\nBlock {} (height {}):", block_index + 1, result.height);
                println!("  - {} wallet outputs found", result.wallet_outputs.len());
                println!("  - Total value: {} MicroMinotari", block_value);
                
                for (i, wallet_output) in result.wallet_outputs.iter().enumerate() {
                    println!("    Output {}: {} MicroMinotari, Payment ID: {:?}", 
                        i + 1,
                        wallet_output.value().as_u64(),
                        wallet_output.payment_id()
                    );
                }
            }
        }
    } else {
        println!("\n⚠️  No wallet outputs found. This could mean:");
        println!("   1. The outputs don't belong to this wallet");
        println!("   2. There's still an issue with key derivation/decryption");
        println!("   3. The base node doesn't have these blocks");
        println!("   4. The transaction data is different than expected");
        
        // Debug: Show what outputs were found in each block
        for result in &scan_results {
            if !result.outputs.is_empty() {
                println!("\nBlock {} had {} transaction outputs (none extracted as wallet outputs)",
                    result.height, result.outputs.len());
            }
        }
    }
    
    Ok(())
}

#[cfg(not(feature = "grpc"))]
fn main() {
    eprintln!("This test requires the 'grpc' feature to be enabled.");
    eprintln!("Run with: cargo run --example test_known_wallet --features grpc");
    std::process::exit(1);
} 