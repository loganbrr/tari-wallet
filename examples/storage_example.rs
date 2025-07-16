//! Storage Usage Example
//! 
//! This example demonstrates how to use the trait-based storage system
//! for wallet transactions independently of the scanner.

#[cfg(feature = "storage")]
use lightweight_wallet_libs::{
    storage::{WalletStorage, SqliteStorage, TransactionFilter},
    data_structures::{
        wallet_transaction::WalletTransaction,
        types::CompressedCommitment,
        transaction::{TransactionStatus, TransactionDirection},
        payment_id::PaymentId,
    },
    errors::LightweightWalletResult,
};

#[cfg(feature = "storage")]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    println!("🗄️  Tari Wallet Storage Example");
    println!("==============================");

    // Create an in-memory SQLite storage instance
    let storage = SqliteStorage::new_in_memory().await?;
    storage.initialize().await?;
    
    println!("✅ Storage initialized");

    // Create some example transactions
    let transactions = vec![
        WalletTransaction::new(
            1000,
            Some(0),
            None,
            CompressedCommitment::new([1u8; 32]),
            1000000, // 1 T
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        ),
        WalletTransaction::new(
            2000,
            Some(1),
            None,
            CompressedCommitment::new([2u8; 32]),
            2000000, // 2 T
            PaymentId::Empty,
            TransactionStatus::CoinbaseConfirmed,
            TransactionDirection::Inbound,
            true,
        ),
        WalletTransaction::new(
            3000,
            None,
            Some(0),
            CompressedCommitment::new([1u8; 32]),
            1000000, // 1 T spent
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Outbound,
            true,
        ),
    ];

    // Save transactions
    storage.save_transactions(&transactions).await?;
    println!("💾 Saved {} transactions to storage", transactions.len());

    // Mark the first transaction as spent
    let commitment1 = CompressedCommitment::new([1u8; 32]);
    let marked = storage.mark_transaction_spent(&commitment1, 3000, 0).await?;
    if marked {
        println!("🔄 Marked transaction as spent");
    }

    // Query transactions with filters
    println!("\n📊 Query Examples:");
    
    // Get all transactions
    let all_txs = storage.get_transactions(None).await?;
    println!("• Total transactions: {}", all_txs.len());

    // Get only inbound transactions
    let inbound_filter = TransactionFilter::new().with_direction(TransactionDirection::Inbound);
    let inbound_txs = storage.get_transactions(Some(inbound_filter)).await?;
    println!("• Inbound transactions: {}", inbound_txs.len());

    // Get transactions by block range
    let range_txs = storage.get_transactions_by_block_range(1500, 2500).await?;
    println!("• Transactions in blocks 1500-2500: {}", range_txs.len());

    // Get unspent transactions
    let unspent_txs = storage.get_unspent_transactions().await?;
    println!("• Unspent transactions: {}", unspent_txs.len());

    // Get storage statistics
    let stats = storage.get_statistics().await?;
    println!("\n📈 Storage Statistics:");
    println!("• Total transactions: {}", stats.total_transactions);
    println!("• Inbound count: {}", stats.inbound_count);
    println!("• Outbound count: {}", stats.outbound_count);
    println!("• Unspent count: {}", stats.unspent_count);
    println!("• Spent count: {}", stats.spent_count);
    println!("• Total received: {} μT ({:.6} T)", stats.total_received, stats.total_received as f64 / 1_000_000.0);
    println!("• Total spent: {} μT ({:.6} T)", stats.total_spent, stats.total_spent as f64 / 1_000_000.0);
    println!("• Current balance: {} μT ({:.6} T)", stats.current_balance, stats.current_balance as f64 / 1_000_000.0);
    println!("• Block range: {} to {}", 
        stats.lowest_block.unwrap_or(0), 
        stats.highest_block.unwrap_or(0)
    );

    // Load wallet state from storage
    let wallet_state = storage.load_wallet_state().await?;
    let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
    
    println!("\n🏦 Reconstructed Wallet State:");
    println!("• Total received: {} μT ({:.6} T)", total_received, total_received as f64 / 1_000_000.0);
    println!("• Total spent: {} μT ({:.6} T)", total_spent, total_spent as f64 / 1_000_000.0);
    println!("• Current balance: {} μT ({:.6} T)", balance, balance as f64 / 1_000_000.0);
    println!("• Unspent outputs: {}", unspent_count);
    println!("• Spent outputs: {}", spent_count);

    // Close storage connection
    storage.close().await?;
    println!("\n✅ Storage example completed successfully!");

    Ok(())
}

#[cfg(not(feature = "storage"))]
fn main() {
    eprintln!("This example requires the 'storage' feature to be enabled.");
    eprintln!("Run with: cargo run --example storage_example --features storage");
    std::process::exit(1);
} 