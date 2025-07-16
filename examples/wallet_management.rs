//! Wallet Management Example
//! 
//! This example demonstrates how to manage wallets in the database storage system,
//! including creating, listing, and using wallets for transaction storage.

#[cfg(all(feature = "grpc", feature = "storage"))]
use lightweight_wallet_libs::{
    storage::{WalletStorage, SqliteStorage, StoredWallet, TransactionFilter},
    data_structures::{
        wallet_transaction::WalletTransaction,
        types::{CompressedCommitment, PrivateKey},
        transaction::{TransactionStatus, TransactionDirection},
        payment_id::PaymentId,
    },
    errors::LightweightWalletResult,
};

#[cfg(all(feature = "grpc", feature = "storage"))]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    println!("👛 Tari Wallet Management Example");
    println!("=================================");

    // Create an in-memory SQLite storage instance
    let storage = SqliteStorage::new_in_memory().await?;
    storage.initialize().await?;
    
    println!("✅ Storage initialized");

    // Create some example wallets
    let alice_view_key = PrivateKey::new([1u8; 32]);
    let alice_spend_key = PrivateKey::new([2u8; 32]);
    let wallet1 = StoredWallet::from_seed_phrase(
        "alice-wallet".to_string(),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        alice_view_key,
        alice_spend_key,
        1000, // birthday block
    );

    let bob_view_key = PrivateKey::new([3u8; 32]);
    let bob_spend_key = PrivateKey::new([4u8; 32]);
    let wallet2 = StoredWallet::from_keys(
        "bob-wallet".to_string(),
        bob_view_key.clone(),
        bob_spend_key,
        2000, // birthday block
    );

    let wallet3 = StoredWallet::view_only(
        "charlie-watch".to_string(),
        PrivateKey::new([5u8; 32]),
        500, // birthday block
    );

    // Save wallets to storage
    let alice_id = storage.save_wallet(&wallet1).await?;
    let bob_id = storage.save_wallet(&wallet2).await?;
    let charlie_id = storage.save_wallet(&wallet3).await?;

    println!("💾 Created wallets:");
    println!("  • Alice (ID {}): Full wallet with seed phrase", alice_id);
    println!("  • Bob (ID {}): Full wallet with keys", bob_id);
    println!("  • Charlie (ID {}): View-only wallet", charlie_id);

    // List all wallets
    let wallets = storage.list_wallets().await?;
    println!("\n📂 All wallets in database:");
    for wallet in &wallets {
        let wallet_type = if wallet.has_seed_phrase() {
            "Full (seed phrase)"
        } else if wallet.can_spend() {
            "Full (keys)"
        } else {
            "View-only"
        };
        
        println!("  • {} - {} (birthday: block {})", 
            wallet.name, 
            wallet_type, 
            wallet.birthday_block
        );
    }

    // Create some example transactions for different wallets
    let transactions_alice = vec![
        WalletTransaction::new(
            1500, Some(0), None, CompressedCommitment::new([10u8; 32]),
            1000000, PaymentId::Empty,
            TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
        ),
        WalletTransaction::new(
            1600, Some(1), None, CompressedCommitment::new([11u8; 32]),
            2000000, PaymentId::Empty,
            TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
        ),
    ];

    let transactions_bob = vec![
        WalletTransaction::new(
            2100, Some(0), None, CompressedCommitment::new([20u8; 32]),
            5000000, PaymentId::Empty,
            TransactionStatus::CoinbaseConfirmed, TransactionDirection::Inbound, true,
        ),
    ];

    let transactions_charlie = vec![
        WalletTransaction::new(
            600, Some(0), None, CompressedCommitment::new([30u8; 32]),
            500000, PaymentId::Empty,
            TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
        ),
        WalletTransaction::new(
            700, None, Some(0), CompressedCommitment::new([30u8; 32]),
            500000, PaymentId::Empty,
            TransactionStatus::MinedConfirmed, TransactionDirection::Outbound, true,
        ),
    ];

    // Save transactions for each wallet
    storage.save_transactions(alice_id, &transactions_alice).await?;
    storage.save_transactions(bob_id, &transactions_bob).await?;
    storage.save_transactions(charlie_id, &transactions_charlie).await?;

    println!("\n💾 Added transactions for each wallet");

    // Query transactions by wallet
    println!("\n📊 Transactions by wallet:");
    
    for (wallet_name, wallet_id) in [("Alice", alice_id), ("Bob", bob_id), ("Charlie", charlie_id)] {
        let filter = TransactionFilter::new().with_wallet_id(wallet_id);
        let wallet_transactions = storage.get_transactions(Some(filter)).await?;
        
        let total_value: u64 = wallet_transactions.iter()
            .filter(|tx| tx.transaction_direction == TransactionDirection::Inbound)
            .map(|tx| tx.value)
            .sum();
        
        println!("  • {}: {} transactions, total received: {} μT ({:.6} T)", 
            wallet_name, 
            wallet_transactions.len(),
            total_value,
            total_value as f64 / 1_000_000.0
        );
    }

    // Demonstrate wallet state loading
    println!("\n🏦 Wallet states:");
    for (wallet_name, wallet_id) in [("Alice", alice_id), ("Bob", bob_id), ("Charlie", charlie_id)] {
        let wallet_state = storage.load_wallet_state(wallet_id).await?;
        let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
        
        println!("  • {} - Balance: {} μT, Unspent: {}, Spent: {}", 
            wallet_name,
            balance,
            unspent_count,
            spent_count
        );
    }

    // Get wallet by name
    println!("\n🔍 Finding wallet by name:");
    if let Some(found_wallet) = storage.get_wallet_by_name("bob-wallet").await? {
        println!("  Found wallet: {} (ID: {})", found_wallet.name, found_wallet.id.unwrap());
    }

    // Demonstrate wallet statistics
    let stats = storage.get_statistics().await?;
    println!("\n📈 Overall storage statistics:");
    println!("  • Total transactions: {}", stats.total_transactions);
    println!("  • Total wallets: {}", wallets.len());
    println!("  • Total value stored: {} μT ({:.6} T)", 
        stats.total_received, 
        stats.total_received as f64 / 1_000_000.0
    );

    // Close storage connection
    storage.close().await?;
    println!("\n✅ Wallet management example completed successfully!");

    Ok(())
}

#[cfg(not(all(feature = "grpc", feature = "storage")))]
fn main() {
    eprintln!("This example requires both 'grpc' and 'storage' features to be enabled.");
    eprintln!("Run with: cargo run --example wallet_management --features grpc-storage");
    std::process::exit(1);
} 