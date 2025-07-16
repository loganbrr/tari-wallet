//! UTXO Output Management Example
//!
//! This example demonstrates how to use the new UTXO output storage functionality
//! on top of the existing transaction storage system. The UTXO outputs contain
//! all the detailed information needed to create new transactions from unspent outputs.
//!
//! Usage:
//! ```bash
//! cargo run --example utxo_management --features storage
//! ```

#[cfg(feature = "storage")]
use lightweight_wallet_libs::{
    storage::{SqliteStorage, WalletStorage, StoredWallet, StoredOutput, OutputFilter, OutputStatus},
    data_structures::{
        types::PrivateKey,
        wallet_output::LightweightOutputFeatures,
    },
    errors::LightweightWalletResult,
};

#[cfg(feature = "storage")]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    println!("🚀 UTXO Output Management Example");
    println!("=================================");

    // Create in-memory storage for demonstration
    let storage = SqliteStorage::new_in_memory().await?;
    storage.initialize().await?;
    println!("✅ Storage initialized with outputs table");

    // Create a test wallet
    let wallet = StoredWallet {
        id: None,
        name: "test-wallet".to_string(),
        seed_phrase: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
        view_key_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        spend_key_hex: Some("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string()),
        birthday_block: 0,
        latest_scanned_block: None,
        created_at: None,
        updated_at: None,
    };

    let wallet_id = storage.save_wallet(&wallet).await?;
    println!("✅ Created wallet with ID: {}", wallet_id);

    // Create test UTXO outputs
    let output1 = StoredOutput {
        id: None,
        wallet_id,
        commitment: vec![0x01; 32],
        hash: vec![0x02; 32],
        value: 1_000_000, // 1 T
        spending_key: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        script_private_key: "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        script: vec![0x03; 64],
        input_data: vec![0x04; 32],
        covenant: vec![0x05; 32],
        output_type: 0, // Payment
        features_json: serde_json::to_string(&LightweightOutputFeatures::default()).unwrap(),
        maturity: 100,
        script_lock_height: 0,
        sender_offset_public_key: vec![0x06; 32],
        metadata_signature_ephemeral_commitment: vec![0x07; 32],
        metadata_signature_ephemeral_pubkey: vec![0x08; 32],
        metadata_signature_u_a: vec![0x09; 32],
        metadata_signature_u_x: vec![0x0a; 32],
        metadata_signature_u_y: vec![0x0b; 32],
        encrypted_data: vec![0x0c; 64],
        minimum_value_promise: 1_000_000,
        rangeproof: Some(vec![0x0d; 128]),
        status: OutputStatus::Unspent as u32,
        mined_height: Some(150),
        spent_in_tx_id: None,
        created_at: None,
        updated_at: None,
    };

    let output2 = StoredOutput {
        id: None,
        wallet_id,
        commitment: vec![0x11; 32],
        hash: vec![0x12; 32],
        value: 2_500_000, // 2.5 T
        spending_key: "3333333333333333333333333333333333333333333333333333333333333333".to_string(),
        script_private_key: "4444444444444444444444444444444444444444444444444444444444444444".to_string(),
        script: vec![0x13; 64],
        input_data: vec![0x14; 32],
        covenant: vec![0x15; 32],
        output_type: 1, // Coinbase
        features_json: serde_json::to_string(&LightweightOutputFeatures::default()).unwrap(),
        maturity: 200,
        script_lock_height: 0,
        sender_offset_public_key: vec![0x16; 32],
        metadata_signature_ephemeral_commitment: vec![0x17; 32],
        metadata_signature_ephemeral_pubkey: vec![0x18; 32],
        metadata_signature_u_a: vec![0x19; 32],
        metadata_signature_u_x: vec![0x1a; 32],
        metadata_signature_u_y: vec![0x1b; 32],
        encrypted_data: vec![0x1c; 64],
        minimum_value_promise: 2_500_000,
        rangeproof: Some(vec![0x1d; 128]),
        status: OutputStatus::Unspent as u32,
        mined_height: Some(250),
        spent_in_tx_id: None,
        created_at: None,
        updated_at: None,
    };

    // Save outputs
    let output_id1 = storage.save_output(&output1).await?;
    let output_id2 = storage.save_output(&output2).await?;
    println!("✅ Saved outputs with IDs: {} and {}", output_id1, output_id2);

    // Demonstrate querying functionality
    println!("\n📊 UTXO Output Queries:");
    println!("======================");

    // Get all outputs for wallet
    let all_outputs = storage.get_unspent_outputs(wallet_id).await?;
    println!("📝 Total unspent outputs: {}", all_outputs.len());
    for output in &all_outputs {
        println!("   • Output {}: {} μT (commitment: {})", 
            output.id.unwrap(),
            output.value,
            hex::encode(&output.commitment[..8])
        );
    }

    // Get spendable balance at different block heights
    let current_height = 300;
    let spendable_balance = storage.get_spendable_balance(wallet_id, current_height).await?;
    println!("💰 Spendable balance at height {}: {} μT ({:.6} T)", 
        current_height, spendable_balance, spendable_balance as f64 / 1_000_000.0);

    // Get spendable outputs at current height
    let spendable_outputs = storage.get_spendable_outputs(wallet_id, current_height).await?;
    println!("🔓 Spendable outputs at height {}: {}", current_height, spendable_outputs.len());
    for output in &spendable_outputs {
        println!("   • Output {}: {} μT (maturity: {}, lock: {})", 
            output.id.unwrap(),
            output.value,
            output.maturity,
            output.script_lock_height
        );
    }

    // Test filtering by value range
    let filter = OutputFilter::new()
        .with_wallet_id(wallet_id)
        .with_value_range(2_000_000, 5_000_000);
    let high_value_outputs = storage.get_outputs(Some(filter)).await?;
    println!("💎 High value outputs (2-5 T): {}", high_value_outputs.len());

    // Demonstrate spending an output
    println!("\n💸 Spending Output:");
    println!("==================");
    
    let tx_id = 12345;
    storage.mark_output_spent(output_id1, tx_id).await?;
    println!("✅ Marked output {} as spent in transaction {}", output_id1, tx_id);

    // Verify the output was marked as spent
    let updated_output = storage.get_output_by_id(output_id1).await?.unwrap();
    println!("📊 Output {} status: {}, spent_in_tx: {:?}", 
        output_id1,
        match updated_output.status {
            0 => "Unspent",
            1 => "Spent",
            _ => "Other",
        },
        updated_output.spent_in_tx_id
    );

    // Check updated spendable balance
    let new_balance = storage.get_spendable_balance(wallet_id, current_height).await?;
    println!("💰 Updated spendable balance: {} μT ({:.6} T)", 
        new_balance, new_balance as f64 / 1_000_000.0);

    // Demonstrate batch operations
    println!("\n📦 Batch Operations:");
    println!("===================");

    let batch_outputs = vec![
        StoredOutput {
            id: None,
            wallet_id,
            commitment: vec![0x21; 32],
            hash: vec![0x22; 32],
            value: 500_000,
            spending_key: "5555555555555555555555555555555555555555555555555555555555555555".to_string(),
            script_private_key: "6666666666666666666666666666666666666666666666666666666666666666".to_string(),
            script: vec![0x23; 64],
            input_data: vec![0x24; 32],
            covenant: vec![0x25; 32],
            output_type: 0,
            features_json: serde_json::to_string(&LightweightOutputFeatures::default()).unwrap(),
            maturity: 100,
            script_lock_height: 0,
            sender_offset_public_key: vec![0x26; 32],
            metadata_signature_ephemeral_commitment: vec![0x27; 32],
            metadata_signature_ephemeral_pubkey: vec![0x28; 32],
            metadata_signature_u_a: vec![0x29; 32],
            metadata_signature_u_x: vec![0x2a; 32],
            metadata_signature_u_y: vec![0x2b; 32],
            encrypted_data: vec![0x2c; 64],
            minimum_value_promise: 500_000,
            rangeproof: Some(vec![0x2d; 128]),
            status: OutputStatus::Unspent as u32,
            mined_height: Some(300),
            spent_in_tx_id: None,
            created_at: None,
            updated_at: None,
        },
        StoredOutput {
            id: None,
            wallet_id,
            commitment: vec![0x31; 32],
            hash: vec![0x32; 32],
            value: 750_000,
            spending_key: "7777777777777777777777777777777777777777777777777777777777777777".to_string(),
            script_private_key: "8888888888888888888888888888888888888888888888888888888888888888".to_string(),
            script: vec![0x33; 64],
            input_data: vec![0x34; 32],
            covenant: vec![0x35; 32],
            output_type: 0,
            features_json: serde_json::to_string(&LightweightOutputFeatures::default()).unwrap(),
            maturity: 100,
            script_lock_height: 0,
            sender_offset_public_key: vec![0x36; 32],
            metadata_signature_ephemeral_commitment: vec![0x37; 32],
            metadata_signature_ephemeral_pubkey: vec![0x38; 32],
            metadata_signature_u_a: vec![0x39; 32],
            metadata_signature_u_x: vec![0x3a; 32],
            metadata_signature_u_y: vec![0x3b; 32],
            encrypted_data: vec![0x3c; 64],
            minimum_value_promise: 750_000,
            rangeproof: Some(vec![0x3d; 128]),
            status: OutputStatus::Unspent as u32,
            mined_height: Some(300),
            spent_in_tx_id: None,
            created_at: None,
            updated_at: None,
        }
    ];

    let batch_ids = storage.save_outputs(&batch_outputs).await?;
    println!("✅ Saved batch of {} outputs with IDs: {:?}", batch_outputs.len(), batch_ids);

    // Final statistics
    println!("\n📈 Final Statistics:");
    println!("===================");
    
    let total_outputs = storage.get_output_count(wallet_id).await?;
    let final_balance = storage.get_spendable_balance(wallet_id, current_height).await?;
    let unspent_outputs = storage.get_unspent_outputs(wallet_id).await?;
    
    println!("📊 Total outputs: {}", total_outputs);
    println!("💰 Final spendable balance: {} μT ({:.6} T)", 
        final_balance, final_balance as f64 / 1_000_000.0);
    println!("🔓 Unspent outputs: {}", unspent_outputs.len());

    println!("\n🎉 Example completed successfully!");
    println!("💡 The outputs table now contains all data needed for transaction creation");
    println!("💡 This works alongside the existing transaction storage for wallet history");

    Ok(())
}

#[cfg(not(feature = "storage"))]
fn main() {
    eprintln!("This example requires the 'storage' feature to be enabled.");
    eprintln!("Run with: cargo run --example utxo_management --features storage");
    std::process::exit(1);
} 