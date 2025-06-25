//! Utility to extract raw transaction output data from a specific block
//! This will help us create unit tests with real blockchain data

#[cfg(feature = "grpc")]
use lightweight_wallet_libs::{
    scanning::{GrpcScannerBuilder, BlockchainScanner},
    errors::LightweightWalletResult,
};

#[cfg(feature = "grpc")]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    println!("Extracting raw block data from block 34926");
    println!("==========================================");

    // Create GRPC scanner
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
            return Err(e);
        }
    };

    // Extract block 35778 specifically
    let block_height = 35778;
    println!("Fetching block {}...", block_height);

    // Create a minimal scan config to get the block
    let scan_config = lightweight_wallet_libs::scanning::ScanConfig {
        start_height: block_height,
        end_height: Some(block_height),
        batch_size: 1,
        request_timeout: std::time::Duration::from_secs(30),
        extraction_config: lightweight_wallet_libs::extraction::ExtractionConfig::default(),
    };

    let scan_results = scanner.scan_blocks(scan_config).await?;
    
    if let Some(block_result) = scan_results.first() {
        println!("✓ Successfully fetched block {}", block_result.height);
        println!("Block hash: {}", hex::encode(&block_result.block_hash));
        println!("Number of transaction outputs: {}", block_result.outputs.len());
        println!("Mined timestamp: {}", block_result.mined_timestamp);
        
        println!("\n=== Transaction Outputs in Block {} ===", block_height);
        
        for (i, output) in block_result.outputs.iter().enumerate() {
            println!("\n--- Output {} ---", i);
            println!("Version: {}", output.version);
            println!("Features:");
            println!("  Output type: {:?}", output.features.output_type);
            println!("  Maturity: {}", output.features.maturity);
            println!("  Range proof type: {:?}", output.features.range_proof_type);
            println!("Commitment: {}", hex::encode(output.commitment().as_bytes()));
            println!("Minimum value promise: {}", output.minimum_value_promise);
            println!("Script length: {}", output.script.bytes.len());
            println!("Script: {}", hex::encode(&output.script.bytes));
            println!("Sender offset public key: {}", hex::encode(output.sender_offset_public_key.as_bytes()));
            println!("Metadata signature length: {}", output.metadata_signature.bytes.len());
            println!("Metadata signature: {}", hex::encode(&output.metadata_signature.bytes));
            println!("Covenant length: {}", output.covenant.bytes.len());
            println!("Covenant: {}", hex::encode(&output.covenant.bytes));
            println!("Encrypted data length: {}", output.encrypted_data.as_bytes().len());
            println!("Encrypted data: {}", hex::encode(output.encrypted_data.as_bytes()));
            
            if let Some(proof) = &output.proof {
                println!("Range proof length: {}", proof.bytes.len());
                println!("Range proof: {}", hex::encode(&proof.bytes));
            } else {
                println!("Range proof: None");
            }
        }
        
        // Generate Rust code for unit test
        println!("\n=== Generated Unit Test Code ===");
        println!("```rust");
        println!("#[test]");
        println!("fn test_extract_wallet_output_block_34926() {{");
        println!("    // Known seed phrase that should have outputs in block 34926");
        println!("    let seed_phrase = \"scare pen great round cherry soul dismiss dance ghost hire color casino train execute awesome shield wire cruel mom depth enhance rough client aerobic\";");
        println!("    ");
        println!("    // Create wallet and derive keys");
        println!("    let wallet = Wallet::new_from_seed_phrase(seed_phrase, None).expect(\"Failed to create wallet\");");
        println!("    let master_key_bytes = wallet.master_key_bytes();");
        println!("    let mut entropy = [0u8; 16];");
        println!("    entropy.copy_from_slice(&master_key_bytes[..16]);");
        println!("    let (view_key, _spend_key) = derive_view_and_spend_keys_from_entropy(&entropy).expect(\"Key derivation failed\");");
        println!("    let view_key_bytes = view_key.as_bytes();");
        println!("    let mut view_key_array = [0u8; 32];");
        println!("    view_key_array.copy_from_slice(view_key_bytes);");
        println!("    let view_private_key = PrivateKey::new(view_key_array);");
        println!("    ");
        
        for (i, output) in block_result.outputs.iter().enumerate() {
            println!("    // Transaction output {} from block {}", i, block_height);
            println!("    let output_{} = LightweightTransactionOutput::new(", i);
            println!("        {},", output.version);
            println!("        LightweightOutputFeatures {{");
            println!("            output_type: {:?},", output.features.output_type);
            println!("            maturity: {},", output.features.maturity);
            println!("            range_proof_type: {:?},", output.features.range_proof_type);
            println!("        }},");
            println!("        CompressedCommitment::new(hex::decode(\"{}\").unwrap().try_into().unwrap()),", hex::encode(output.commitment().as_bytes()));
            
            if let Some(proof) = &output.proof {
                println!("        Some(LightweightRangeProof {{ bytes: hex::decode(\"{}\").unwrap() }}),", hex::encode(&proof.bytes));
            } else {
                println!("        None,");
            }
            
            println!("        LightweightScript {{ bytes: hex::decode(\"{}\").unwrap() }},", hex::encode(&output.script.bytes));
            println!("        CompressedPublicKey::new(hex::decode(\"{}\").unwrap().try_into().unwrap()),", hex::encode(output.sender_offset_public_key.as_bytes()));
            println!("        LightweightSignature {{ bytes: hex::decode(\"{}\").unwrap() }},", hex::encode(&output.metadata_signature.bytes));
            println!("        LightweightCovenant {{ bytes: hex::decode(\"{}\").unwrap() }},", hex::encode(&output.covenant.bytes));
            println!("        EncryptedData::from_bytes(&hex::decode(\"{}\").unwrap()).expect(\"Invalid encrypted data\"),", hex::encode(output.encrypted_data.as_bytes()));
            println!("        MicroMinotari::new({}),", output.minimum_value_promise.as_u64());
            println!("    );");
            println!("    ");
            println!("    // Test extraction with wallet keys");
            println!("    let config = ExtractionConfig::with_private_key(view_private_key.clone());");
            println!("    let result = extract_wallet_output(&output_{}, &config);", i);
            println!("    ");
            println!("    match result {{");
            println!("        Ok(wallet_output) => {{");
            println!("            println!(\"✓ Successfully extracted wallet output {} with value: {{}}\", wallet_output.value().as_u64());", i);
            println!("            println!(\"  Payment ID: {{:?}}\", wallet_output.payment_id());");
            println!("            // This output belongs to our wallet");
            println!("        }},");
            println!("        Err(e) => {{");
            println!("            println!(\"✗ Failed to extract output {}: {{}}\", e);", i);
            println!("            // This output doesn't belong to our wallet");
            println!("        }}");
            println!("    }}");
            println!("}}");
            println!("```");
        }
        
    } else {
        println!("✗ No block data found for height {}", block_height);
    }

    Ok(())
}

#[cfg(not(feature = "grpc"))]
fn main() {
    eprintln!("This utility requires the 'grpc' feature to be enabled.");
    eprintln!("Run with: cargo run --example extract_block_data --features grpc");
    std::process::exit(1);
} 