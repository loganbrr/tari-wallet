#[cfg(feature = "storage")]
use lightweight_wallet_libs::data_structures::address::TariAddressFeatures;
#[cfg(feature = "storage")]
use lightweight_wallet_libs::wallet::Wallet;
#[cfg(feature = "storage")]
use clap::{Parser, Subcommand};

// Storage-related imports
#[cfg(feature = "storage")]
use lightweight_wallet_libs::{
    storage::{SqliteStorage, WalletStorage, StoredWallet},
    data_structures::types::PrivateKey,
    key_management::{
        key_derivation,
        seed_phrase::{mnemonic_to_bytes, CipherSeed},
    },
    utils::number::format_number,
    LightweightWalletError,
};

/// Tari Wallet CLI
#[cfg(feature = "storage")]
#[derive(Parser)]
#[command(name = "wallet")]
#[command(about = "Tari Wallet CLI - Generate wallets, addresses, and manage database storage")]
#[command(version, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[cfg(feature = "storage")]
#[derive(Subcommand)]
enum Commands {
    /// Generate a new wallet with seed phrase and one-sided address
    Generate {
        /// Network to use (mainnet, esmeralda, stagenet)
        #[arg(long, default_value = "mainnet")]
        network: String,
        
        /// Payment ID as UTF-8 string (e.g., "my-payment-123")
        #[arg(long)]
        payment_id: Option<String>,
        
        /// Optional passphrase for CipherSeed encryption/decryption
        #[arg(long)]
        passphrase: Option<String>,
    },
    
    /// Generate a one-sided address from existing seed phrase
    NewAddress {
        /// Seed phrase for the wallet
        seed_phrase: String,
        
        /// Network to use (mainnet, esmeralda, stagenet)
        #[arg(long, default_value = "mainnet")]
        network: String,
        
        /// Payment ID as UTF-8 string (e.g., "my-payment-123")
        #[arg(long)]
        payment_id: Option<String>,
        
        /// Optional passphrase for CipherSeed encryption/decryption
        #[arg(long)]
        passphrase: Option<String>,
    },
    
    /// List all wallets stored in database
    List {
        /// Database file path
        #[arg(long, default_value = "./wallet.db")]
        database: String,
    },
    
    /// Create and store a new wallet in database from seed phrase
    AddWallet {
        /// Seed phrase for the wallet
        seed_phrase: String,
        
        /// Wallet name (required)
        #[arg(long)]
        name: String,
        
        /// Database file path
        #[arg(long, default_value = "./wallet.db")]
        database: String,
        
        /// Network to use (mainnet, esmeralda, stagenet)
        #[arg(long, default_value = "mainnet")]
        network: String,
        
        /// Optional passphrase for CipherSeed encryption/decryption
        #[arg(long)]
        passphrase: Option<String>,
    },
    
    /// Clear all data from database
    ClearDatabase {
        /// Database file path
        #[arg(long, default_value = "./wallet.db")]
        database: String,
    },
}

// Async main function to support database operations
#[cfg(feature = "storage")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Generate { network, payment_id, passphrase } => {
            handle_generate(network, payment_id, passphrase).await?;
        }
        Commands::NewAddress { seed_phrase, network, payment_id, passphrase } => {
            handle_new_address(seed_phrase, network, payment_id, passphrase).await?;
        }
        Commands::List { database } => {
            handle_list_wallets(database).await?;
        }
        Commands::AddWallet { seed_phrase, name, database, network, passphrase } => {
            handle_create_wallet(seed_phrase, name, database, network, passphrase).await?;
        }
        Commands::ClearDatabase { database } => {
            handle_clear_database(database).await?;
        }
    }
    
    Ok(())
}

// Non-storage version for when storage feature is not enabled
#[cfg(not(feature = "storage"))]
fn main() {
    eprintln!("❌ Error: This wallet binary requires the 'storage' feature to be enabled for full CLI functionality.");
    eprintln!("💡 Run with: cargo run --bin wallet --features storage");
    eprintln!();
    eprintln!("Available commands:");
    eprintln!("  generate        Generate a new wallet with seed phrase and one-sided address");
    eprintln!("  new-address     Generate a one-sided address from existing seed phrase");
    eprintln!("  list            List all wallets stored in database");
    eprintln!("  add-wallet      Create and store a new wallet in database from seed phrase");
    eprintln!("  clear-database  Clear all data from database");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  cargo run --bin wallet --features storage generate --help");
    eprintln!("  cargo run --bin wallet --features storage list");
    std::process::exit(1);
}

// Storage-enabled versions of functions
#[cfg(feature = "storage")]
async fn handle_generate(
    network: String,
    payment_id: Option<String>,
    passphrase: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate network
    if !is_valid_network(&network) {
        eprintln!("Error: Invalid network '{}'. Valid networks: mainnet, esmeralda, stagenet", network);
        return Ok(());
    }
    
    let payment_id_bytes = payment_id.map(|s| s.as_bytes().to_vec());
    let passphrase_ref = passphrase.as_deref();
    
    // Generate new wallet
    match Wallet::generate_new_with_seed_phrase(passphrase_ref) {
        Ok(mut wallet) => {
            wallet.set_network(network.clone());
            
            // Get seed phrase
            match wallet.export_seed_phrase() {
                Ok(seed) => {
                    println!("Seed: {}", seed);
                    
                    // Generate one-sided address using dual address method to support payment ID
                    match wallet.get_dual_address(TariAddressFeatures::create_one_sided_only(), payment_id_bytes) {
                        Ok(address) => {
                            println!("Base58: {}", address.to_base58());
                            println!("Emoji: {}", address.to_emoji_string());
                            println!("Birthday: {}", wallet.birthday());
                            
                            // Print additional info if payment ID was provided
                            if address.features().contains(TariAddressFeatures::PAYMENT_ID) {
                                println!("Payment ID included: Yes");
                            }
                        }
                        Err(e) => eprintln!("Error generating address: {}", e),
                    }
                }
                Err(e) => eprintln!("Error exporting seed: {}", e),
            }
        }
        Err(e) => eprintln!("Error creating wallet: {}", e),
    }
    
    Ok(())
}

#[cfg(feature = "storage")]
async fn handle_new_address(
    seed_phrase: String,
    network: String,
    payment_id: Option<String>,
    passphrase: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate network
    if !is_valid_network(&network) {
        eprintln!("Error: Invalid network '{}'. Valid networks: mainnet, esmeralda, stagenet", network);
        return Ok(());
    }
    
    let payment_id_bytes = payment_id.map(|s| s.as_bytes().to_vec());
    let passphrase_ref = passphrase.as_deref();
    
    // Create wallet from seed
    match Wallet::new_from_seed_phrase(&seed_phrase, passphrase_ref) {
        Ok(mut wallet) => {
            wallet.set_network(network.clone());
            
            // Generate one-sided address using dual address method to support payment ID
            match wallet.get_dual_address(TariAddressFeatures::create_one_sided_only(), payment_id_bytes) {
                Ok(address) => {
                    println!("Base58: {}", address.to_base58());
                    println!("Emoji: {}", address.to_emoji_string());
                    
                    // Print additional info if payment ID was provided
                    if address.features().contains(TariAddressFeatures::PAYMENT_ID) {
                        println!("Payment ID included: Yes");
                    }
                }
                Err(e) => eprintln!("Error generating address: {}", e),
            }
        }
        Err(e) => eprintln!("Error creating wallet from seed: {}", e),
    }
    
    Ok(())
}

/// List all wallets stored in the database
#[cfg(feature = "storage")]
async fn handle_list_wallets(database_path: String) -> Result<(), Box<dyn std::error::Error>> {
    // Create storage connection
    let storage: Box<dyn WalletStorage> = if database_path == ":memory:" {
        Box::new(SqliteStorage::new_in_memory().await?)
    } else {
        Box::new(SqliteStorage::new(&database_path).await?)
    };
    
    storage.initialize().await?;
    
    // List wallets
    let wallets = storage.list_wallets().await?;
    if wallets.is_empty() {
        println!("📂 No wallets found in database: {}", database_path);
    } else {
        println!("📂 Available wallets in database: {}", database_path);
        for wallet in &wallets {
            let wallet_type = if wallet.has_seed_phrase() {
                "Full (seed phrase)"
            } else if wallet.can_spend() {
                "Full (keys)"
            } else {
                "View-only"
            };

            println!(
                "  • {} - {} (birthday: block {})",
                wallet.name,
                wallet_type,
                format_number(wallet.birthday_block)
            );
        }
    }
    
    Ok(())
}

/// Create and store a new wallet in the database
#[cfg(feature = "storage")]
async fn handle_create_wallet(
    seed_phrase: String,
    wallet_name: String,
    database_path: String,
    network: String,
    passphrase: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate network
    if !is_valid_network(&network) {
        eprintln!("Error: Invalid network '{}'. Valid networks: mainnet, esmeralda, stagenet", network);
        return Ok(());
    }
    
    let passphrase_ref = passphrase.as_deref();
    
    // Create storage connection
    let storage: Box<dyn WalletStorage> = if database_path == ":memory:" {
        Box::new(SqliteStorage::new_in_memory().await?)
    } else {
        Box::new(SqliteStorage::new(&database_path).await?)
    };
    
    storage.initialize().await?;
    
    // Check if wallet name already exists
    if storage.wallet_name_exists(&wallet_name).await? {
        eprintln!("Error: Wallet name '{}' already exists", wallet_name);
        return Ok(());
    }
    
    // Create wallet from seed phrase
    let wallet = Wallet::new_from_seed_phrase(&seed_phrase, passphrase_ref)?;
    
    // Derive view key and spend key from seed phrase
    let encrypted_bytes = mnemonic_to_bytes(&seed_phrase)?;
    let cipher_seed = CipherSeed::from_enciphered_bytes(&encrypted_bytes, passphrase_ref)?;
    let entropy = cipher_seed.entropy();
    
    let entropy_array: [u8; 16] = entropy.try_into()
        .map_err(|_| LightweightWalletError::KeyManagementError(
            lightweight_wallet_libs::KeyManagementError::key_derivation_failed("Invalid entropy length")
        ))?;
    
    // Derive view key
    let view_key_raw = key_derivation::derive_private_key_from_entropy(&entropy_array, "data encryption", 0)?;
    let view_key = PrivateKey::new({
        use tari_utilities::ByteArray;
        view_key_raw.as_bytes().try_into()
            .map_err(|_| LightweightWalletError::KeyManagementError(
                lightweight_wallet_libs::KeyManagementError::key_derivation_failed("Failed to convert view key")
            ))?
    });
    
    // For now, use view key as spend key - this should be properly derived from seed in production
    let spend_key = view_key.clone();
    
    // Create stored wallet
    let stored_wallet = StoredWallet::from_seed_phrase(
        wallet_name.clone(),
        seed_phrase.to_string(),
        view_key,
        spend_key,
        wallet.birthday(), // Use wallet birthday
    );
    
    // Save wallet to database
    let wallet_id = storage.save_wallet(&stored_wallet).await?;
    
    println!("✅ Created wallet '{}' with ID {} in database: {}", wallet_name, wallet_id, database_path);
    println!("   Birthday: block {}", format_number(wallet.birthday()));
    println!("   Network: {}", network);
    
    Ok(())
}

/// Clear all data from the database
#[cfg(feature = "storage")]
async fn handle_clear_database(database_path: String) -> Result<(), Box<dyn std::error::Error>> {
    if database_path == ":memory:" {
        println!("Cannot clear in-memory database");
        return Ok(());
    }
    
    // Confirm action
    println!("⚠️  WARNING: This will permanently delete ALL data from: {}", database_path);
    print!("Are you sure you want to continue? (yes/no): ");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let confirmation = input.trim().to_lowercase();
    
    if confirmation != "yes" && confirmation != "y" {
        println!("Operation cancelled");
        return Ok(());
    }
    
    // Create storage connection
    let storage: Box<dyn WalletStorage> = Box::new(SqliteStorage::new(&database_path).await?);
    storage.initialize().await?;
    
    // Clear all data
    storage.clear_all_transactions().await?;
    
    println!("✅ Database cleared successfully: {}", database_path);
    
    Ok(())
}



#[cfg(feature = "storage")]
fn is_valid_network(network: &str) -> bool {
    matches!(network, "mainnet" | "esmeralda" | "stagenet")
} 