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
//! # *** DATABASE STORAGE FEATURES (requires 'grpc-storage' feature) ***
//! # Persist transactions to SQLite database
//! cargo run --example scanner --features grpc-storage -- --seed-phrase "your seed phrase" --database wallet.db
//!
//! # Clear existing database and start fresh
//! cargo run --example scanner --features grpc-storage -- --seed-phrase "your seed phrase" --database wallet.db --clear-database
//!
//! # Resume scanning from last processed block in database
//! cargo run --example scanner --features grpc-storage -- --seed-phrase "your seed phrase" --database wallet.db --resume
//!
//! # Resume scanning without providing seed phrase (loads keys from stored wallet)
//! cargo run --example scanner --features grpc-storage -- --database wallet.db --resume
//!
//! # Use in-memory database (useful for testing)
//! cargo run --example scanner --features grpc-storage -- --seed-phrase "your seed phrase" --database ":memory:"
//!
//! # *** WALLET MANAGEMENT FEATURES ***
//! # List all wallets in database
//! cargo run --example scanner --features grpc-storage -- --database wallet.db --list-wallets
//!
//! # Create a new wallet in database
//! cargo run --example scanner --features grpc-storage -- --seed-phrase "your seed phrase" --database wallet.db --create-wallet --wallet-name "my-wallet"
//!
//! # Use specific wallet for scanning
//! cargo run --example scanner --features grpc-storage -- --database wallet.db --wallet-name "my-wallet" --resume
//!
//! # Scanner will auto-select wallet if only one exists, or create default wallet if none exist
//! cargo run --example scanner --features grpc-storage -- --database wallet.db --resume
//!
//! # Resume specific wallet without providing keys (loads keys from database)
//! cargo run --example scanner --features grpc-storage -- --database wallet.db --wallet-name "my-wallet" --resume
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
use clap::Parser;
#[cfg(feature = "grpc")]
use lightweight_wallet_libs::{
    data_structures::{
        block::Block, payment_id::PaymentId, transaction::TransactionDirection,
        transaction_output::LightweightTransactionOutput, types::{PrivateKey, CompressedCommitment},
        wallet_transaction::WalletState,
    },
    errors::LightweightWalletResult,
    key_management::{
        key_derivation,
        seed_phrase::{mnemonic_to_bytes, CipherSeed},
    },
    scanning::{BlockchainScanner, GrpcBlockchainScanner, GrpcScannerBuilder},
    utils::number::format_number,
    wallet::Wallet,
    KeyManagementError,
    LightweightWalletError,
};
#[cfg(all(feature = "grpc", feature = "storage"))]
use lightweight_wallet_libs::{
    storage::{OutputStatus, SqliteStorage, StoredOutput, WalletStorage, StoredWallet},
    errors::ValidationError,
};
#[cfg(feature = "grpc")]
use tari_utilities::ByteArray;
#[cfg(feature = "grpc")]
use tokio::signal;
#[cfg(feature = "grpc")]
use tokio::time::Instant;

/// Enhanced Tari Wallet Scanner CLI
#[cfg(feature = "grpc")]
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Seed phrase for the wallet (required unless --view-key is provided or --resume with --database)
    #[arg(short, long, help = "Seed phrase for the wallet")]
    seed_phrase: Option<String>,

    /// Private view key in hex format (alternative to seed phrase)
    #[arg(
        long,
        help = "Private view key in hex format (64 characters). Alternative to --seed-phrase. Not required when resuming from database"
    )]
    view_key: Option<String>,

    /// Base URL for the Tari base node GRPC endpoint
    #[arg(
        short,
        long,
        default_value = "http://127.0.0.1:18142",
        help = "Base URL for Tari base node GRPC"
    )]
    base_url: String,

    /// Starting block height for scanning
    #[arg(
        long,
        help = "Starting block height (defaults to wallet birthday or 0 for view-key mode)"
    )]
    from_block: Option<u64>,

    /// Ending block height for scanning
    #[arg(long, help = "Ending block height (defaults to current tip)")]
    to_block: Option<u64>,

    /// Specific block heights to scan (comma-separated)
    #[arg(
        long,
        help = "Specific block heights to scan (comma-separated). If provided, overrides from-block and to-block",
        value_delimiter = ','
    )]
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
    #[arg(
        long,
        default_value = "summary",
        help = "Output format: detailed, summary, json"
    )]
    format: String,

    /// Enable detailed profiling output
    #[arg(long, help = "Enable detailed performance profiling")]
    profile: bool,

    /// Database file path for storing transactions (optional, enables persistence)
    #[arg(
        long,
        help = "SQLite database file path for storing transactions. If not provided, transactions are only stored in memory"
    )]
    database: Option<String>,

    /// Clear existing database before scanning
    #[arg(
        long,
        help = "Clear all existing transactions from database before starting scan"
    )]
    clear_database: bool,

    /// Resume scan from last processed block in database
    #[arg(
        long,
        help = "Resume scanning from the highest block height stored in database"
    )]
    resume: bool,

    /// Wallet name to use for scanning (when using database storage)
    #[arg(
        long,
        help = "Wallet name to use for scanning. If not provided with database, will prompt for selection or creation"
    )]
    wallet_name: Option<String>,

    /// Create a new wallet in the database
    #[arg(
        long,
        help = "Create a new wallet in the database with the provided name"
    )]
    create_wallet: bool,

    /// List available wallets in the database
    #[arg(long, help = "List all available wallets in the database and exit")]
    list_wallets: bool,
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
    pub database_path: Option<String>,
    pub clear_database: bool,
    pub resume: bool,
    pub wallet_name: Option<String>,
    pub create_wallet: bool,
    pub list_wallets: bool,
    pub explicit_from_block: Option<u64>,
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
            _ => Err(format!(
                "Invalid output format: {}. Valid options: detailed, summary, json",
                s
            )),
        }
    }
}

/// Unified storage handler for the scanner
#[cfg(feature = "grpc")]
pub struct ScannerStorage {
    #[cfg(feature = "storage")]
    pub database: Option<Box<dyn WalletStorage>>,
    pub wallet_id: Option<u32>,
    pub is_memory_only: bool,
}

#[cfg(feature = "grpc")]
impl ScannerStorage {
    /// Create a new scanner storage instance (memory-only mode)
    pub fn new_memory() -> Self {
        Self {
            #[cfg(feature = "storage")]
            database: None,
            wallet_id: None,
            is_memory_only: true,
        }
    }

    /// Create a new scanner storage instance with database
    #[cfg(feature = "storage")]
    pub async fn new_with_database(
        database_path: &str,
        clear_database: bool,
    ) -> LightweightWalletResult<Self> {
        let storage: Box<dyn WalletStorage> = if database_path == ":memory:" {
            Box::new(SqliteStorage::new_in_memory().await?)
        } else {
            Box::new(SqliteStorage::new(database_path).await?)
        };

        storage.initialize().await?;

        if clear_database {
            storage.clear_all_transactions().await?;
        }

        Ok(Self {
            database: Some(storage),
            wallet_id: None,
            is_memory_only: false,
        })
    }

    /// List available wallets in the database
    #[cfg(feature = "storage")]
    pub async fn list_wallets(&self) -> LightweightWalletResult<Vec<StoredWallet>> {
        if let Some(storage) = &self.database {
            storage.list_wallets().await
        } else {
            Ok(Vec::new())
        }
    }

    /// Handle wallet operations (list, create, select)
    #[cfg(feature = "storage")]
    pub async fn handle_wallet_operations(
        &mut self,
        config: &ScanConfig,
        scan_context: Option<&ScanContext>,
        original_seed_phrase: Option<&str>,
    ) -> LightweightWalletResult<Option<ScanContext>> {
        let storage = match &self.database {
            Some(storage) => storage,
            None => return Ok(None), // Memory-only mode
        };

        // Handle list wallets command
        if config.list_wallets {
            let wallets = storage.list_wallets().await?;
            if wallets.is_empty() {
                println!("📂 No wallets found in database");
            } else {
                println!("📂 Available wallets:");
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
            return Ok(None); // Exit after listing
        }

        // Handle wallet creation
        if config.create_wallet {
            let wallet_name = config.wallet_name.as_ref().ok_or_else(|| {
                LightweightWalletError::InvalidArgument {
                    argument: "wallet_name".to_string(),
                    value: "None".to_string(),
                    message: "Wallet name is required when creating a wallet".to_string(),
                }
            })?;

            // Check if wallet name already exists
            if storage.wallet_name_exists(wallet_name).await? {
                return Err(LightweightWalletError::InvalidArgument {
                    argument: "wallet_name".to_string(),
                    value: wallet_name.clone(),
                    message: "Wallet name already exists".to_string(),
                });
            }

            // Create new wallet from scan context
            let wallet = if let Some(seed_phrase) = original_seed_phrase {
                // Create from seed phrase - derive and store all keys
                if let Some(scan_ctx) = scan_context {
                    let view_key = scan_ctx.view_key.clone();
                    // For now, use view key as spend key - this should be properly derived from seed in production
                    let spend_key = view_key.clone();

                    StoredWallet::from_seed_phrase(
                        wallet_name.clone(),
                        seed_phrase.to_string(),
                        view_key,
                        spend_key,
                        0, // Default birthday
                    )
                } else {
                    return Err(LightweightWalletError::InvalidArgument {
                        argument: "scan_context".to_string(),
                        value: "None".to_string(),
                        message: "Scan context is required when creating wallet from seed phrase"
                            .to_string(),
                    });
                }
            } else if let Some(scan_ctx) = scan_context {
                StoredWallet::view_only(
                    wallet_name.clone(),
                    scan_ctx.view_key.clone(),
                    0, // Default birthday
                )
            } else {
                return Err(LightweightWalletError::InvalidArgument {
                    argument: "scan_context".to_string(),
                    value: "None".to_string(),
                    message: "Scan context is required when creating wallet".to_string(),
                });
            };

            let wallet_id = storage.save_wallet(&wallet).await?;
            self.wallet_id = Some(wallet_id);
            println!("✅ Created wallet '{}' with ID {}", wallet_name, wallet_id);
            return Ok(None);
        }

        // Handle wallet selection and loading
        self.wallet_id = self.select_or_create_wallet(config, scan_context).await?;

        // Load scan context from database if needed
        if scan_context.is_none() && self.wallet_id.is_some() {
            self.load_scan_context_from_wallet(config.quiet).await
        } else {
            Ok(None)
        }
    }

    /// Select or create a wallet
    #[cfg(feature = "storage")]
    async fn select_or_create_wallet(
        &self,
        config: &ScanConfig,
        scan_context: Option<&ScanContext>,
    ) -> LightweightWalletResult<Option<u32>> {
        let storage = self.database.as_ref().unwrap();

        // Handle wallet selection by name
        if let Some(wallet_name) = &config.wallet_name {
            if let Some(wallet) = storage.get_wallet_by_name(wallet_name).await? {
                println!("📂 Using wallet: {}", wallet.name);
                return Ok(wallet.id);
            } else {
                return Err(LightweightWalletError::ResourceNotFound(format!(
                    "Wallet '{}' not found",
                    wallet_name
                )));
            }
        }

        // Auto-select wallet or prompt for creation
        let wallets = storage.list_wallets().await?;
        if wallets.is_empty() {
            if let Some(scan_ctx) = scan_context {
                println!("📂 No wallets found. Creating default wallet...");
                let wallet =
                    StoredWallet::view_only("default".to_string(), scan_ctx.view_key.clone(), 0);
                let wallet_id = storage.save_wallet(&wallet).await?;
                println!("✅ Created default wallet with ID {}", wallet_id);
                return Ok(Some(wallet_id));
            } else {
                return Err(LightweightWalletError::InvalidArgument {
                    argument: "wallets".to_string(),
                    value: "empty".to_string(),
                    message: "No wallets found and no keys provided to create one. Provide --seed-phrase or --view-key, or use an existing wallet.".to_string(),
                });
            }
        } else if wallets.len() == 1 {
            let wallet = &wallets[0];
            println!("📂 Using wallet: {}", wallet.name);
            return Ok(wallet.id);
        } else {
            // Multiple wallets available - for now, use the first one
            let wallet = &wallets[0];
            println!("📂 Multiple wallets found, using: {}", wallet.name);
            return Ok(wallet.id);
        }
    }

    /// Load scan context from stored wallet
    #[cfg(feature = "storage")]
    async fn load_scan_context_from_wallet(
        &self,
        quiet: bool,
    ) -> LightweightWalletResult<Option<ScanContext>> {
        let storage = self.database.as_ref().unwrap();
        let wallet_id = self.wallet_id.unwrap();

        if let Some(wallet) = storage.get_wallet_by_id(wallet_id).await? {
            if !quiet {
                println!("🔑 Loading keys from stored wallet...");
            }

            let view_key = wallet.get_view_key().map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to get view key: {}", e))
            })?;

            // Create entropy array - derive from seed phrase if available
            let entropy = if wallet.has_seed_phrase() {
                // Derive entropy from stored seed phrase
                if let Some(seed_phrase) = &wallet.seed_phrase {
                    match derive_entropy_from_seed_phrase(seed_phrase) {
                        Ok(entropy_array) => entropy_array,
                        Err(_) => {
                            if !quiet {
                                println!("⚠️  Warning: Failed to derive entropy from stored seed phrase, using view-key mode");
                            }
                            [0u8; 16]
                        }
                    }
                } else {
                    [0u8; 16]
                }
            } else {
                [0u8; 16] // View-only wallet
            };

            Ok(Some(ScanContext { view_key, entropy }))
        } else {
            Err(LightweightWalletError::ResourceNotFound(format!(
                "Wallet with ID {} not found",
                wallet_id
            )))
        }
    }

    /// Get wallet birthday for resume functionality
    #[cfg(feature = "storage")]
    pub async fn get_wallet_birthday(&self) -> LightweightWalletResult<Option<u64>> {
        if let (Some(storage), Some(wallet_id)) = (&self.database, self.wallet_id) {
            if let Some(wallet) = storage.get_wallet_by_id(wallet_id).await? {
                Ok(Some(wallet.get_resume_block()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Save transactions to storage
    #[cfg(feature = "storage")]
    pub async fn save_transactions(
        &self,
        transactions: &[lightweight_wallet_libs::data_structures::wallet_transaction::WalletTransaction],
    ) -> LightweightWalletResult<()> {
        if let (Some(storage), Some(wallet_id)) = (&self.database, self.wallet_id) {
            storage.save_transactions(wallet_id, transactions).await
        } else {
            Ok(()) // Memory-only mode
        }
    }

    /// Save UTXO outputs to storage
    #[cfg(feature = "storage")]
    pub async fn save_outputs(&self, outputs: &[StoredOutput]) -> LightweightWalletResult<Vec<u32>> {
        if let Some(storage) = &self.database {
            storage.save_outputs(outputs).await
        } else {
            Ok(Vec::new()) // Memory-only mode
        }
    }

    /// Update wallet's latest scanned block
    #[cfg(feature = "storage")]
    pub async fn update_wallet_scanned_block(&self, block_height: u64) -> LightweightWalletResult<()> {
        if let (Some(storage), Some(wallet_id)) = (&self.database, self.wallet_id) {
            storage.update_wallet_scanned_block(wallet_id, block_height).await
        } else {
            Ok(()) // Memory-only mode
        }
    }

    /// Mark outputs as spent (DEPRECATED - spending is now handled automatically by wallet state)
    /// This method is kept for compatibility but is no longer used in the main scanning flow.
    /// Spending detection is handled by wallet_state.mark_output_spent() called from block.process_inputs()
    #[cfg(feature = "storage")]
    pub async fn mark_outputs_spent(&self, spent_outputs: &[(Vec<u8>, u64, usize)]) -> LightweightWalletResult<()> {
        if let Some(storage) = &self.database {
            for (commitment, block_height, input_index) in spent_outputs {
                // Get the output by commitment
                if let Some(mut output) = storage.get_output_by_commitment(commitment).await? {
                    // Calculate transaction ID
                    let tx_id = generate_transaction_id(*block_height, *input_index);
                    
                    // Update the output as spent
                    output.status = OutputStatus::Spent as u32;
                    output.spent_in_tx_id = Some(tx_id);
                    
                    // Save the updated output
                    storage.update_output(&output).await?;
                }
            }
        }
        Ok(())
    }

    /// Get storage statistics for the current wallet
    #[cfg(feature = "storage")]
    pub async fn get_statistics(&self) -> LightweightWalletResult<lightweight_wallet_libs::storage::StorageStats> {
        if let Some(storage) = &self.database {
            // Get wallet-specific statistics if we have a wallet_id
            storage.get_wallet_statistics(self.wallet_id).await
        } else {
            // Return empty statistics for memory-only mode
            Ok(lightweight_wallet_libs::storage::StorageStats {
                total_transactions: 0,
                inbound_count: 0,
                outbound_count: 0,
                unspent_count: 0,
                spent_count: 0,
                total_received: 0,
                total_spent: 0,
                current_balance: 0,
                lowest_block: None,
                highest_block: None,
                latest_scanned_block: None,
            })
        }
    }

    /// Get unspent outputs count
    #[cfg(feature = "storage")]
    pub async fn get_unspent_outputs_count(&self) -> LightweightWalletResult<usize> {
        if let (Some(storage), Some(wallet_id)) = (&self.database, self.wallet_id) {
            let outputs = storage.get_unspent_outputs(wallet_id).await?;
            Ok(outputs.len())
        } else {
            Ok(0)
        }
    }

    /// Display storage information
    pub async fn display_storage_info(&self, config: &ScanConfig) -> LightweightWalletResult<()> {
        if config.quiet {
            return Ok(());
        }

        if self.is_memory_only {
            println!("💭 Using in-memory storage (transactions will not be persisted)");
            return Ok(());
        }

        #[cfg(feature = "storage")]
        if let Some(_storage) = &self.database {
            if let Some(db_path) = &config.database_path {
                println!("💾 Using SQLite database: {}", db_path);
                if config.clear_database {
                    println!("🗑️  Database cleared before scanning");
                }
            } else {
                println!("💾 Using in-memory database");
            }

            // Show existing data if any
            let stats = self.get_statistics().await?;
            if stats.total_transactions > 0 {
                println!(
                    "📄 Existing data: {} transactions, balance: {:.6} T, blocks: {}-{}",
                    format_number(stats.total_transactions),
                    stats.current_balance as f64 / 1_000_000.0,
                    format_number(stats.lowest_block.unwrap_or(0)),
                    format_number(stats.highest_block.unwrap_or(0))
                );
            }
        }

        Ok(())
    }

    /// Display completion information
    pub async fn display_completion_info(&self, config: &ScanConfig) -> LightweightWalletResult<()> {
        if config.quiet {
            return Ok(());
        }

        if self.is_memory_only {
            println!("💭 Transactions stored in memory only (not persisted)");
            return Ok(());
        }

        #[cfg(feature = "storage")]
        if let Some(_storage) = &self.database {
            let stats = self.get_statistics().await?;
            println!(
                "💾 Database updated: {} total transactions stored",
                format_number(stats.total_transactions)
            );
            if config.resume {
                println!(
                    "📍 Next scan can resume from block {}",
                    format_number(stats.highest_block.unwrap_or(0) + 1)
                );
            }

            // Also show UTXO output count if available
            let utxo_count = self.get_unspent_outputs_count().await?;
            if utxo_count > 0 {
                println!(
                    "🔗 UTXO outputs stored: {} (ready for transaction creation)",
                    format_number(utxo_count)
                );
            }
        }

        Ok(())
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

        let entropy_array: [u8; 16] = entropy
            .try_into()
            .map_err(|_| KeyManagementError::key_derivation_failed("Invalid entropy length"))?;

        let view_key_raw =
            key_derivation::derive_private_key_from_entropy(&entropy_array, "data encryption", 0)?;
        let view_key = PrivateKey::new(
            view_key_raw
                .as_bytes()
                .try_into()
                .expect("Should convert to array"),
        );

        Ok(Self {
            view_key,
            entropy: entropy_array,
        })
    }

    pub fn from_view_key(view_key_hex: &str) -> LightweightWalletResult<Self> {
        // Parse the hex view key
        let view_key_bytes = hex::decode(view_key_hex).map_err(|_| {
            KeyManagementError::key_derivation_failed("Invalid hex format for view key")
        })?;

        if view_key_bytes.len() != 32 {
            return Err(KeyManagementError::key_derivation_failed(
                "View key must be exactly 32 bytes (64 hex characters)",
            )
            .into());
        }

        let view_key_array: [u8; 32] = view_key_bytes.try_into().map_err(|_| {
            KeyManagementError::key_derivation_failed("Failed to convert view key to array")
        })?;

        let view_key = PrivateKey::new(view_key_array);

        let entropy = [0u8; 16];

        Ok(Self { view_key, entropy })
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
        Self {
            from_block,
            to_block,
            block_heights,
        }
    }

    pub fn into_scan_config(self, args: &CliArgs) -> LightweightWalletResult<ScanConfig> {
        let output_format = args
            .format
            .parse()
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
            database_path: args.database.clone(),
            clear_database: args.clear_database,
            resume: args.resume,
            wallet_name: args.wallet_name.clone(),
            create_wallet: args.create_wallet,
            list_wallets: args.list_wallets,
            explicit_from_block: args.from_block,
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
        }
        "s" | "skip" => {
            println!("   ⏭️  Skipping problematic batch/block and continuing...");
            true // Continue (skip this batch/block)
        }
        _ => {
            println!(
                "   🛑 Scan aborted by user at block {}",
                format_number(error_block_height)
            );
            println!("\n💡 To resume from this point, run:");
            if has_specific_blocks {
                let remaining_blocks_str: Vec<String> =
                    remaining_blocks.iter().map(|b| b.to_string()).collect();
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

/// Derive entropy from a seed phrase string
#[cfg(all(feature = "grpc", feature = "storage"))]
fn derive_entropy_from_seed_phrase(seed_phrase: &str) -> LightweightWalletResult<[u8; 16]> {
    use lightweight_wallet_libs::key_management::seed_phrase::{mnemonic_to_bytes, CipherSeed};
    
    let encrypted_bytes = mnemonic_to_bytes(seed_phrase)?;
    let cipher_seed = CipherSeed::from_enciphered_bytes(&encrypted_bytes, None)?;
    let entropy = cipher_seed.entropy();
    
    let entropy_array: [u8; 16] = entropy.try_into()
        .map_err(|_| KeyManagementError::key_derivation_failed("Invalid entropy length"))?;
    
    Ok(entropy_array)
}

/// Extract UTXO data from blockchain outputs and create StoredOutput objects
#[cfg(all(feature = "grpc", feature = "storage"))]
fn extract_utxo_outputs_from_wallet_state(
    wallet_state: &WalletState,
    scan_context: &ScanContext,
    wallet_id: u32,
    block_outputs: &[LightweightTransactionOutput],
    block_height: u64,
) -> LightweightWalletResult<Vec<StoredOutput>> {
    use lightweight_wallet_libs::data_structures::transaction::TransactionDirection;

    let mut utxo_outputs = Vec::new();

    // Get inbound transactions from this specific block
    let block_transactions: Vec<_> = wallet_state
        .transactions
        .iter()
        .filter(|tx| {
            tx.block_height == block_height
                && tx.transaction_direction == TransactionDirection::Inbound
        })
        .collect();

    for transaction in block_transactions {
        // Find the corresponding blockchain output
        if let Some(output_index) = transaction.output_index {
            if let Some(blockchain_output) = block_outputs.get(output_index) {
                // Derive spending keys for this output
                let (spending_key, script_private_key) =
                    derive_utxo_spending_keys(&scan_context.entropy, output_index as u64)?;

                // Extract script input data and lock height
                let (input_data, script_lock_height) = extract_script_data(&blockchain_output.script.bytes)?;

                // Create StoredOutput from blockchain data
                let stored_output = StoredOutput {
                    id: None, // Will be set by database
                    wallet_id,

                    // Core UTXO identification
                    commitment: blockchain_output.commitment.as_bytes().to_vec(),
                    hash: compute_output_hash(blockchain_output)?,
                    value: transaction.value,

                    // Spending keys (derived from entropy)
                    spending_key: hex::encode(spending_key.as_bytes()),
                    script_private_key: hex::encode(script_private_key.as_bytes()),

                    // Script and covenant data
                    script: blockchain_output.script.bytes.clone(),
                    input_data,
                    covenant: blockchain_output.covenant.bytes.clone(),

                    // Output features and type
                    output_type: blockchain_output.features.output_type.clone() as u32,
                    features_json: serde_json::to_string(&blockchain_output.features).map_err(
                        |e| {
                            LightweightWalletError::StorageError(format!(
                                "Failed to serialize features: {}",
                                e
                            ))
                        },
                    )?,

                    // Maturity and lock constraints
                    maturity: blockchain_output.features.maturity,
                    script_lock_height,

                    // Metadata signature components
                    sender_offset_public_key: blockchain_output
                        .sender_offset_public_key
                        .as_bytes()
                        .to_vec(),
                    // Note: LightweightSignature only has bytes field, so we use placeholders
                    // In a full implementation, these would be extracted from the signature structure
                    metadata_signature_ephemeral_commitment: vec![0u8; 32], // Placeholder
                    metadata_signature_ephemeral_pubkey: vec![0u8; 32],     // Placeholder
                    metadata_signature_u_a: if blockchain_output.metadata_signature.bytes.len()
                        >= 32
                    {
                        blockchain_output.metadata_signature.bytes[0..32].to_vec()
                    } else {
                        vec![0u8; 32]
                    },
                    metadata_signature_u_x: if blockchain_output.metadata_signature.bytes.len()
                        >= 64
                    {
                        blockchain_output.metadata_signature.bytes[32..64].to_vec()
                    } else {
                        vec![0u8; 32]
                    },
                    metadata_signature_u_y: vec![0u8; 32], // Placeholder

                    // Payment information
                    encrypted_data: blockchain_output.encrypted_data.as_bytes().to_vec(),
                    minimum_value_promise: blockchain_output.minimum_value_promise.as_u64(),

                    // Range proof
                    rangeproof: blockchain_output.proof.as_ref().map(|p| p.bytes.clone()),

                    // Status and spending tracking
                    status: if transaction.is_spent {
                        OutputStatus::Spent as u32
                    } else {
                        OutputStatus::Unspent as u32
                    },
                    mined_height: Some(transaction.block_height),
                    spent_in_tx_id: if transaction.is_spent {
                        // Calculate transaction ID from spent block and input index
                        transaction.spent_in_block.and_then(|spent_block| {
                            transaction.spent_in_input.map(|spent_input| {
                                generate_transaction_id(spent_block, spent_input)
                            })
                        })
                    } else {
                        None
                    },

                    // Timestamps (will be set by database)
                    created_at: None,
                    updated_at: None,
                };

                utxo_outputs.push(stored_output);
            }
        }
    }

    Ok(utxo_outputs)
}

/// Extract script input data and script lock height from script bytes
#[cfg(all(feature = "grpc", feature = "storage"))]
fn extract_script_data(script_bytes: &[u8]) -> LightweightWalletResult<(Vec<u8>, u64)> {
    // If script is empty, return empty data
    if script_bytes.is_empty() {
        return Ok((Vec::new(), 0));
    }

    let mut input_data = Vec::new();
    let mut script_lock_height = 0u64;
    let mut potential_heights = Vec::new();

    // Parse script bytecode to extract data
    // This is a simplified parser - in a full implementation, you'd use a proper script interpreter
    let mut i = 0;
    while i < script_bytes.len() {
        match script_bytes[i] {
            // OP_PUSHDATA opcodes (0x01-0x4b) - extract the data being pushed
            0x01..=0x4b => {
                let data_len = script_bytes[i] as usize;
                i += 1;
                if i + data_len <= script_bytes.len() {
                    let data = script_bytes[i..i + data_len].to_vec();
                    
                    // Check if this data might be input data (execution stack data)
                    // Input data is typically non-zero and has meaningful structure
                    if !data.iter().all(|&b| b == 0) && data.len() >= 1 {
                        // Prefer larger, more structured data as input data
                        if input_data.is_empty() || data.len() > input_data.len() {
                            input_data = data.clone();
                        }
                    }

                    // Check if this could be a height value (4 or 8 bytes)
                    if data.len() == 4 || data.len() == 8 {
                        let height = if data.len() == 4 {
                            u32::from_le_bytes(data.clone().try_into().unwrap_or([0; 4])) as u64
                        } else {
                            u64::from_le_bytes(data.clone().try_into().unwrap_or([0; 8]))
                        };
                        
                        // Store as potential height if it looks reasonable
                        if height > 0 && height < 10_000_000 && height > 100 {
                            potential_heights.push(height);
                        }
                    }
                    
                    i += data_len;
                } else {
                    break; // Malformed script
                }
            }
            
            // OP_PUSHDATA1 (0x4c) - next byte is data length
            0x4c => {
                if i + 1 < script_bytes.len() {
                    let data_len = script_bytes[i + 1] as usize;
                    i += 2;
                    if i + data_len <= script_bytes.len() {
                        let data = script_bytes[i..i + data_len].to_vec();
                        if !data.iter().all(|&b| b == 0) && data.len() >= 1 {
                            if input_data.is_empty() || data.len() > input_data.len() {
                                input_data = data.clone();
                            }
                        }

                        // Check for height values
                        if data.len() == 4 || data.len() == 8 {
                            let height = if data.len() == 4 {
                                u32::from_le_bytes(data.clone().try_into().unwrap_or([0; 4])) as u64
                            } else {
                                u64::from_le_bytes(data.clone().try_into().unwrap_or([0; 8]))
                            };
                            
                            if height > 0 && height < 10_000_000 && height > 100 {
                                potential_heights.push(height);
                            }
                        }

                        i += data_len;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            
            // OP_PUSHDATA2 (0x4d) - next 2 bytes are data length (little-endian)
            0x4d => {
                if i + 2 < script_bytes.len() {
                    let data_len = u16::from_le_bytes([script_bytes[i + 1], script_bytes[i + 2]]) as usize;
                    i += 3;
                    if i + data_len <= script_bytes.len() {
                        let data = script_bytes[i..i + data_len].to_vec();
                        if !data.iter().all(|&b| b == 0) && data.len() >= 1 && data.len() <= 256 {
                            if input_data.is_empty() || data.len() > input_data.len() {
                                input_data = data;
                            }
                        }
                        i += data_len;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            
            // OP_CHECKHEIGHTVERIFY or similar time-lock opcodes
            // In Tari, this might be represented differently, but we'll look for patterns
            0x65..=0x6a => {
                // Time-lock related opcodes - try to extract height from following bytes
                if i + 8 < script_bytes.len() {
                    // Try to read the next 8 bytes as a u64 height
                    let height_bytes = &script_bytes[i + 1..i + 9];
                    if let Ok(height_array) = height_bytes.try_into() {
                        let height = u64::from_le_bytes(height_array);
                        if height > 0 && height < 10_000_000 && height > 100 {
                            script_lock_height = height;
                        }
                    }
                }
                i += 1;
            }
            
            // OP_NOP and other common opcodes that might precede time locks
            0x61 => {
                // OP_NOP - check if followed by height data
                if i + 9 < script_bytes.len() {
                    let height_bytes = &script_bytes[i + 1..i + 9];
                    if let Ok(height_array) = height_bytes.try_into() {
                        let height = u64::from_le_bytes(height_array);
                        if height > 0 && height < 10_000_000 && height > 100 {
                            potential_heights.push(height);
                        }
                    }
                }
                i += 1;
            }
            
            // All other opcodes
            _ => {
                i += 1;
            }
        }
    }

    // If no explicit script lock height was found, use the best candidate from potential heights
    if script_lock_height == 0 && !potential_heights.is_empty() {
        // Sort potential heights and pick the most reasonable one
        potential_heights.sort();
        
        // Prefer heights that are in the typical blockchain range
        for &height in &potential_heights {
            if height > 1000 && height < 1_000_000 {
                script_lock_height = height;
                break;
            }
        }
        
        // If no reasonable height found, use the smallest positive one
        if script_lock_height == 0 {
            script_lock_height = potential_heights[0];
        }
    }

    // Additional heuristic: scan for 8-byte sequences that look like heights
    if script_lock_height == 0 && script_bytes.len() >= 8 {
        for chunk_start in 0..=(script_bytes.len() - 8) {
            if let Ok(height_bytes) = script_bytes[chunk_start..chunk_start + 8].try_into() {
                let potential_height = u64::from_le_bytes(height_bytes);
                // More restrictive check for reasonable block heights
                if potential_height > 1000 && potential_height < 1_000_000 {
                    script_lock_height = potential_height;
                    break;
                }
            }
        }
    }

    Ok((input_data, script_lock_height))
}

/// Generate a deterministic transaction ID from block height and input index
#[cfg(all(feature = "grpc", feature = "storage"))]
fn generate_transaction_id(block_height: u64, input_index: usize) -> u64 {
    // Create a deterministic transaction ID by combining block height and input index
    // This is a simplified approach - in a real implementation, you'd use the actual transaction hash
    // 
    // Format: [32-bit block_height][32-bit input_index]
    // This ensures unique IDs while being deterministic and easily debuggable
    
    // Use the block height as the upper 32 bits and input index as lower 32 bits
    let tx_id = ((block_height & 0xFFFFFFFF) << 32) | (input_index as u64 & 0xFFFFFFFF);
    
    // Ensure we don't return 0 (which is often treated as "no transaction")
    if tx_id == 0 {
        1
    } else {
        tx_id
    }
}

/// Validate that the extracted script data is reasonable
#[cfg(all(feature = "grpc", feature = "storage"))]
fn validate_script_data(input_data: &[u8], script_lock_height: u64) -> LightweightWalletResult<()> {
    // Validate input data
    if input_data.len() > 1024 {
        return Err(LightweightWalletError::ValidationError(
            ValidationError::ScriptValidationFailed(
                format!("Input data too large: {} bytes (max 1024)", input_data.len())
            )
        ));
    }

    // Validate script lock height
    if script_lock_height > 0 {
        // Should be a reasonable block height
        if script_lock_height > 100_000_000 {
            return Err(LightweightWalletError::ValidationError(
                ValidationError::ScriptValidationFailed(
                    format!("Script lock height too large: {}", script_lock_height)
                )
            ));
        }
    }

    Ok(())
}

/// Derive spending keys for a UTXO output using wallet entropy
/// For view-key mode (entropy all zeros), returns placeholder keys
#[cfg(all(feature = "grpc", feature = "storage"))]
fn derive_utxo_spending_keys(
    entropy: &[u8; 16],
    output_index: u64,
) -> LightweightWalletResult<(PrivateKey, PrivateKey)> {
    use lightweight_wallet_libs::errors::KeyManagementError;
    use lightweight_wallet_libs::key_management::key_derivation;

    // Check if we have real entropy or if this is view-key mode
    let has_real_entropy = entropy != &[0u8; 16];

    if has_real_entropy {
        // Derive real spending keys using wallet entropy
        let spending_key_raw = key_derivation::derive_private_key_from_entropy(
            entropy,
            "wallet_spending", // Branch for spending keys
            output_index,
        )?;

        let script_private_key_raw = key_derivation::derive_private_key_from_entropy(
            entropy,
            "script_keys", // Branch for script keys
            output_index,
        )?;

        // Convert to PrivateKey type
        let spending_key = PrivateKey::new(spending_key_raw.as_bytes().try_into().map_err(|_| {
            KeyManagementError::key_derivation_failed("Failed to convert spending key")
        })?);

        let script_private_key =
            PrivateKey::new(script_private_key_raw.as_bytes().try_into().map_err(|_| {
                KeyManagementError::key_derivation_failed("Failed to convert script private key")
            })?);

        Ok((spending_key, script_private_key))
    } else {
        // View-key mode: use placeholder keys (cannot spend, but can store UTXO structure)
        let placeholder_key_bytes = [0u8; 32];
        let spending_key = PrivateKey::new(placeholder_key_bytes);
        let script_private_key = PrivateKey::new(placeholder_key_bytes);
        
        Ok((spending_key, script_private_key))
    }
}

/// Compute output hash for UTXO identification
#[cfg(all(feature = "grpc", feature = "storage"))]
fn compute_output_hash(output: &LightweightTransactionOutput) -> LightweightWalletResult<Vec<u8>> {
    use blake2::{Blake2b, Digest};
    use digest::consts::U32;

    // Compute hash of output fields for identification
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(output.commitment.as_bytes());
    hasher.update(output.script.bytes.as_slice());
    hasher.update(output.sender_offset_public_key.as_bytes());
    hasher.update(&output.minimum_value_promise.as_u64().to_le_bytes());

    Ok(hasher.finalize().to_vec())
}

/// Core scanning logic - simplified and focused with batch processing
#[cfg(feature = "grpc")]
async fn scan_wallet_across_blocks_with_cancellation(
    scanner: &mut GrpcBlockchainScanner,
    scan_context: &ScanContext,
    config: &ScanConfig,
    storage_backend: &mut ScannerStorage,
    cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> LightweightWalletResult<ScanResult> {
    let has_specific_blocks = config.block_heights.is_some();

    // Handle resume functionality for database storage
    let (from_block, to_block) = if config.resume {
        #[cfg(feature = "storage")]
        if let Some(wallet_id) = storage_backend.wallet_id {
            // Check if user explicitly provided --from-block (takes precedence over database resume)
            if let Some(explicit_from_block) = config.explicit_from_block {
                if !config.quiet {
                    println!(
                        "📄 Using explicit --from-block {} (overriding database resume)",
                        format_number(explicit_from_block)
                    );
                }
                (explicit_from_block, config.to_block)
            } else {
                // Get the wallet to check its resume block
                if let Some(wallet_birthday) = storage_backend.get_wallet_birthday().await? {
                    if !config.quiet {
                        if let Some(last_scanned) = storage_backend.wallet_id {
                            println!(
                                "📄 Resuming wallet '{}' from block {} (last scanned: {})",
                                "wallet",
                                format_number(wallet_birthday),
                                format_number(last_scanned)
                            );
                        } else {
                            println!(
                                "📄 Starting wallet '{}' from birthday block {}",
                                "wallet",
                                format_number(wallet_birthday)
                            );
                        }
                    }
                    (wallet_birthday, config.to_block)
                } else {
                    if !config.quiet {
                        println!("📄 Wallet not found, starting from configuration");
                    }
                    (config.from_block, config.to_block)
                }
            }
        } else {
            if !config.quiet {
                if storage_backend.is_memory_only {
                    println!("⚠️  Resume option requires database storage, ignoring");
                } else {
                    println!("⚠️  Resume requires a selected wallet");
                }
            }
            (config.from_block, config.to_block)
        }

        #[cfg(not(feature = "storage"))]
        {
            if !config.quiet {
                println!("⚠️  Resume option requires storage feature, ignoring");
            }
            (config.from_block, config.to_block)
        }
    } else {
        (config.from_block, config.to_block)
    };

    let block_heights = config
        .block_heights
        .clone()
        .unwrap_or_else(|| (from_block..=to_block).collect());

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
                "Scanning",
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
                        println!(
                            "\n⏱️  GRPC batch fetch: {:.3}s for {} blocks",
                            grpc_duration.as_secs_f64(),
                            format_number(batch_heights.len())
                        );
                    }
                }
                blocks
            }
            Err(e) => {
                let grpc_duration = grpc_start_time.elapsed();
                if config.enable_profiling {
                    profile_data.add_grpc_time(grpc_duration);
                }
                println!(
                    "\n❌ Error scanning batch starting at block {}: {}",
                    batch_heights[0], e
                );
                println!("   Batch heights: {:?}", batch_heights);
                println!("   Error details: {:?}", e);
                println!(
                    "   GRPC call took: {:.3}s before failing",
                    grpc_duration.as_secs_f64()
                );

                let remaining_blocks = &block_heights[batch_start_index..];
                if handle_scan_error(
                    batch_heights[0],
                    remaining_blocks,
                    has_specific_blocks,
                    config.to_block,
                ) {
                    // Check for cancellation before continuing
                    if *cancel_rx.borrow() {
                        profile_data.total_scan_time = scan_start_time.elapsed();
                        return Ok(ScanResult::Interrupted(wallet_state, profile_data));
                    }
                    continue; // Continue to next batch
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
                        println!(
                            "\n⚠️  Block {} not found in batch, skipping...",
                            block_height
                        );
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
            let found_outputs = block.process_outputs(
                &scan_context.view_key,
                &scan_context.entropy,
                &mut wallet_state,
            );
            let output_duration = output_start_time.elapsed();

            // Time input processing separately
            let input_start_time = Instant::now();
            let spent_outputs = block.process_inputs(&mut wallet_state);
            let input_duration = input_start_time.elapsed();

            let scan_result = match (found_outputs, spent_outputs) {
                (Ok(found), Ok(spent)) => Ok((found, spent)),
                (Err(e), _) | (_, Err(e)) => Err(e),
            };

            let (_found_outputs, spent_outputs_count) = match scan_result {
                Ok(result) => {
                    let block_duration = block_start_time.elapsed();
                    if config.enable_profiling {
                        profile_data.add_block_processing_time(*block_height, block_duration);
                    }

                    // Note: Spent output tracking is handled automatically by wallet_state.mark_output_spent()
                    // called from block.process_inputs() - and we also update the database below

                    // Save transactions to storage backend if using database
                    #[cfg(feature = "storage")]
                    if storage_backend.wallet_id.is_some() {
                        // Mark any transactions as spent in the database that were marked as spent in this block
                        for (input_index, input) in block.inputs.iter().enumerate() {
                            let input_commitment = CompressedCommitment::new(input.commitment);
                            if let Some(storage) = &storage_backend.database {
                                if let Err(e) = storage.mark_transaction_spent(
                                    &input_commitment,
                                    *block_height,
                                    input_index,
                                ).await {
                                    if !config.quiet {
                                        println!("\n⚠️  Warning: Failed to mark transaction as spent in database for commitment {}: {}", 
                                            hex::encode(&input_commitment.as_bytes()[..8]), e);
                                    }
                                }
                            }
                        }

                        // Save ALL accumulated transactions frequently (using INSERT OR REPLACE to handle duplicates)
                        // This ensures no transactions are lost if individual block saves fail
                        // Save every block to ensure data integrity (INSERT OR REPLACE handles duplicates efficiently)
                        let should_save_transactions = true;

                        if should_save_transactions {
                            let all_transactions: Vec<_> = wallet_state
                                .transactions
                                .iter()
                                .cloned()
                                .collect();

                        if !all_transactions.is_empty() {
                            // Save transaction data (includes both inbound and outbound transactions)
                            if let Err(e) = storage_backend
                                .save_transactions(&all_transactions)
                                .await
                            {
                                if !config.quiet {
                                    println!("\n⚠️  Warning: Failed to save {} accumulated transactions to database: {}", 
                                        format_number(all_transactions.len()), e);
                                }
                            } else {
                                // Validate that we're saving both inbound and outbound transactions correctly
                                let inbound_count = all_transactions.iter().filter(|tx| tx.transaction_direction == TransactionDirection::Inbound).count();
                                let outbound_count = all_transactions.iter().filter(|tx| tx.transaction_direction == TransactionDirection::Outbound).count();
                                
                                if !config.quiet && config.enable_profiling {
                                    println!("\n💾 Saved {} total transactions to database ({} inbound, {} outbound)", 
                                        format_number(all_transactions.len()), 
                                        format_number(inbound_count), format_number(outbound_count));
                                }
                                
                                // Verify that outbound transactions have proper spending details
                                for tx in &all_transactions {
                                    if tx.transaction_direction == TransactionDirection::Outbound {
                                        if tx.input_index.is_none() {
                                            if !config.quiet {
                                                println!("\n⚠️  Warning: Outbound transaction missing input_index");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        } // Close the should_save_transactions if block

                        // Extract and save UTXO data for wallet outputs (works for both seed phrase and view-key modes)
                        match extract_utxo_outputs_from_wallet_state(
                            &wallet_state,
                            scan_context,
                            storage_backend.wallet_id.unwrap(),
                            &block.outputs,
                            *block_height,
                        ) {
                            Ok(utxo_outputs) => {
                                if !utxo_outputs.is_empty() {
                                    if let Err(e) = storage_backend.save_outputs(&utxo_outputs).await {
                                        if !config.quiet {
                                            println!("\n⚠️  Warning: Failed to save {} UTXO outputs from block {} to database: {}", 
                                                format_number(utxo_outputs.len()), format_number(*block_height), e);
                                        }
                                    } else if !config.quiet && config.enable_profiling {
                                        let unspent_utxos = utxo_outputs.iter().filter(|o| o.status == (OutputStatus::Unspent as u32)).count();
                                        let spent_utxos = utxo_outputs.iter().filter(|o| o.status == (OutputStatus::Spent as u32)).count();
                                        println!("\n🔗 Saved {} UTXO outputs for block {} ({} unspent, {} spent)", 
                                            format_number(utxo_outputs.len()), format_number(*block_height),
                                            format_number(unspent_utxos), format_number(spent_utxos));
                                            
                                        // Verify that all UTXOs have proper spending keys (or placeholders for view-key mode)
                                        for utxo in &utxo_outputs {
                                            if utxo.spending_key.is_empty() {
                                                println!("⚠️  Warning: UTXO missing spending key for commitment: {}", hex::encode(&utxo.commitment[..8]));
                                            }
                                        }
                                    }
                                }
                            },
                            Err(e) => {
                                if !config.quiet {
                                    println!(
                                        "\n⚠️  Warning: Failed to extract UTXO data from block {}: {}",
                                        format_number(*block_height), e
                                    );
                                }
                            }
                        }
                    }

                    result
                }
                Err(e) => {
                    let block_duration = block_start_time.elapsed();
                    if config.enable_profiling {
                        profile_data.add_block_processing_time(*block_height, block_duration);
                    }
                    println!("\n❌ Error processing block {}: {}", block_height, e);
                    println!("   Block height: {}", block_height);
                    println!("   Error details: {:?}", e);
                    println!(
                        "   Block processing took: {:.3}s before failing",
                        block_duration.as_secs_f64()
                    );

                    let remaining_blocks = &block_heights[global_block_index..];
                    if handle_scan_error(
                        *block_height,
                        remaining_blocks,
                        has_specific_blocks,
                        config.to_block,
                    ) {
                        // Check for cancellation before continuing
                        if *cancel_rx.borrow() {
                            profile_data.total_scan_time = scan_start_time.elapsed();
                            return Ok(ScanResult::Interrupted(wallet_state, profile_data));
                        }
                        continue; // Continue to next block
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
                println!(
                    "\n⏱️  Batch {}: {:.3}s total ({} blocks, avg: {:.3}s per block)",
                    format_number(batch_index + 1),
                    batch_duration.as_secs_f64(),
                    format_number(batch_heights.len()),
                    batch_duration.as_secs_f64() / batch_heights.len() as f64
                );
            }
        }

        // Update wallet scanned block at the end of each batch (for progress tracking)
        #[cfg(feature = "storage")]
        if storage_backend.wallet_id.is_some() {
            if let Some(last_block_height) = batch_heights.last() {
                if let Err(e) = storage_backend.update_wallet_scanned_block(*last_block_height).await {
                    if !config.quiet {
                        println!("\n⚠️  Warning: Failed to update wallet scanned block to {}: {}", format_number(*last_block_height), e);
                    }
                }
            }
        }
        // Update progress display after processing each batch
        if !config.quiet {
            let processed_blocks =
                std::cmp::min(batch_start_index + batch_size, block_heights.len());
            let progress_bar = wallet_state.format_progress_bar(
                processed_blocks as u64,
                block_heights.len() as u64,
                batch_heights.last().cloned().unwrap_or(0),
                if processed_blocks == block_heights.len() {
                    "Complete"
                } else {
                    "Scanning"
                },
            );
            print!("\r{}", progress_bar);
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
        }
    }

    // Record total scan time
    profile_data.total_scan_time = scan_start_time.elapsed();

    // Final wallet scanned block update (ensure highest processed block is recorded)
    #[cfg(feature = "storage")]
    if storage_backend.wallet_id.is_some() {
        if let Some(highest_block) = block_heights.last() {
            if let Err(e) = storage_backend.update_wallet_scanned_block(*highest_block).await {
                if !config.quiet {
                    println!("\n⚠️  Warning: Failed to final update wallet scanned block to {}: {}", format_number(*highest_block), e);
                }
            } else if !config.quiet && config.enable_profiling {
                println!("\n💾 Final wallet scanned block updated to: {}", format_number(*highest_block));
            }
        }
    }

    if !config.quiet {
        // Ensure final progress bar shows 100%
        let final_progress_bar = wallet_state.format_progress_bar(
            block_heights.len() as u64,
            block_heights.len() as u64,
            block_heights.last().cloned().unwrap_or(0),
            "Complete",
        );
        println!("\r{}", final_progress_bar);

        let scan_elapsed = profile_data.total_scan_time;
        let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();
        println!("\n✅ Scan complete in {:.2}s!", scan_elapsed.as_secs_f64());
        println!(
            "📊 Total: {} outputs found, {} outputs spent",
            format_number(inbound_count),
            format_number(outbound_count)
        );
    }

    Ok(ScanResult::Completed(wallet_state, profile_data))
}

/// Display scan configuration information
#[cfg(feature = "grpc")]
fn display_scan_info(config: &ScanConfig, block_heights: &[u64], has_specific_blocks: bool) {
    if has_specific_blocks {
        println!(
            "🔍 Scanning {} specific blocks: {:?}",
            format_number(block_heights.len()),
            if block_heights.len() <= 10 {
                block_heights
                    .iter()
                    .map(|h| format_number(*h))
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                format!(
                    "{}..{} and {} others",
                    format_number(block_heights[0]),
                    format_number(*block_heights.last().unwrap()),
                    format_number(block_heights.len() - 2)
                )
            }
        );
    } else {
        let block_range = config.to_block - config.from_block + 1;
        println!(
            "🔍 Scanning blocks {} to {} ({} blocks total)...",
            format_number(config.from_block),
            format_number(config.to_block),
            format_number(block_range)
        );
    }

    // Warning about scanning limitations
    if config.from_block > 1 && !has_specific_blocks {
        println!(
            "⚠️  WARNING: Starting scan from block {} (not genesis)",
            format_number(config.from_block)
        );
        println!(
            "   📍 This will MISS any wallet outputs received before block {}",
            format_number(config.from_block)
        );
        println!("   💡 For complete transaction history, consider scanning from genesis (--from-block 1)");
    }
    println!();
}

#[cfg(feature = "grpc")]
fn display_wallet_activity(wallet_state: &WalletState, from_block: u64, to_block: u64) {
    let (total_received, total_spent, balance, unspent_count, spent_count) =
        wallet_state.get_summary();
    let total_count = wallet_state.transactions.len();

    if total_count == 0 {
        println!(
            "💡 No wallet activity found in blocks {} to {}",
            format_number(from_block),
            format_number(to_block)
        );
        if from_block > 1 {
            println!("   ⚠️  Note: Scanning from block {} - wallet history before this block was not checked", format_number(from_block));
            println!("   💡 For complete history, try: cargo run --example scanner --features grpc -- --seed-phrase \"your seed phrase\" --from-block 1");
        }
        return;
    }

    println!("🏦 WALLET ACTIVITY SUMMARY");
    println!("========================");
    println!(
        "Scan range: Block {} to {} ({} blocks)",
        format_number(from_block),
        format_number(to_block),
        format_number(to_block - from_block + 1)
    );

    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();
    println!(
        "📥 Inbound:  {} transactions, {} μT ({:.6} T)",
        format_number(inbound_count),
        format_number(total_received),
        total_received as f64 / 1_000_000.0
    );
    println!(
        "📤 Outbound: {} transactions, {} μT ({:.6} T)",
        format_number(outbound_count),
        format_number(total_spent),
        total_spent as f64 / 1_000_000.0
    );
    println!(
        "💰 Current balance: {} μT ({:.6} T)",
        format_number(balance),
        balance as f64 / 1_000_000.0
    );
    println!(
        "📊 Total activity: {} transactions",
        format_number(total_count)
    );
    println!();

    if !wallet_state.transactions.is_empty() {
        println!("📋 DETAILED TRANSACTION HISTORY");
        println!("===============================");

        // Sort transactions by block height for chronological order
        let mut sorted_transactions: Vec<_> =
            wallet_state.transactions.iter().enumerate().collect();
        sorted_transactions.sort_by_key(|(_, tx)| tx.block_height);

        // Create a mapping from commitments to transactions for spent tracking
        let mut commitment_to_inbound: std::collections::HashMap<Vec<u8>, &lightweight_wallet_libs::data_structures::wallet_transaction::WalletTransaction> = std::collections::HashMap::new();
        for tx in &wallet_state.transactions {
            if tx.transaction_direction == TransactionDirection::Inbound {
                commitment_to_inbound.insert(tx.commitment.as_bytes().to_vec(), tx);
            }
        }

        for (original_index, tx) in sorted_transactions {
            let direction_symbol = match tx.transaction_direction {
                TransactionDirection::Inbound => "📥",
                TransactionDirection::Outbound => "📤",
                TransactionDirection::Unknown => "❓",
            };

            let amount_display = match tx.transaction_direction {
                TransactionDirection::Inbound => format!("+{} μT", format_number(tx.value)),
                TransactionDirection::Outbound => format!("-{} μT", format_number(tx.value)),
                TransactionDirection::Unknown => format!("±{} μT", format_number(tx.value)),
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
                        format!("SPENT in block {}", format_number(tx.spent_in_block.unwrap_or(0)))
                    } else {
                        "UNSPENT".to_string()
                    };

                    println!(
                        "{}. {} Block {}, Output #{}: {} ({:.6} T) - {} [{}{}]",
                        format_number(original_index + 1),
                        direction_symbol,
                        format_number(tx.block_height),
                        format_number(tx.output_index.unwrap_or(0)),
                        amount_display,
                        tx.value as f64 / 1_000_000.0,
                        status,
                        tx.transaction_status,
                        maturity_indicator
                    );

                    // Show spending details if this output was spent
                    if tx.is_spent {
                        if let Some(spent_block) = tx.spent_in_block {
                            if let Some(spent_input) = tx.spent_in_input {
                                println!("   └─ Spent as input #{} in block {}", 
                                    format_number(spent_input), 
                                    format_number(spent_block));
                            }
                        }
                    }
                }
                TransactionDirection::Outbound => {
                    println!(
                        "{}. {} Block {}, Input #{}: {} ({:.6} T) - SPENDING [{}]",
                        format_number(original_index + 1),
                        direction_symbol,
                        format_number(tx.block_height),
                        format_number(tx.input_index.unwrap_or(0)),
                        amount_display,
                        tx.value as f64 / 1_000_000.0,
                        tx.transaction_status
                    );

                    // Try to find which output this is spending
                    let commitment_bytes = tx.commitment.as_bytes().to_vec();
                    if let Some(original_tx) = commitment_to_inbound.get(&commitment_bytes) {
                        println!("   └─ Spending output from block {} (output #{})", 
                            format_number(original_tx.block_height),
                            format_number(original_tx.output_index.unwrap_or(0)));
                    }
                }
                TransactionDirection::Unknown => {
                    println!(
                        "{}. {} Block {}: {} ({:.6} T) - UNKNOWN [{}]",
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
                PaymentId::Empty => {}
                PaymentId::Open { user_data, .. } if !user_data.is_empty() => {
                    // Try to decode as UTF-8 string
                    if let Ok(text) = std::str::from_utf8(user_data) {
                        if text
                            .chars()
                            .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                        {
                            println!("   💬 Payment ID: \"{}\"", text);
                        } else {
                            println!("   💬 Payment ID (hex): {}", hex::encode(user_data));
                        }
                    } else {
                        println!("   💬 Payment ID (hex): {}", hex::encode(user_data));
                    }
                }
                PaymentId::TransactionInfo { user_data, .. } if !user_data.is_empty() => {
                    // Convert the binary data to utf8 string if possible otherwise print as hex
                    if let Ok(text) = std::str::from_utf8(user_data) {
                        println!("   💬 Payment ID: \"{}\"", text);
                    } else {
                        println!("   💬 Payment ID (hex): {}", hex::encode(user_data));
                    }
                }
                _ => {
                    let user_data_str = tx.payment_id.user_data_as_string();
                    if !user_data_str.is_empty() {
                        println!("   💬 Payment ID: \"{}\"", user_data_str);
                    }
                }
            }
        }
        println!();
    }

    // Show balance breakdown
    let unspent_value = wallet_state.get_unspent_value();

    println!("💰 BALANCE BREAKDOWN");
    println!("===================");
    println!(
        "Unspent outputs: {} ({:.6} T)",
        format_number(unspent_count),
        unspent_value as f64 / 1_000_000.0
    );
    println!(
        "Spent outputs: {} ({:.6} T)",
        format_number(spent_count),
        total_spent as f64 / 1_000_000.0
    );
    println!(
        "Total wallet activity: {} transactions",
        format_number(total_count)
    );

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
        println!(
            "📥 Inbound:  {} transactions, {:.6} T total",
            format_number(inbound_count),
            total_inbound_value as f64 / 1_000_000.0
        );
        println!(
            "📤 Outbound: {} transactions, {:.6} T total",
            format_number(outbound_count),
            total_outbound_value as f64 / 1_000_000.0
        );
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
                println!(
                    "{}: {} ({} immature)",
                    status,
                    format_number(count),
                    format_number(coinbase_immature)
                );
            } else {
                println!("{}: {}", status, format_number(count));
            }
        }

        // Show net flow
        let net_flow = total_inbound_value as i64 - total_outbound_value as i64;
        println!();
        println!("📊 NET FLOW SUMMARY");
        println!("==================");
        println!(
            "Net flow: {:.6} T ({})",
            net_flow as f64 / 1_000_000.0,
            if net_flow > 0 {
                "📈 Positive"
            } else if net_flow < 0 {
                "📉 Negative"
            } else {
                "⚖️  Neutral"
            }
        );
        println!(
            "Current balance: {:.6} T",
            wallet_state.get_balance() as f64 / 1_000_000.0
        );
    }
}

#[cfg(feature = "grpc")]
#[tokio::main]
async fn main() -> LightweightWalletResult<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = CliArgs::parse();

    // Handle wallet listing without requiring keys
    if args.list_wallets {
        #[cfg(feature = "storage")]
        {
            // Create configuration and storage for wallet listing
            let block_height_range = BlockHeightRange::new(0, 0, None); // Dummy range for wallet listing
            let config = block_height_range.into_scan_config(&args)?;
            
            let storage_backend = if let Some(db_path) = &config.database_path {
                ScannerStorage::new_with_database(db_path, config.clear_database).await?
            } else {
                ScannerStorage::new_memory()
            };

            let wallets = storage_backend.list_wallets().await?;
            if wallets.is_empty() {
                println!("📂 No wallets found in database");
            } else {
                println!("📂 Available wallets:");
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
        }
        #[cfg(not(feature = "storage"))]
        {
            println!("❌ Error: Wallet listing requires the 'storage' feature to be enabled.");
            println!("💡 Run with: cargo run --example scanner --features grpc-storage -- --list-wallets");
        }
        return Ok(());
    }

    // Validate input arguments (required for scanning operations, unless resuming from database)
    let keys_provided = args.seed_phrase.is_some() || args.view_key.is_some();
    let can_resume_from_db = args.resume && args.database.is_some();

    match (&args.seed_phrase, &args.view_key) {
        (Some(_), Some(_)) => {
            eprintln!("❌ Error: Cannot specify both --seed-phrase and --view-key. Choose one.");
            std::process::exit(1);
        }
        (None, None) => {
            if !can_resume_from_db {
                eprintln!("❌ Error: Must specify either --seed-phrase or --view-key.");
                eprintln!("💡 Use --help for usage information.");
                eprintln!(
                    "💡 Or use --resume --database <path> to resume from stored wallet keys."
                );
                std::process::exit(1);
            }
            // Allow no keys when resuming from database
        }
        _ => {} // Valid: exactly one is provided
    }

    if !args.quiet {
        println!("🚀 Enhanced Tari Wallet Scanner");
        println!("===============================");
    }

    // Create scan context based on input method (or defer if resuming from database)
    let (scan_context, default_from_block) = if keys_provided {
        if let Some(seed_phrase) = &args.seed_phrase {
            if !args.quiet {
                println!("🔨 Creating wallet from seed phrase...");
            }
            let wallet = Wallet::new_from_seed_phrase(seed_phrase, None)?;
            let scan_context = ScanContext::from_wallet(&wallet)?;
            let default_from_block = wallet.birthday();
            (Some(scan_context), default_from_block)
        } else if let Some(view_key_hex) = &args.view_key {
            if !args.quiet {
                println!("🔑 Creating scan context from view key...");
            }
            let scan_context = ScanContext::from_view_key(view_key_hex)?;
            let default_from_block = 0; // Start from genesis when using view key only
            (Some(scan_context), default_from_block)
        } else {
            unreachable!("Keys provided but neither seed phrase nor view key found");
        }
    } else {
        // Keys will be loaded from database wallet
        if !args.quiet {
            println!("🔑 Will load wallet keys from database...");
        }
        (None, args.from_block.unwrap_or(0)) // Default from block will be set from wallet birthday
    };

    // Connect to base node
    if !args.quiet {
        println!("🌐 Connecting to Tari base node...");
    }
    let mut scanner = GrpcScannerBuilder::new()
        .with_base_url(args.base_url.clone())
        .with_timeout(std::time::Duration::from_secs(30))
        .build()
        .await
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
        println!(
            "📊 Current blockchain tip: block {}",
            format_number(tip_info.best_block_height)
        );
    }

    let to_block = args.to_block.unwrap_or(tip_info.best_block_height);

    // Create temporary config for storage operations (will be recreated with correct from_block later)
    let temp_block_height_range = BlockHeightRange::new(0, to_block, args.blocks.clone());
    let temp_config = temp_block_height_range.into_scan_config(&args)?;

    // Create storage backend
    let mut storage_backend = if let Some(db_path) = &temp_config.database_path {
        #[cfg(feature = "storage")]
        {
            ScannerStorage::new_with_database(db_path, temp_config.clear_database).await?
        }
        #[cfg(not(feature = "storage"))]
        {
            ScannerStorage::new_memory()
        }
    } else {
        ScannerStorage::new_memory()
    };

    // Handle wallet operations for database storage
    #[cfg(feature = "storage")]
    let (loaded_scan_context, wallet_birthday) = {
        let loaded_context = storage_backend.handle_wallet_operations(
            &temp_config,
            scan_context.as_ref(),
            args.seed_phrase.as_deref(),
        ).await?;

        // If listing wallets or creating wallet without scanning, exit here
        if temp_config.list_wallets
            || (temp_config.create_wallet
                && !temp_config.resume
                && temp_config.block_heights.is_none()
                && temp_config.from_block == 0)
        {
            return Ok(());
        }

        // Get wallet birthday if we have a wallet
        let wallet_birthday = if args.from_block.is_none() {
            storage_backend.get_wallet_birthday().await?
        } else {
            None
        };

        (loaded_context, wallet_birthday)
    };

    #[cfg(not(feature = "storage"))]
    let (loaded_scan_context, wallet_birthday): (
        Option<ScanContext>,
        Option<u64>,
    ) = (None, None);

    // Use loaded scan context if we didn't have one initially, or fall back to provided scan context
    let final_scan_context = if let Some(loaded_context) = loaded_scan_context {
        loaded_context
    } else if let Some(context) = scan_context {
        context
    } else {
        return Err(LightweightWalletError::InvalidArgument {
            argument: "scan_context".to_string(),
            value: "None".to_string(),
            message: "No scan context available - provide keys or use existing wallet".to_string(),
        });
    };

    // Storage backend already has wallet_id set from wallet operations

    // Calculate final default from block (outside conditional compilation)
    let final_default_from_block = wallet_birthday.unwrap_or(default_from_block);

    // Now calculate the from_block using the final_default_from_block
    let from_block = args.from_block.unwrap_or(final_default_from_block);

    // Update the config with the correct from_block
    let block_height_range = BlockHeightRange::new(from_block, to_block, args.blocks.clone());
    let config = block_height_range.into_scan_config(&args)?;

    // Display storage info and existing data
    if !args.quiet {
        storage_backend.display_storage_info(&config).await?;
    }

    // Setup cancellation mechanism
    let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);

    // Setup ctrl-c handling
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
        let _ = cancel_tx.send(true);
    };

    // Perform the scan with cancellation support
    let scan_result = tokio::select! {
        result = scan_wallet_across_blocks_with_cancellation(&mut scanner, &final_scan_context, &config, &mut storage_backend, &mut cancel_rx) => {
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
                OutputFormat::Detailed => {
                    display_wallet_activity(&wallet_state, config.from_block, config.to_block)
                }
            }

            // Display profiling information if enabled
            if config.enable_profiling {
                profile_data.display_profile(config.quiet);
                profile_data.display_recommendations(config.quiet);
            }

                // Display storage completion info and verify data integrity
    if !args.quiet {
        storage_backend.display_completion_info(&config).await?;
        
        // Verify that transaction flow data was persisted correctly
        #[cfg(feature = "storage")]
        if storage_backend.wallet_id.is_some() {
            let stats = storage_backend.get_statistics().await?;
            let (in_memory_received, in_memory_spent, in_memory_balance, _, _) = wallet_state.get_summary();
            
            // Compare in-memory wallet state with database statistics
            if stats.total_received != in_memory_received {
                println!("⚠️  Warning: Database total received ({}) doesn't match in-memory state ({})", 
                    format_number(stats.total_received), format_number(in_memory_received));
            }
            if stats.total_spent != in_memory_spent {
                println!("⚠️  Warning: Database total spent ({}) doesn't match in-memory state ({})", 
                    format_number(stats.total_spent), format_number(in_memory_spent));
            }
            // Compare balances (handling signed vs unsigned)
            let db_balance_signed = stats.current_balance as i64;
            if db_balance_signed != in_memory_balance {
                println!("⚠️  Warning: Database balance ({}) doesn't match in-memory state ({})", 
                    format_number(db_balance_signed), format_number(in_memory_balance));
            }
            
            // Verify transaction counts
            let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();
            if stats.inbound_count != inbound_count {
                println!("⚠️  Warning: Database inbound count ({}) doesn't match in-memory state ({})", 
                    format_number(stats.inbound_count), format_number(inbound_count));
            }
            if stats.outbound_count != outbound_count {
                println!("⚠️  Warning: Database outbound count ({}) doesn't match in-memory state ({})", 
                    format_number(stats.outbound_count), format_number(outbound_count));
            }
            
            // If all checks pass, confirm data integrity
            let db_balance_signed = stats.current_balance as i64;
            if stats.total_received == in_memory_received && 
               stats.total_spent == in_memory_spent && 
               db_balance_signed == in_memory_balance &&
               stats.inbound_count == inbound_count && 
               stats.outbound_count == outbound_count {
                println!("✅ Transaction flow data integrity verified - all data persisted correctly");
            }
        }
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
                OutputFormat::Detailed => {
                    display_wallet_activity(&wallet_state, config.from_block, config.to_block)
                }
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
                println!(
                    "⚡ To resume, use the same command with appropriate --from-block parameter."
                );
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
    let (total_received, total_spent, balance, unspent_count, spent_count) =
        wallet_state.get_summary();
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();

    println!("{{");
    println!("  \"summary\": {{");
    println!(
        "    \"total_transactions\": {},",
        format_number(wallet_state.transactions.len())
    );
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
    let (total_received, total_spent, balance, unspent_count, spent_count) =
        wallet_state.get_summary();
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();

    println!("📊 WALLET SCAN SUMMARY");
    println!("=====================");
    println!(
        "Scan range: Block {} to {}",
        format_number(config.from_block),
        format_number(config.to_block)
    );
    println!(
        "Total transactions: {}",
        format_number(wallet_state.transactions.len())
    );
    println!(
        "Inbound: {} transactions ({:.6} T)",
        format_number(inbound_count),
        total_received as f64 / 1_000_000.0
    );
    println!(
        "Outbound: {} transactions ({:.6} T)",
        format_number(outbound_count),
        total_spent as f64 / 1_000_000.0
    );
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
            self.memory_usage.push(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as usize,
            );
        }
    }

    pub fn display_profile(&self, quiet: bool) {
        if quiet {
            return;
        }

        println!("\n📊 PERFORMANCE PROFILE");
        println!("======================");
        println!(
            "Total scan time: {:.3}s",
            self.total_scan_time.as_secs_f64()
        );
        println!(
            "Total GRPC time: {:.3}s ({:.1}%)",
            self.total_grpc_time.as_secs_f64(),
            (self.total_grpc_time.as_secs_f64() / self.total_scan_time.as_secs_f64()) * 100.0
        );
        println!(
            "Total processing time: {:.3}s ({:.1}%)",
            self.total_processing_time.as_secs_f64(),
            (self.total_processing_time.as_secs_f64() / self.total_scan_time.as_secs_f64()) * 100.0
        );

        if !self.grpc_call_times.is_empty() {
            let avg_grpc = self.total_grpc_time.as_secs_f64() / self.grpc_call_times.len() as f64;
            let max_grpc = self.grpc_call_times.iter().max().unwrap().as_secs_f64();
            let min_grpc = self.grpc_call_times.iter().min().unwrap().as_secs_f64();
            println!(
                "GRPC calls: {} total, avg: {:.3}s, min: {:.3}s, max: {:.3}s",
                format_number(self.grpc_call_times.len()),
                avg_grpc,
                min_grpc,
                max_grpc
            );
        }

        if !self.block_processing_times.is_empty() {
            let avg_processing =
                self.total_processing_time.as_secs_f64() / self.block_processing_times.len() as f64;
            let max_processing = self
                .block_processing_times
                .iter()
                .map(|(_, d)| d)
                .max()
                .unwrap()
                .as_secs_f64();
            let min_processing = self
                .block_processing_times
                .iter()
                .map(|(_, d)| d)
                .min()
                .unwrap()
                .as_secs_f64();
            println!(
                "Block processing: {} blocks, avg: {:.3}s, min: {:.3}s, max: {:.3}s",
                format_number(self.block_processing_times.len()),
                avg_processing,
                min_processing,
                max_processing
            );

            // Show slowest blocks
            let mut sorted_blocks = self.block_processing_times.clone();
            sorted_blocks.sort_by(|a, b| b.1.cmp(&a.1));
            if sorted_blocks.len() > 5 {
                println!("Slowest blocks:");
                for (block_height, duration) in sorted_blocks.iter().take(5) {
                    println!(
                        "  Block {}: {:.3}s",
                        format_number(*block_height),
                        duration.as_secs_f64()
                    );
                }
            }
        }

        if !self.batch_processing_times.is_empty() {
            let avg_batch = self
                .batch_processing_times
                .iter()
                .sum::<std::time::Duration>()
                .as_secs_f64()
                / self.batch_processing_times.len() as f64;
            let max_batch = self
                .batch_processing_times
                .iter()
                .max()
                .unwrap()
                .as_secs_f64();
            let min_batch = self
                .batch_processing_times
                .iter()
                .min()
                .unwrap()
                .as_secs_f64();
            println!(
                "Batch processing: {} batches, avg: {:.3}s, min: {:.3}s, max: {:.3}s",
                format_number(self.batch_processing_times.len()),
                avg_batch,
                min_batch,
                max_batch
            );
        }

        // Calculate overhead (time not accounted for by GRPC or processing)
        let accounted_time = self.total_grpc_time + self.total_processing_time;
        let overhead = self.total_scan_time.saturating_sub(accounted_time);
        if overhead.as_secs_f64() > 0.1 {
            println!(
                "Overhead/Other: {:.3}s ({:.1}%)",
                overhead.as_secs_f64(),
                (overhead.as_secs_f64() / self.total_scan_time.as_secs_f64()) * 100.0
            );
        }

        if !self.memory_usage.is_empty() && cfg!(target_os = "linux") {
            let max_mem = self.memory_usage.iter().max().unwrap_or(&0);
            let min_mem = self.memory_usage.iter().min().unwrap_or(&0);
            println!(
                "Memory usage: min: {:.1} MB, max: {:.1} MB",
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

        let grpc_percentage =
            (self.total_grpc_time.as_secs_f64() / self.total_scan_time.as_secs_f64()) * 100.0;
        let processing_percentage =
            (self.total_processing_time.as_secs_f64() / self.total_scan_time.as_secs_f64()) * 100.0;

        if grpc_percentage > 60.0 {
            println!(
                "🌐 GRPC calls are the main bottleneck ({:.1}% of time)",
                grpc_percentage
            );
            println!("   → Consider increasing --batch-size to reduce number of GRPC calls");
            println!(
                "   → Made {} GRPC calls total",
                format_number(self.grpc_call_times.len())
            );
            println!("   → Check network latency to the base node");
            println!("   → Consider using a local base node for faster access");
        } else if processing_percentage > 60.0 {
            println!(
                "⚙️  Block processing is the main bottleneck ({:.1}% of time)",
                processing_percentage
            );
            println!("   → Check if running on a fast CPU with good single-thread performance");
        } else {
            println!("⚖️  Balanced performance - no major bottlenecks detected");
            println!(
                "   → GRPC: {:.1}%, Processing: {:.1}%",
                grpc_percentage, processing_percentage
            );
        }

        if !self.block_processing_times.is_empty() {
            let avg_processing =
                self.total_processing_time.as_secs_f64() / self.block_processing_times.len() as f64;
            if avg_processing > 0.1 {
                println!(
                    "🐌 Block processing is slow (avg: {:.3}s per block)",
                    avg_processing
                );
                println!("   → Large blocks with many transactions take longer to process");
                println!("   → Consider scanning smaller ranges or using view-key mode");
            }
        }

        if !self.grpc_call_times.is_empty() {
            let avg_grpc = self.total_grpc_time.as_secs_f64() / self.grpc_call_times.len() as f64;
            if avg_grpc > 2.0 {
                println!(
                    "🌐 GRPC calls are very slow (avg: {:.3}s per batch)",
                    avg_grpc
                );
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
