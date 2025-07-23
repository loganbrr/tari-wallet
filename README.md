# Tari Lightweight Wallet Libraries
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/Krakaw/tari-wallet/branch/main/graph/badge.svg)](https://codecov.io/gh/Krakaw/tari-wallet)
[![CI](https://github.com/Krakaw/tari-wallet/workflows/CI/badge.svg)](https://github.com/Krakaw/tari-wallet/actions/workflows/ci.yml)

A standalone, minimal dependency implementation of core Tari wallet functionality designed for lightweight applications, mobile wallets, web applications, and embedded systems.

## 🚀 **What is this?**

The Tari Lightweight Wallet Libraries provide essential wallet functionality extracted from the main Tari codebase, designed to be:

- **🪶 Lightweight**: Minimal dependencies, optimized for resource-constrained environments
- **🌐 Cross-platform**: Native Rust, WASM, mobile, and web compatibility
- **🔒 Secure**: Industry-standard cryptography with secure memory handling
- **🔧 Modular**: Use only the components you need
- **✅ Compatible**: 100% compatible with main Tari wallet key derivation and address generation

## 🎯 **Key Features**

### 💼 **Wallet Operations**
- ✅ Create wallets from seed phrases (24-word Tari CipherSeed format)
- ✅ Generate new wallets with cryptographically secure entropy
- ✅ Master key derivation following Tari specification
- ✅ Wallet metadata management and secure storage

### 🔑 **Key Management**
- ✅ BIP39-like mnemonic generation and validation (Tari format)
- ✅ Hierarchical deterministic key derivation
- ✅ View and spend key generation
- ✅ Stealth address support
- ✅ Secure key zeroization and memory protection

### 🏠 **Address Generation**
- ✅ Dual addresses (view + spend keys) for advanced features
- ✅ Single addresses (spend key only) for simplified use
- ✅ Multiple formats: Emoji 🦀, Base58, and Hex
- ✅ Payment ID embedding and extraction
- ✅ Network support (MainNet, StageNet, Esmeralda, LocalNet)

### 🔍 **Blockchain Scanning**
- ✅ GRPC-based blockchain scanning with Tari base nodes
- ✅ UTXO discovery and wallet output reconstruction
- ✅ Progress tracking and interactive error handling
- ✅ Batch processing with configurable block ranges
- ✅ Multiple scanning strategies (one-sided, recoverable, coinbase)
- ✅ Resume functionality for interrupted scans
- ✅ Multiple output formats (detailed, summary, JSON)

### 🔒 **Cryptographic Validation**
- ✅ Range proof validation and rewinding
- ✅ Encrypted data decryption using view keys
- ✅ Commitment validation and verification
- ✅ Payment ID extraction and decoding
- ✅ Stealth address key recovery

### ✍️ **Message Signing & Verification**
- ✅ Tari-compatible Schnorr signature generation
- ✅ Domain-separated message signing for security
- ✅ Hex-encoded signature components for transport
- ✅ Complete signature verification workflows
- ✅ CLI tool for signing and verification operations
- ✅ JSON and compact output formats

## 📦 **Installation**

Add to your `Cargo.toml`:

```toml
[dependencies]
lightweight_wallet_libs = "0.1"

# Optional features
lightweight_wallet_libs = { version = "0.1", features = ["wasm", "grpc"] }
```

### Feature Flags

- `default`: Core wallet functionality
- `wasm`: WASM compatibility and JavaScript bindings
- `grpc`: GRPC blockchain scanning support

## 🏗️ **Quick Start**

### Create a New Wallet

```rust
use lightweight_wallet_libs::wallet::Wallet;
use lightweight_wallet_libs::data_structures::address::TariAddressFeatures;

// Generate a new wallet with a 24-word seed phrase
let wallet = Wallet::generate_new_with_seed_phrase(None)?;

// Export the seed phrase for backup
let seed_phrase = wallet.export_seed_phrase()?;
println!("Backup this seed phrase: {}", seed_phrase);

// Generate a dual Tari address (supports both interactive and one-sided payments)
let features = TariAddressFeatures::create_interactive_and_one_sided();
let address = wallet.get_dual_address(features, None)?;

println!("Your Tari address (emoji): {}", address.to_emoji_string());
println!("Your Tari address (base58): {}", address.to_base58());

// Generate a single address (spend key only, simpler)
let single_features = TariAddressFeatures::create_one_sided_only();
let single_address = wallet.get_single_address(single_features)?;
println!("Single address: {}", single_address.to_base58());
```

### Restore Wallet from Seed Phrase

```rust
use lightweight_wallet_libs::wallet::Wallet;
use lightweight_wallet_libs::data_structures::address::TariAddressFeatures;

// Restore wallet from existing seed phrase
let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
let wallet = Wallet::new_from_seed_phrase(seed_phrase, None)?;

// Generate the same address as before
let address = wallet.get_dual_address(
    TariAddressFeatures::create_interactive_and_one_sided(),
    None
)?;
```

### Key Management

```rust
use lightweight_wallet_libs::key_management::{
    generate_seed_phrase,
    validate_seed_phrase,
    seed_phrase::{CipherSeed, mnemonic_to_bytes},
};

// Generate a new 24-word seed phrase
let seed_phrase = generate_seed_phrase()?;
println!("Generated seed phrase: {}", seed_phrase);

// Validate an existing seed phrase
validate_seed_phrase(&seed_phrase)?;
println!("Seed phrase is valid!");

// Work with CipherSeed for advanced operations
let cipher_seed = CipherSeed::new(); // Creates with random entropy
let encrypted_bytes = cipher_seed.encipher(Some("optional_passphrase"))?;

// Convert bytes back to mnemonic
let encrypted_bytes = mnemonic_to_bytes(&seed_phrase)?;
let cipher_seed = CipherSeed::from_enciphered_bytes(&encrypted_bytes, Some("optional_passphrase"))?;
let entropy = cipher_seed.entropy();
println!("Extracted entropy: {:?}", entropy);
```

### Message Signing & Verification

```rust
use lightweight_wallet_libs::crypto::signing::{
    sign_message_with_hex_output, 
    verify_message_from_hex,
    derive_tari_signing_key,
    sign_message_with_tari_wallet
};
use tari_crypto::{
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use tari_utilities::hex::Hex;
use rand::rngs::OsRng;

// Method 1: Using a random key (for testing)
let secret_key = RistrettoSecretKey::random(&mut OsRng);
let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
let message = "Hello, Tari! This message is cryptographically signed.";
let (signature_hex, nonce_hex) = sign_message_with_hex_output(&secret_key, message)?;

// Method 2: Using Tari wallet-compatible key derivation (RECOMMENDED)
let seed_phrase = "your 24-word seed phrase here...";
let message = "Hello, Tari! Signed with real wallet key.";

// Derive the exact same communication key that Tari wallet uses
let tari_signing_key = derive_tari_signing_key(seed_phrase, None)?;
let tari_public_key = RistrettoPublicKey::from_secret_key(&tari_signing_key);

// Sign with the Tari wallet key
let (tari_sig_hex, tari_nonce_hex) = sign_message_with_tari_wallet(seed_phrase, message, None)?;

println!("Message: {}", message);
println!("Tari Signature: {}", tari_sig_hex);
println!("Tari Nonce: {}", tari_nonce_hex);

// Verify the signature
let is_valid = verify_message_from_hex(&tari_public_key, message, &tari_sig_hex, &tari_nonce_hex)?;
println!("Tari signature valid: {}", is_valid);

// This signature is cryptographically identical to what official Tari wallet would produce
```

### Blockchain Scanning

```rust
use lightweight_wallet_libs::scanning::{GrpcScannerBuilder, BlockchainScanner};
use lightweight_wallet_libs::wallet::Wallet;

// Connect to a Tari base node
let mut scanner = GrpcScannerBuilder::new()
    .with_base_url("http://127.0.0.1:18142".to_string())
    .with_timeout(std::time::Duration::from_secs(30))
    .build().await?;

// Create wallet for scanning
let wallet = Wallet::new_from_seed_phrase("your seed phrase here", None)?;

// Get blockchain tip and scan from wallet birthday
let tip_info = scanner.get_tip_info().await?;
let from_block = wallet.birthday();
let to_block = tip_info.best_block_height;

// Scan specific block range
let block_info = scanner.get_block_by_height(12345).await?;
if let Some(block) = block_info {
    println!("Block {} has {} outputs", block.height, block.outputs.len());
}
```

### Advanced Blockchain Scanning

The scanner provides comprehensive blockchain analysis with multiple scanning modes:

```rust
// The scanner example demonstrates advanced features like:
// 
// 1. Seed phrase OR view key scanning
// cargo run --bin scanner --features grpc -- --seed-phrase "your seed phrase"
// cargo run --bin scanner --features grpc -- --view-key "64_char_hex_view_key"
//
// 2. Flexible block range scanning
// cargo run --bin scanner --features grpc -- --from-block 1000 --to-block 2000
// cargo run --bin scanner --features grpc -- --blocks 1000,1500,2000,2500
//
// 3. Multiple output formats
// cargo run --bin scanner --features grpc -- --format detailed  # Full transaction history
// cargo run --bin scanner --features grpc -- --format summary   # Compact overview  
// cargo run --bin scanner --features grpc -- --format json      # Machine-readable
//
// 4. Error recovery and resume functionality
// When errors occur, the scanner provides interactive options and resume commands
//
// 5. Progress tracking with real-time statistics
// Shows blocks/second, outputs found, balance changes, etc.
```

**Scanner Features:**
- **Dual Input Methods**: Use seed phrase (full wallet) or view key (view-only)  
- **Interactive Error Handling**: Continue, skip, or abort on GRPC errors with resume commands
- **Transaction History**: Complete chronological transaction listing with spent/unspent tracking
- **Payment ID Decoding**: Automatic extraction and UTF-8 decoding of payment IDs
- **Balance Analysis**: Running balances, net flow calculations, and transaction breakdowns
- **Maturity Tracking**: Coinbase output maturity detection and immature balance warnings

## 🏛️ **Architecture**

```
lightweight_wallet_libs/
├── wallet/           # Core wallet operations
├── key_management/   # Key derivation and mnemonics  
├── data_structures/  # Wallet data types
├── validation/       # Cryptographic validation
├── extraction/       # UTXO processing
├── scanning/         # Blockchain scanning
├── crypto/           # Independent crypto primitives
│   ├── signing.rs    # Message signing and verification
│   └── hash_domain.rs # Domain separation for security  
└── errors/           # Comprehensive error handling
```

### Core Components

- **`Wallet`**: Main wallet struct for key management and address generation
- **`CipherSeed`**: Tari's encrypted seed format with birthday tracking
- **`TariAddress`**: Dual and single address types with multiple encoding formats
- **`BlockchainScanner`**: GRPC-based scanning for wallet output discovery
- **`ValidationEngine`**: Cryptographic proof and signature validation
- **`MessageSigning`**: Tari-compatible Schnorr signature creation and verification

## 🌐 **Cross-Platform Support**

### Native Rust
```rust
// Standard Rust usage
let wallet = Wallet::generate_new_with_seed_phrase(None)?;
```

### WASM (Web Assembly)
```rust
// WASM-compatible with feature flag
#[cfg(feature = "wasm")]
use lightweight_wallet_libs::wasm::*;
```

### Mobile Development
- Android: Use via JNI bindings
- iOS: Use via C FFI or Swift Package Manager
- React Native: Use via WASM bindings

## 🧪 **CLI Tools**

The project includes powerful command-line tools for wallet operations:

### 💼 **Wallet CLI** - Complete wallet management
```bash
# Create new wallet with seed phrase
cargo run --bin wallet new-wallet

# Generate address from existing seed phrase
cargo run --bin wallet new-address "your 24-word seed phrase here"

# Create wallet with payment ID and custom network
cargo run --bin wallet new-wallet --network stagenet --payment-id "my-payment-123"
```

### 🔍 **Scanner CLI** - Advanced blockchain analysis
```bash
# Comprehensive blockchain scanning (requires running Tari base node)
cargo run --bin scanner --features grpc -- --seed-phrase "your seed phrase"

# Scan specific block range with view key
cargo run --bin scanner --features grpc -- --view-key "your_64_char_hex_view_key" --from-block 1000 --to-block 2000

# Scan with multiple output formats
cargo run --bin scanner --features grpc -- --seed-phrase "your seed phrase" --format summary --quiet
```

### ✍️ **Signing CLI** - Message signing and verification
```bash
# Generate a new keypair
cargo run --bin signing --features storage -- generate --stdout

# Save keypair to files
cargo run --bin signing --features storage -- generate --secret-key-file secret.key --public-key-file public.key

# Sign a message using secret key file
cargo run --bin signing --features storage -- sign \
    --secret-key-file secret.key \
    --message "Hello, Tari! This is a signed message."

# Sign a message using wallet from database (requires storage feature)
cargo run --bin signing --features storage -- sign \
    --wallet-name my_wallet \
    --database-path wallet.db \
    --message "Hello, Tari! Signed with wallet from database."

# Sign with JSON output format
cargo run --bin signing --features storage -- sign \
    --secret-key-file secret.key \
    --message "Test message" \
    --format json \
    --output-file signature.json

# Verify a signature using hex components
cargo run --bin signing --features storage -- verify \
    --public-key-file public.key \
    --message "Hello, Tari! This is a signed message." \
    --signature <signature_hex> \
    --nonce <nonce_hex> \
    --verbose

# Verify using signature file (compact format)
cargo run --bin signing --features storage -- verify \
    --public-key-file public.key \
    --message "Test message" \
    --signature-file signature.txt

# Verify using JSON signature file
cargo run --bin signing --features storage -- verify \
    --public-key-file public.key \
    --message "Test message" \
    --signature-file signature.json

# Sign and verify workflow with files
echo "My important message" > message.txt
cargo run --bin signing --features storage -- sign \
    --secret-key-file secret.key \
    --message-file message.txt \
    --output-file signature.txt

cargo run --bin signing --features storage -- verify \
    --public-key-file public.key \
    --message-file message.txt \
    --signature-file signature.txt

# Complete database workflow: create wallet and sign
# 1. Generate a new seed phrase
SEED=$(cargo run --bin wallet --features storage -- generate | head -1 | cut -d' ' -f2-)

# 2. Add wallet to database  
cargo run --bin wallet --features storage -- add-wallet \
    --name my_signing_wallet \
    --database wallet.db \
    "$SEED"

# 3. Sign messages using the wallet from database
cargo run --bin signing --features storage -- sign \
    --wallet-name my_signing_wallet \
    --database-path wallet.db \
    --message "Signed with database wallet!"

# 4. List available wallets
cargo run --bin wallet --features storage -- list --database wallet.db
```

#### **Signing CLI Features:**
- **🔑 Keypair Generation**: Create new Ed25519 keypairs with secure randomness
- **✍️ Message Signing**: Sign arbitrary messages with Schnorr signatures  
- **✅ Signature Verification**: Verify signatures with detailed validation
- **📁 File Support**: Read keys/messages from files for automation
- **🎯 Multiple Formats**: Compact (sig:nonce) and JSON output formats
- **🔧 Flexible Input**: Support command-line args and file inputs
- **📊 Verbose Mode**: Detailed output for debugging and verification
- **🔒 Tari Compatible**: 100% compatible with Tari wallet message signing
- **💾 Database Integration**: Sign with wallets stored in SQLite database (storage feature)  
- **🔗 Seed Phrase Derivation**: Uses Tari communication node identity key ("comms" branch)
- **🔑 Deterministic Keys**: Same seed phrase always produces identical signatures
- **⚡ Exit Codes**: Returns proper exit codes (0=success, 1=invalid signature) for scripting

## 🔒 **Security Features**

- **Secure Memory**: Automatic zeroization of sensitive data
- **Constant-time Operations**: Timing attack resistant comparisons
- **Domain Separation**: Cryptographic domain separation for security
- **Memory Safety**: Rust's memory safety guarantees
- **Secure Randomness**: Cryptographically secure random number generation

## ⚡ **Performance**

- **Batch Operations**: Optimized for processing multiple UTXOs
- **Parallel Processing**: Optional parallel validation (with `parallel` feature)
- **Memory Efficient**: Minimal memory footprint for mobile/embedded use
- **Fast Scanning**: Efficient blockchain scanning with progress tracking

## 🧰 **Use Cases**

### ✅ **Perfect For**
- 📱 Mobile wallet applications
- 🌐 Web wallets and browser extensions
- 🔧 Hardware wallet firmware
- 📡 Lightweight desktop applications
- 🚀 DeFi integrations requiring Tari addresses
- 🔍 Blockchain analysis tools
- ✍️ Message signing and authentication systems

### ❌ **Not Suitable For**
- ⛏️ Running Tari base nodes
- 🏭 Mining operations
- 🌐 Peer-to-peer networking
- 💾 Full blockchain storage
- 🏛️ Consensus mechanisms

## 🆚 **vs. Main Tari Project**

| Feature | Main Tari | Lightweight Libs |
|---------|-----------|------------------|
| **Purpose** | Full blockchain protocol | Wallet functionality only |
| **Dependencies** | Heavy (tari-* crates) | Minimal (crypto only) |
| **Size** | ~100MB+ | ~5MB |
| **Platforms** | Desktop/Server | All platforms + WASM |
| **Use Case** | Run nodes/miners | Build wallet apps |

## 🤝 **Contributing**

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Krakaw/tari-wallet.git
cd tari-wallet

# Run tests
cargo test

# Run with all features
cargo test --all-features

# Check WASM compatibility
cargo check --target wasm32-unknown-unknown --features wasm

# Test signing binary
cargo test --bin signing --features storage
```

### Testing

```bash
# Unit tests
cargo test

# Integration tests with GRPC (requires base node)
cargo test --features grpc

# Test specific binaries
cargo test --bin wallet --features storage
cargo test --bin scanner --features grpc-storage
cargo test --bin signing --features storage

# WASM tests
wasm-pack test --node --features wasm
```

### Test Coverage

```bash
# Install tarpaulin for code coverage
cargo install cargo-tarpaulin

# Generate coverage report (uses tarpaulin.toml config)
cargo tarpaulin

# Generate coverage with custom options
cargo tarpaulin --all-features --out html --output-dir coverage

# View HTML coverage report
open coverage/tarpaulin-report.html  # macOS
xdg-open coverage/tarpaulin-report.html  # Linux

# Generate coverage for CI (XML format for Codecov)
cargo tarpaulin --all-features --out xml --output-dir coverage
```

The coverage configuration is defined in `tarpaulin.toml` and excludes:
- Binary files (`src/bin/*`)
- Examples and test files
- Long-running stress tests that would slow down CI

Current coverage target: **70%** minimum (adjustable in `tarpaulin.toml`)

## 📋 **Compatibility**

- **Rust**: 1.70.0 or later
- **WASM**: All major browsers
- **Mobile**: iOS 12+, Android API 21+
- **Tari**: Compatible with main Tari wallet key derivation

## 📄 **License**

This project is licensed under the [BSD 3-Clause License](LICENSE).
