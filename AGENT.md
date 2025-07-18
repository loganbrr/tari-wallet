# Tari Lightweight Wallet Libraries - Enhanced Agent Instructions

## Build/Test Commands

### Core Commands
- `cargo test` - Run all unit tests
- `cargo test --all-features` - Run tests with all features enabled
- `cargo test --features grpc-storage` - Most comprehensive test suite (scanning + persistence)
- `cargo test --features grpc` - Run tests with GRPC blockchain scanning
- `cargo test --features storage` - Run tests with database storage
- `cargo test test_name` - Run specific test by name
- `cargo check` - Fast compile check without building
- `cargo build --release` - Production build

### WASM Commands
- `wasm-pack test --node --features wasm` - WASM-specific tests
- `wasm-pack build --target web --out-dir examples/wasm/pkg --features http` - Build WASM module for web
- `wasm-pack build --target nodejs --out-dir examples/wasm/pkg --features http` - Build WASM module for node

### CLI Usage
- `cargo run --bin scanner --features grpc-storage` - Main blockchain scanner
- `cargo run --bin wallet --features storage` - Wallet management CLI

### Quality & Dependencies
- `cargo clippy --all-features -- -D warnings` - Enforce strict linting across all features
- `cargo machete` - Detect unused dependencies (configured in Cargo.toml)
- `cargo +nightly fmt` - Format code with nightly formatter features

## Environment Setup

### Prerequisites
- **Rust**: 1.70+ (tested with 1.90.0-nightly)
- **Tools**: `wasm-pack` (0.13.1+), `cargo machete`
- **Platform**: Cross-platform (native + WASM)

### Dependencies
- **Tari ecosystem**: tari_crypto 0.22, tari_utilities 0.8, tari_script 1.0.0-rc.5
- **Crypto**: chacha20poly1305, curve25519-dalek, blake2
- **Platform-specific**: reqwest (native), web-sys (WASM)

## Architecture & Structure

### Libraries and Binaries
 - **Primary Focus** - This repository is primarily a library implementation. the binaries should always be lightweight wrappers around the library functionality.
 
### Core Modules
- **wallet/**: Master keys, addresses, metadata management
- **key_management/**: Tari Index based key generation, seed phrases
- **data_structures/**: Addresses, transactions, outputs, encrypted data (13 modules)
- **validation/**: Range proofs, commitments, signatures, batch processing (9 modules)
- **scanning/**: GRPC/HTTP blockchain scanners for UTXO discovery
- **extraction/**: UTXO processing and wallet output reconstruction
- **storage/**: Optional SQLite database support

### Feature Flags & Targets
- **Default**: `http` - Basic wallet functionality with HTTP scanning
- **grpc**: GRPC blockchain scanning with rayon parallel processing
- **storage**: SQLite persistence with async support
- **wasm**: WebAssembly compatibility with web-sys bindings
- **Combined**: `grpc-storage`, `http-storage` for full functionality

### Module Dependencies (⚠️ CIRCULAR DEPENDENCY ISSUES)
**KNOWN PROBLEM**: data_structures → validation → extraction → data_structures
- **Root cause**: data_structures imports ValidationError, validation imports data types
- **Impact**: Compilation complexity, refactoring difficulty
- **Solution needed**: Break cycle with core/primitives layer

### Database Architecture
- **File**: `wallet.db` (SQLite)
- **Tables**: wallets, transactions, outputs, metadata
- **Features**: Async operations via tokio-rusqlite
- **Threading**: Connection pooling for concurrent access

## Security Patterns & Requirements

### Critical Security Practices (NON-NEGOTIABLE)
1. **Zeroize sensitive data**: All private keys, seed phrases, transaction components
2. **No secrets in logs**: Use `console_log!` in WASM, avoid Debug on sensitive types
3. **Real crypto validation**: Replace TODO stubs with actual verification
4. **Memory protection**: Use `SafeArray<N>` for fixed-size sensitive data
5. **Feature gating**: Security-critical code must not depend on optional features

### Current Security Issues (🚨 CRITICAL)
- **Fake validation**: range_proofs.rs and metadata_signature.rs only check structure, not cryptographic validity
- **Default insecure**: `full_verification: false` by default in validators
- **TODO stubs**: Lines 84-86 in range_proofs.rs, lines 99-100 in metadata_signature.rs

### Zeroize Implementation Patterns
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct SensitiveData {
    private_key: PrivateKey,
    #[zeroize(skip)]  // Skip non-sensitive fields
    public_data: PublicKey,
}

// Manual implementation for complex types
impl Zeroize for Wallet {
    fn zeroize(&mut self) {
        self.master_key.zeroize();
        // Zeroize all sensitive fields
    }
}
```

## Code Quality Standards

### Linting Configuration (Enforced via .cargo/config.toml)
- **Enforced**: `clippy::all`, `clippy::pedantic`
- **Warnings**: `clippy::nursery`
- **Allowed exceptions**: missing_errors_doc, missing_panics_doc, must_use_candidate, module_name_repetitions
- **Dead code**: `-D dead_code`, `-D unused_imports`, `-D unused_variables`

### Complexity Thresholds
- **Max function length**: 50 lines (current avg: 18 lines)
- **Max parameters**: 7 (use `#[allow(clippy::too_many_arguments)]` sparingly)
- **Cyclomatic complexity**: Keep functions simple, extract helpers

### Current Quality Issues
- **Excessive allows**: 9 instances of `#[allow(clippy::too_many_arguments)]`
- **Dead code**: Functions marked `#[allow(dead_code)]` need removal
- **Monster functions**: Some test functions >300 lines

## Performance-Critical Code Paths

### Scanning Operations (⚠️ HOTTEST PATHS)
- **File**: `src/scanning/mod.rs` lines 650-730
- **Issue**: O(n²) progress calculations - recalculates totals by iterating all previous results
- **Impact**: Performance degrades quadratically with scan length
- **Fix needed**: Maintain running counters instead of recalculating

### Memory Usage Issues
- **File**: `src/scanning/mod.rs` lines 520-570
- **Issue**: Excessive `.clone()` calls on large Vec<Block> during batch processing
- **Impact**: Memory exhaustion on long scans
- **Fix needed**: Use `Arc<Vec<_>>` or references

### Batch Validation Duplication
- **File**: `src/validation/batch.rs`
- **Issue**: `validate_output_batch` and `validate_output_batch_parallel` are copy-paste with only iterator changed
- **Fix needed**: Extract `validate_single_output` function

### Crypto Validation Performance
- **Range proofs**: BulletProofPlus verification is computationally expensive
- **Signature validation**: EdDSA signature checks in metadata validation
- **Batching opportunity**: Use rayon for parallel validation where cryptographically safe

## Error Handling Patterns

### Hierarchical Error Design
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LightweightWalletError {
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),
    
    #[error("Data structure error: {0}")]
    DataStructure(#[from] DataStructureError),
}
```

### Error Propagation
- Use `?` operator throughout
- Provide context with `map_err()` when crossing module boundaries
- Replace `unwrap()` with `expect("descriptive message")`

## Development Workflow Patterns

### Testing Strategy
- **Unit tests**: Per module in same file
- **Integration tests**: `tests/` directory for end-to-end workflows  
- **Feature tests**: Test feature flag combinations
- **WASM tests**: Use `wasm-bindgen-test` for browser/node compatibility

### CLI Testing Commands
```bash
# Test specific scanner scenarios
cargo run --bin scanner --features grpc-storage -- --seed-phrase "your seed phrase"
cargo run --bin scanner --features grpc-storage -- --view-key "64_char_hex" --from-block 1000

# Test wallet operations
cargo run --bin wallet --features storage generate
cargo run --bin wallet --features storage query balance
```

### Debugging Performance Issues
```bash
# Profile memory usage
cargo build --release
valgrind --tool=massif target/release/scanner

# Profile CPU usage  
cargo build --release
perf record target/release/scanner
perf report
```

## Platform-Specific Considerations

### WASM Specifics
- **HTTP client**: Use web-sys instead of reqwest
- **Logging**: Use `console_log!` macro, not println!
- **Async**: wasm-bindgen-futures for Promise compatibility
- **RNG**: getrandom with "js" feature for browser entropy

### Native vs WASM Dependencies
```toml
# Native (full featured)
[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
reqwest = { version = "0.12", features = ["json", "stream"] }
tokio = { version = "1.0", features = ["full"] }

# WASM (browser compatible)  
[target.'cfg(target_arch = "wasm32")'.dependencies]
web-sys = { version = "0.3", features = ["console", "Request"] }
getrandom = { version = "0.2", features = ["js"] }
```

## Debugging & Troubleshooting

### Common Build Failures
1. **Feature flag issues**: Missing feature dependencies in Cargo.toml
2. **WASM build errors**: Missing web-sys features for browser APIs
3. **Crypto dependency conflicts**: Incompatible tari_crypto versions
4. **Circular dependency**: Compilation hangs due to module cycles

### Development Anti-Patterns (🚫 AVOID)
- **Code duplication**: 3.7% of codebase currently duplicated
- **Fake validation**: Structure-only checks instead of cryptographic verification
- **Memory cloning**: Unnecessary `.clone()` in hot paths
- **Monolithic functions**: >50 line functions should be split
- **Feature coupling**: Don't make security depend on optional features

### Integration Testing Patterns
```rust
#[cfg(test)]
mod integration_tests {
    use crate::wallet::Wallet;
    
    #[tokio::test]
    async fn test_full_wallet_workflow() {
        let wallet = Wallet::generate_new_with_seed_phrase(None)?;
        let address = wallet.get_dual_address(features, None)?;
        // Test complete flow end-to-end
    }
}
```

## Technical Debt Priority

### Critical (Fix Immediately)
1. **Security**: Implement real crypto validation (40 hours estimated)
2. **Performance**: Fix O(n²) scanning progress (2 hours)
3. **Memory**: Reduce cloning in scanning loops (4 hours)
4. **Dead code**: Remove confirmed dead code (8 hours)

### High Priority (Fix This Quarter)
1. **Architecture**: Break circular dependencies (32 hours)
2. **Duplication**: Extract duplicate primitives (20 hours)
3. **Testing**: Break down monster test functions (16 hours)
4. **Validation**: Implement missing abstractions (20 hours)

### Maintenance Tasks
- **Weekly**: Run `cargo machete` to detect unused dependencies
- **Monthly**: Review complexity metrics and refactor >50 line functions
- **Quarterly**: Security audit of crypto validation implementation

## Memory Management

### Sensitive Data Lifecycle
1. **Creation**: Use secure random generation
2. **Processing**: Minimize lifetime, use references where possible
3. **Storage**: Encrypt at rest, use zeroize-compatible types
4. **Destruction**: Explicit zeroize before drop

### Performance Guidelines
- Use `Arc<T>` for shared read-only data
- Use `Cow<T>` for conditional cloning
- Prefer `&str` over `String` in function signatures
- Use `Vec::with_capacity()` when size is known

This enhanced AGENT.md provides comprehensive guidance for navigating the Tari Lightweight Wallet codebase efficiently while maintaining security and performance standards.
