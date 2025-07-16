# UTXO Output Storage Implementation

## Overview

This implementation adds comprehensive UTXO (Unspent Transaction Output) storage functionality **on top of** the existing transaction storage system. The new functionality enables storing all data necessary for creating new transactions from unspent outputs, while preserving all existing wallet history and transaction tracking capabilities.

## What Was Added

### 1. Database Schema Extension

**New `outputs` table** added alongside existing `wallets` and `wallet_transactions` tables:

```sql
CREATE TABLE outputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wallet_id INTEGER NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    
    -- Core UTXO identification (essential for spending)
    commitment BLOB NOT NULL,                    -- The Pedersen commitment (32 bytes)
    hash BLOB NOT NULL,                          -- Output hash for identification
    value BIGINT NOT NULL,                       -- Value in microMinotari
    
    -- Spending keys (essential for creating transaction inputs)
    spending_key TEXT NOT NULL,                  -- Private key to spend this output
    script_private_key TEXT NOT NULL,            -- Private key for script execution
    
    -- Script and covenant (essential for spending logic)
    script BLOB NOT NULL,                        -- Script that governs spending
    input_data BLOB NOT NULL,                    -- Execution stack data for script
    covenant BLOB NOT NULL,                      -- Covenant restrictions
    
    -- Output features and type (needed for transaction input)
    output_type INTEGER NOT NULL,               -- Type: 0=Payment, 1=Coinbase, etc.
    features_json TEXT NOT NULL,                -- Serialized output features
    
    -- Maturity and lock constraints (essential for spendability)
    maturity BIGINT NOT NULL,                   -- Block height when spendable
    script_lock_height BIGINT NOT NULL,         -- Script lock height
    
    -- Metadata signature components (required for transaction input)
    sender_offset_public_key BLOB NOT NULL,    -- Sender offset public key
    metadata_signature_ephemeral_commitment BLOB NOT NULL,
    metadata_signature_ephemeral_pubkey BLOB NOT NULL,
    metadata_signature_u_a BLOB NOT NULL,
    metadata_signature_u_x BLOB NOT NULL,
    metadata_signature_u_y BLOB NOT NULL,
    
    -- Payment information (for transaction metadata)
    encrypted_data BLOB NOT NULL,              -- Contains payment information
    minimum_value_promise BIGINT NOT NULL,     -- Minimum value promise
    
    -- Range proof (may be needed for verification)
    rangeproof BLOB,                           -- Range proof bytes (nullable)
    
    -- Status and spending tracking (essential for UTXO management)
    status INTEGER NOT NULL DEFAULT 0,         -- 0=Unspent, 1=Spent, 2=Locked, etc.
    mined_height BIGINT,                       -- Block height when mined (for maturity)
    spent_in_tx_id BIGINT,                     -- Transaction ID where spent (nullable)
    
    -- Wallet association and timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(wallet_id, commitment)
);
```

### 2. Data Structures

**New structures in `src/storage/storage_trait.rs`:**

- `StoredOutput` - Complete UTXO data with all fields needed for spending
- `OutputStatus` - Enumeration for output states (Unspent, Spent, Locked, Frozen)
- `OutputFilter` - Query filtering for efficient output retrieval

### 3. Storage Trait Extensions

**New methods added to `WalletStorage` trait:**

```rust
// Basic CRUD operations
async fn save_output(&self, output: &StoredOutput) -> LightweightWalletResult<u32>;
async fn save_outputs(&self, outputs: &[StoredOutput]) -> LightweightWalletResult<Vec<u32>>;
async fn update_output(&self, output: &StoredOutput) -> LightweightWalletResult<()>;
async fn get_output_by_id(&self, output_id: u32) -> LightweightWalletResult<Option<StoredOutput>>;
async fn get_output_by_commitment(&self, commitment: &[u8]) -> LightweightWalletResult<Option<StoredOutput>>;

// Spending management
async fn mark_output_spent(&self, output_id: u32, spent_in_tx_id: u64) -> LightweightWalletResult<()>;
async fn get_unspent_outputs(&self, wallet_id: u32) -> LightweightWalletResult<Vec<StoredOutput>>;
async fn get_spendable_outputs(&self, wallet_id: u32, block_height: u64) -> LightweightWalletResult<Vec<StoredOutput>>;

// Balance and filtering
async fn get_spendable_balance(&self, wallet_id: u32, block_height: u64) -> LightweightWalletResult<u64>;
async fn get_outputs(&self, filter: Option<OutputFilter>) -> LightweightWalletResult<Vec<StoredOutput>>;

// Maintenance operations
async fn delete_output(&self, output_id: u32) -> LightweightWalletResult<bool>;
async fn clear_outputs(&self, wallet_id: u32) -> LightweightWalletResult<()>;
async fn get_output_count(&self, wallet_id: u32) -> LightweightWalletResult<usize>;
```

### 4. SQLite Implementation

**Complete implementation in `src/storage/sqlite.rs`:**

- All new methods implemented with proper error handling
- Optimized indexes for efficient querying
- Database views for common queries
- Automatic timestamp triggers
- Foreign key constraints for data integrity

### 5. Example Usage

**New example:** `examples/utxo_management.rs` demonstrates:

- Creating and storing UTXO outputs
- Querying spendable outputs at specific block heights
- Filtering outputs by value ranges
- Marking outputs as spent
- Batch operations for efficiency
- Balance calculations

## Key Design Decisions

### Fields Kept vs Removed

**Essential fields for transaction creation:**
- All commitment and identification fields
- All spending keys required for transaction inputs
- All script and covenant data needed for spending logic
- All metadata signature components required for `TransactionInput`
- Maturity and lock constraints for spendability validation
- Status tracking for UTXO management
- Core payment data (encrypted_data, minimum_value_promise)
- Range proof for verification when needed

**Fields removed (not needed for transaction creation):**
- `marked_deleted_at_height` - Just tracking info
- `marked_deleted_in_block` - Just tracking info  
- `coinbase_extra` - Coinbase specific data
- `spending_priority` - UI/wallet preference
- `source` - Tracking where it came from
- `last_validation_timestamp` - Validation tracking
- `user_payment_id` - User-facing payment ID
- `mined_timestamp` - Can derive from block if needed
- `mined_in_block` - Can derive from height if needed
- `received_in_tx_id` - Just tracking info

### Integration Approach

**Complementary to existing functionality:**
- Existing `wallet_transactions` table continues to track transaction history
- New `outputs` table focuses specifically on spendable UTXOs
- Both systems can work together for complete wallet functionality
- No existing functionality was removed or modified

## Usage Patterns

### 1. During Wallet Scanning
```rust
// Continue using existing transaction storage for history
storage.save_transactions(wallet_id, &wallet_transactions).await?;

// Additionally store detailed UTXO data for spending
storage.save_outputs(&utxo_outputs).await?;
```

### 2. For Transaction Creation
```rust
// Find spendable outputs at current block height
let spendable_outputs = storage.get_spendable_outputs(wallet_id, current_height).await?;

// Create transaction inputs from outputs
for output in spendable_outputs {
    let tx_input = TransactionInput::new(
        output.output_type as u8,
        output.features_json, // Parse features
        output.commitment.try_into().unwrap(),
        // ... other fields from stored output
    );
    
    // Mark output as spent
    storage.mark_output_spent(output.id.unwrap(), new_tx_id).await?;
}
```

### 3. Balance Queries
```rust
// Get accurate spendable balance considering maturity
let balance = storage.get_spendable_balance(wallet_id, current_height).await?;

// Filter outputs by value for coin selection
let filter = OutputFilter::new()
    .with_wallet_id(wallet_id)
    .with_value_range(min_value, max_value)
    .spendable_at(current_height);
let suitable_outputs = storage.get_outputs(Some(filter)).await?;
```

## Performance Optimizations

### Database Indexes
- `idx_outputs_wallet_status` - Fast queries by wallet and status
- `idx_outputs_spendable` - Optimized spendability checks
- `idx_outputs_commitment` - Quick commitment lookups
- `idx_outputs_maturity` - Efficient maturity filtering

### Views
- `spendable_outputs` - Pre-filtered unspent outputs
- `outputs_spendable_at_height` - Height-based spendability check

### Batch Operations
- `save_outputs()` - Efficient bulk inserts
- Transaction-wrapped operations for consistency

## Testing

Run the example to verify functionality:
```bash
cargo run --example utxo_management --features storage
```

The example demonstrates:
- ✅ Complete CRUD operations
- ✅ Spendability calculations
- ✅ Status management
- ✅ Filtering and querying
- ✅ Batch operations
- ✅ Balance calculations

## Benefits

1. **Complete Transaction Creation Support** - All data needed to spend UTXOs
2. **Preserves Existing Functionality** - Transaction history remains intact
3. **Efficient Querying** - Optimized for common wallet operations
4. **Flexible Filtering** - Multiple query options for coin selection
5. **Proper State Management** - Tracks output lifecycle from unspent to spent
6. **Scalable Design** - Indexes and batch operations for performance

This implementation provides a solid foundation for building transaction creation functionality while maintaining compatibility with all existing wallet operations. 