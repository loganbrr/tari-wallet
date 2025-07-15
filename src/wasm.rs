use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use tari_utilities::ByteArray;

use crate::{
    data_structures::{
        types::PrivateKey,
        payment_id::PaymentId,
        wallet_transaction::WalletState,
        transaction::TransactionDirection,
        block::Block,
        transaction_output::LightweightTransactionOutput,
        transaction_input::TransactionInput,
    },
    key_management::{
        key_derivation,
        seed_phrase::{mnemonic_to_bytes, CipherSeed},
    },
};

/// Derive a public key from a master key, returning it as a hex string.
#[wasm_bindgen]
pub fn derive_public_key_hex(master_key: &[u8]) -> Result<String, JsValue> {
    if master_key.len() != 32 {
        return Err(JsValue::from_str("master_key must be 32 bytes"));
    }
    // Simplified implementation - just return the master key as hex for now
    Ok(hex::encode(master_key))
}

/// Simple BlockInfo struct for WASM (no async dependencies)
#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub height: u64,
    pub hash: Vec<u8>,
    pub timestamp: u64,
    pub outputs: Vec<LightweightTransactionOutput>,
    pub inputs: Vec<TransactionInput>, // Use proper TransactionInput
    pub kernels: Vec<u8>, // Simplified for WASM
}

/// WASM-compatible wallet scanner
#[wasm_bindgen]
pub struct WasmScanner {
    view_key: PrivateKey,
    entropy: [u8; 16],
    wallet_state: WalletState,
}

/// Block data structure for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockData {
    pub height: u64,
    pub hash: String,
    pub timestamp: u64,
    pub outputs: Vec<OutputData>,
    pub inputs: Vec<InputData>,
}

/// Output data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputData {
    pub commitment: String,
    pub sender_offset_public_key: String,
    pub encrypted_data: String,
    pub minimum_value_promise: u64,
    pub features: Option<String>,
    pub script: Option<String>,
    pub metadata_signature: Option<String>,
    pub covenant: Option<String>,
}

/// Input data structure (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputData {
    pub commitment: String,
    pub script: Option<String>,
    pub input_data: Option<String>,
    pub script_signature: Option<String>,
    pub sender_offset_public_key: Option<String>,
}

/// Scan result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub total_outputs: u64,
    pub total_spent: u64,
    pub total_value: u64,
    pub current_balance: u64,
    pub blocks_processed: u64,
    pub transactions: Vec<TransactionSummary>,
    pub success: bool,
    pub error: Option<String>,
}

/// Transaction summary for results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSummary {
    pub block_height: u64,
    pub value: u64,
    pub direction: String,
    pub status: String,
    pub is_spent: bool,
    pub payment_id: Option<String>,
}

impl WasmScanner {
    /// Create scanner from seed phrase
    pub fn from_seed_phrase(seed_phrase: &str) -> Result<Self, String> {
        // Convert seed phrase to bytes
        let encrypted_bytes = mnemonic_to_bytes(seed_phrase)
            .map_err(|e| format!("Failed to convert seed phrase: {}", e))?;
        
        let cipher_seed = CipherSeed::from_enciphered_bytes(&encrypted_bytes, None)
            .map_err(|e| format!("Failed to create cipher seed: {}", e))?;
        
        let entropy = cipher_seed.entropy();
        let entropy_array: [u8; 16] = entropy.try_into()
            .map_err(|_| "Invalid entropy length".to_string())?;
        
        // Derive view key from entropy
        let view_key_raw = key_derivation::derive_private_key_from_entropy(
            &entropy_array,
            "data encryption",
            0,
        ).map_err(|e| format!("Failed to derive view key: {}", e))?;
        
        let view_key = PrivateKey::new(view_key_raw.as_bytes().try_into()
            .map_err(|_| "Failed to convert view key".to_string())?);
        
        Ok(Self {
            view_key,
            entropy: entropy_array,
            wallet_state: WalletState::new(),
        })
    }

    /// Create scanner from view key
    pub fn from_view_key(view_key_hex: &str) -> Result<Self, String> {
        let view_key_bytes = hex::decode(view_key_hex)
            .map_err(|e| format!("Invalid hex format: {}", e))?;
        
        if view_key_bytes.len() != 32 {
            return Err("View key must be exactly 32 bytes (64 hex characters)".to_string());
        }

        let view_key_array: [u8; 32] = view_key_bytes.try_into()
            .map_err(|_| "Failed to convert view key to array".to_string())?;
        
        let view_key = PrivateKey::new(view_key_array);
        let entropy = [0u8; 16]; // Default entropy for view-key only mode
        
        Ok(Self {
            view_key,
            entropy,
            wallet_state: WalletState::new(),
        })
    }

    /// Process block data
    pub fn process_block(&mut self, block_data: &BlockData) -> ScanResult {
        // Convert block data to internal format
        let block_info = match self.convert_block_data_to_internal(block_data) {
            Ok(info) => info,
            Err(e) => {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(e),
                };
            }
        };

        // Create Block directly
        let block = Block::new(
            block_info.height,
            block_info.hash,
            block_info.timestamp,
            block_info.outputs,
            block_info.inputs,
        );

        // Process block
        let found_outputs = match block.process_outputs(&self.view_key, &self.entropy, &mut self.wallet_state) {
            Ok(count) => count,
            Err(e) => {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(format!("Failed to process outputs: {}", e)),
                };
            }
        };

        let spent_outputs = match block.process_inputs(&mut self.wallet_state) {
            Ok(count) => count,
            Err(e) => {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(format!("Failed to process inputs: {}", e)),
                };
            }
        };

        self.create_scan_result(found_outputs, spent_outputs, 1)
    }

    /// Convert block data to internal format
    fn convert_block_data_to_internal(&self, block_data: &BlockData) -> Result<BlockInfo, String> {
        let block_hash = hex::decode(&block_data.hash)
            .map_err(|e| format!("Invalid block hash: {}", e))?;

        // Convert outputs
        let mut outputs = Vec::new();
        for output_data in &block_data.outputs {
            let output = self.convert_output_data(output_data)?;
            outputs.push(output);
        }

        // Convert inputs  
        let mut inputs = Vec::new();
        for input_data in &block_data.inputs {
            let input = self.convert_input_data(input_data)?;
            inputs.push(input);
        }

        Ok(BlockInfo {
            height: block_data.height,
            hash: block_hash,
            timestamp: block_data.timestamp,
            outputs,
            inputs,
            kernels: Vec::new(), // Kernels not provided in current API
        })
    }

    /// Convert OutputData to LightweightTransactionOutput
    fn convert_output_data(&self, output_data: &OutputData) -> Result<LightweightTransactionOutput, String> {
        use crate::data_structures::{
            types::{CompressedCommitment, CompressedPublicKey, MicroMinotari},
            encrypted_data::EncryptedData,
            wallet_output::{LightweightOutputFeatures, LightweightScript, LightweightSignature, LightweightCovenant},
        };

        // Parse commitment
        let commitment = CompressedCommitment::from_hex(&output_data.commitment)
            .map_err(|e| format!("Invalid commitment hex: {}", e))?;

        // Parse sender offset public key
        let sender_offset_public_key = CompressedPublicKey::from_hex(&output_data.sender_offset_public_key)
            .map_err(|e| format!("Invalid sender offset public key hex: {}", e))?;

        // Parse encrypted data
        let encrypted_data = EncryptedData::from_hex(&output_data.encrypted_data)
            .map_err(|e| format!("Invalid encrypted data hex: {}", e))?;

        // Create output with available data
        Ok(LightweightTransactionOutput::new_current_version(
            LightweightOutputFeatures::default(), // Use default features
            commitment,
            None, // Range proof not provided in UTXO sync
            LightweightScript::default(), // Script not provided or use default
            sender_offset_public_key,
            LightweightSignature::default(), // Metadata signature not provided or use default
            LightweightCovenant::default(), // Covenant not provided or use default
            encrypted_data,
            MicroMinotari::from(output_data.minimum_value_promise),
        ))
    }

    /// Convert InputData to TransactionInput
    fn convert_input_data(&self, input_data: &InputData) -> Result<TransactionInput, String> {
        use crate::data_structures::{
            types::{CompressedPublicKey, MicroMinotari},
            transaction_input::LightweightExecutionStack,
        };

        // Parse commitment
        let commitment_bytes = hex::decode(&input_data.commitment)
            .map_err(|e| format!("Invalid input commitment hex: {}", e))?;
        
        if commitment_bytes.len() != 32 {
            return Err("Commitment must be exactly 32 bytes".to_string());
        }
        
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&commitment_bytes);

        // Parse sender offset public key if provided
        let sender_offset_public_key = if let Some(ref pk_hex) = input_data.sender_offset_public_key {
            CompressedPublicKey::from_hex(pk_hex)
                .map_err(|e| format!("Invalid sender offset public key hex: {}", e))?
        } else {
            CompressedPublicKey::default()
        };

        // Create input with available data
        Ok(TransactionInput {
            version: 1,
            features: 0, // Default features
            commitment,
            script_signature: [0u8; 64], // Not provided in UTXO sync
            sender_offset_public_key,
            covenant: Vec::new(), // Not provided
            input_data: LightweightExecutionStack::new(), // Not provided
            output_hash: [0u8; 32], // Not provided in UTXO sync
            output_features: 0, // Not provided
            output_metadata_signature: [0u8; 64], // Not provided
            maturity: 0, // Not provided
            value: MicroMinotari::from(0u64), // Not provided in UTXO sync
        })
    }

    /// Create scan result from processing results
    fn create_scan_result(&self, _found_outputs: usize, _spent_outputs: usize, blocks_processed: usize) -> ScanResult {
        let (total_received, _total_spent, balance, unspent_count, spent_count) = self.wallet_state.get_summary();
        
        // Convert transactions to summary format
        let transactions: Vec<TransactionSummary> = self.wallet_state.transactions.iter().map(|tx| {
            TransactionSummary {
                block_height: tx.block_height,
                value: tx.value,
                direction: match tx.transaction_direction {
                    TransactionDirection::Inbound => "inbound".to_string(),
                    TransactionDirection::Outbound => "outbound".to_string(),
                    TransactionDirection::Unknown => "unknown".to_string(),
                },
                status: format!("{:?}", tx.transaction_status),
                is_spent: tx.is_spent,
                payment_id: match &tx.payment_id {
                    PaymentId::Empty => None,
                    _ => Some(tx.payment_id.user_data_as_string()),
                },
            }
        }).collect();

        ScanResult {
            total_outputs: unspent_count as u64,
            total_spent: spent_count as u64,
            total_value: total_received,
            current_balance: balance as u64,
            blocks_processed: blocks_processed as u64,
            transactions,
            success: true,
            error: None,
        }
    }

    /// Get current wallet state
    pub fn get_state(&self) -> String {
        match serde_json::to_string(&self.wallet_state) {
            Ok(json) => json,
            Err(_) => "{}".to_string(),
        }
    }

    /// Reset wallet state
    pub fn reset(&mut self) {
        self.wallet_state = WalletState::new();
    }
}

/// Create a scanner from seed phrase (WASM export)
#[wasm_bindgen]
pub fn create_wasm_scanner(scanner_type: &str, data: &str) -> Result<WasmScanner, JsValue> {
    match scanner_type {
        "seed_phrase" => WasmScanner::from_seed_phrase(data).map_err(|e| JsValue::from_str(&e)),
        "view_key" => WasmScanner::from_view_key(data).map_err(|e| JsValue::from_str(&e)),
        _ => Err(JsValue::from_str("Invalid scanner type. Use 'seed_phrase' or 'view_key'")),
    }
}

/// Scan block data (WASM export)
#[wasm_bindgen]
pub fn scan_block_data(scanner: &mut WasmScanner, block_data_json: &str) -> Result<String, JsValue> {
    let block_data: BlockData = serde_json::from_str(block_data_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse block data: {}", e)))?;

    let result = scanner.process_block(&block_data);
    
    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Get scanner state (WASM export)
#[wasm_bindgen]
pub fn get_scanner_state(scanner: &WasmScanner) -> String {
    scanner.get_state()
}

/// Reset scanner state (WASM export)
#[wasm_bindgen]
pub fn reset_scanner(scanner: &mut WasmScanner) {
    scanner.reset();
}

/// Get version information (WASM export)
#[wasm_bindgen]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
