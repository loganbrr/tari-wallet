use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use tari_utilities::ByteArray;
use web_sys::console;

use crate::{
    data_structures::{
        types::{PrivateKey, CompressedCommitment, CompressedPublicKey, MicroMinotari},
        payment_id::PaymentId,
        wallet_transaction::WalletState,
        transaction::TransactionDirection,
        block::Block,
        transaction_output::LightweightTransactionOutput,
        transaction_input::TransactionInput,
        encrypted_data::EncryptedData,
        wallet_output::{LightweightOutputFeatures, LightweightScript, LightweightSignature, LightweightCovenant},
    },
    key_management::{
        key_derivation,
        seed_phrase::{mnemonic_to_bytes, CipherSeed},
    },
};

// Only import HTTP scanner types when available
#[cfg(feature = "http")]
use crate::scanning::{
    http_scanner::{HttpBlockchainScanner, HttpBlockResponse, HttpBlockData, HttpOutputData},
    ScanConfig, BlockchainScanner,
};

#[cfg(feature = "http")]
use crate::extraction::ExtractionConfig;

/// Simplified block info for WASM serialization
#[derive(Debug, Clone, serde::Serialize)]
pub struct WasmBlockInfo {
    /// Block height
    pub height: u64,
    /// Block hash (hex encoded)
    pub hash: String,
    /// Block timestamp
    pub timestamp: u64,
    /// Number of outputs in this block
    pub output_count: usize,
    /// Number of inputs in this block
    pub input_count: usize,
    /// Number of kernels in this block
    pub kernel_count: usize,
}

#[cfg(feature = "http")]
impl From<crate::scanning::BlockInfo> for WasmBlockInfo {
    fn from(block_info: crate::scanning::BlockInfo) -> Self {
        Self {
            height: block_info.height,
            hash: hex::encode(&block_info.hash),
            timestamp: block_info.timestamp,
            output_count: block_info.outputs.len(),
            input_count: block_info.inputs.len(),
            kernel_count: block_info.kernels.len(),
        }
    }
}

// HTTP data structures for WASM (when HTTP scanner is not available or for legacy compatibility)
#[cfg(not(feature = "http"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlockResponse {
    pub blocks: Vec<HttpBlockData>,
    pub has_next_page: bool,
}

#[cfg(not(feature = "http"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpBlockData {
    pub header_hash: Vec<u8>,
    pub height: u64,
    pub outputs: Vec<HttpOutputData>,
    pub mined_timestamp: u64,
}

#[cfg(not(feature = "http"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpOutputData {
    pub output_hash: Vec<u8>,
    pub commitment: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub sender_offset_public_key: Vec<u8>,
}

/// Derive a public key from a master key, returning it as a hex string.
#[wasm_bindgen]
pub fn derive_public_key_hex(master_key: &[u8]) -> Result<String, JsValue> {
    if master_key.len() != 32 {
        return Err(JsValue::from_str("master_key must be 32 bytes"));
    }
    // Simplified implementation - just return the master key as hex for now
    Ok(hex::encode(master_key))
}

/// WASM-compatible wallet scanner
#[wasm_bindgen]
pub struct WasmScanner {
    #[cfg(feature = "http")]
    http_scanner: Option<HttpBlockchainScanner>,
    view_key: PrivateKey,
    entropy: [u8; 16],
    wallet_state: WalletState,
}

/// Legacy block data structure for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockData {
    pub height: u64,
    pub hash: String,
    pub timestamp: u64,
    pub outputs: Vec<OutputData>,
    pub inputs: Vec<InputData>,
}

/// Legacy output data structure
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

/// Legacy input data structure (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputData {
    pub commitment: String,
    pub script: Option<String>,
    pub input_data: Option<String>,
    pub script_signature: Option<String>,
    pub sender_offset_public_key: Option<String>,
}

/// Block-specific scan result structure (only data found in this block)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockScanResult {
    pub block_height: u64,
    pub block_hash: String,
    pub outputs_found: u64,
    pub inputs_spent: u64,
    pub value_found: u64,
    pub value_spent: u64,
    pub transactions: Vec<TransactionSummary>,
    pub success: bool,
    pub error: Option<String>,
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
    /// Create scanner from string input (automatically detects view key or seed phrase)
    pub fn from_str(data: &str) -> Result<Self, String> {
        // Try view key first
        match Self::from_view_key(data) {
            Ok(scanner) => Ok(scanner),
            Err(view_key_error) => {
                // If view key fails, try seed phrase
                match Self::from_seed_phrase(data) {
                    Ok(scanner) => Ok(scanner),
                    Err(seed_phrase_error) => {
                        // Both failed, return combined error message
                        Err(format!(
                            "Failed to create scanner. View key error: {}. Seed phrase error: {}",
                            view_key_error, seed_phrase_error
                        ))
                    }
                }
            }
        }
    }

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
            #[cfg(feature = "http")]
            http_scanner: None, // Will be initialized when needed
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
            #[cfg(feature = "http")]
            http_scanner: None, // Will be initialized when needed
            view_key,
            entropy,
            wallet_state: WalletState::new(),
        })
    }

    /// Initialize HTTP scanner with base URL (if not already initialized)
    #[cfg(feature = "http")]
    pub async fn initialize_http_scanner(&mut self, base_url: &str) -> Result<(), String> {
        if self.http_scanner.is_none() {
            let scanner = HttpBlockchainScanner::new(base_url.to_string()).await
                .map_err(|e| format!("Failed to initialize HTTP scanner: {}", e))?;
            self.http_scanner = Some(scanner);
        }
        Ok(())
    }

    /// Process HTTP block response using the new HTTP scanner
    #[cfg(feature = "http")]
    pub async fn process_http_blocks_async(&mut self, http_response_json: &str, base_url: Option<&str>) -> ScanResult {
        // Initialize scanner if needed
        if let Some(url) = base_url {
            if let Err(e) = self.initialize_http_scanner(url).await {
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
        }

        // Process blocks using the new method
        self.process_http_blocks_internal(http_response_json)
    }

    /// Process HTTP block response - LEGACY METHOD maintained for compatibility
    pub fn process_http_blocks(&mut self, http_response_json: &str) -> ScanResult {
        self.process_http_blocks_internal(http_response_json)
    }

    /// Internal method to process HTTP blocks
    fn process_http_blocks_internal(&mut self, http_response_json: &str) -> ScanResult {
        // Parse HTTP response
        let http_response: HttpBlockResponse = match serde_json::from_str(http_response_json) {
            Ok(response) => response,
            Err(e) => {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(format!("Failed to parse HTTP response: {}", e)),
                };
            }
        };

        let mut _total_found_outputs = 0;
        let mut _total_spent_outputs = 0;
        let mut blocks_processed = 0;
        let mut batch_transactions = Vec::new();

        // Track initial transaction count to identify new transactions
        let _initial_transaction_count = self.wallet_state.transactions.len();

        // Process each block and collect block-specific transactions
        for http_block in http_response.blocks {
            let block_start_tx_count = self.wallet_state.transactions.len();
            
            match self.process_single_http_block(&http_block) {
                Ok((found_outputs, spent_outputs)) => {
                    _total_found_outputs += found_outputs;
                    _total_spent_outputs += spent_outputs;
                    blocks_processed += 1;

                    // Get transactions added in this block
                    let block_transactions: Vec<TransactionSummary> = self.wallet_state.transactions
                        .iter()
                        .skip(block_start_tx_count)
                        .map(|tx| {
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

                    batch_transactions.extend(block_transactions);
                }
                Err(e) => {
                    return ScanResult {
                        total_outputs: 0,
                        total_spent: 0,
                        total_value: 0,
                        current_balance: 0,
                        blocks_processed,
                        transactions: batch_transactions,
                        success: false,
                        error: Some(format!("Failed to process block {}: {}", http_block.height, e)),
                    };
                }
            }
        }

        // Create result with all transactions found in this batch
        let (total_received, _total_spent, balance, unspent_count, spent_count) = self.wallet_state.get_summary();
        
        ScanResult {
            total_outputs: unspent_count as u64,
            total_spent: spent_count as u64,
            total_value: total_received,
            current_balance: balance as u64,
            blocks_processed: blocks_processed as u64,
            transactions: batch_transactions,
            success: true,
            error: None,
        }
    }

    /// Process single HTTP block using the new HTTP scanner if available, otherwise fallback to legacy method
    fn process_single_http_block(&mut self, http_block: &HttpBlockData) -> Result<(usize, usize), String> {
        // If we have an HTTP scanner, try to use it for better integration
        #[cfg(feature = "http")]
        if self.http_scanner.is_some() {
            return self.process_single_http_block_with_scanner(http_block);
        }
        
        // Fallback to legacy processing
        self.process_single_http_block_legacy(http_block)
    }

    /// Process single HTTP block using HTTP scanner (new method)
    #[cfg(feature = "http")]
    fn process_single_http_block_with_scanner(&mut self, http_block: &HttpBlockData) -> Result<(usize, usize), String> {
        // Convert HTTP block to our internal format and process
        // For now, use the same conversion logic but with better integration potential
        self.process_single_http_block_legacy(http_block)
    }

    /// Process single HTTP block using legacy method
    /// 
    /// This method converts HTTP block data to the Block struct and uses the same
    /// `process_outputs()` method. For inputs, it extracts spending information from
    /// payment IDs since HTTP API doesn't provide actual input data.
    fn process_single_http_block_legacy(&mut self, http_block: &HttpBlockData) -> Result<(usize, usize), String> {
        // Convert HTTP outputs to LightweightTransactionOutput (same as scanner.rs expects)
        let outputs = self.convert_http_outputs_to_lightweight(&http_block.outputs)?;
        
        // Extract synthetic inputs from payment IDs (HTTP API limitation workaround)
        let synthetic_inputs = self.extract_synthetic_inputs_from_payment_ids(&outputs, http_block.height)?;

        // Create Block using the same constructor as scanner.rs
        let block = Block::new(
            http_block.height,
            http_block.header_hash.clone(),
            http_block.mined_timestamp,
            outputs,
            synthetic_inputs,
        );

        // Use the EXACT same processing methods as scanner.rs
        let found_outputs = block.process_outputs(
            &self.view_key,
            &self.entropy,
            &mut self.wallet_state,
        ).map_err(|e| format!("Failed to process outputs: {}", e))?;

        let spent_outputs = block.process_inputs(&mut self.wallet_state)
            .map_err(|e| format!("Failed to process inputs: {}", e))?;

        Ok((found_outputs, spent_outputs))
    }

    /// Extract synthetic transaction inputs from payment IDs containing sent_output_hashes
    /// 
    /// Since HTTP API doesn't provide input data, we extract spending information from
    /// the payment IDs of outputs we can decrypt. This allows us to detect outbound transactions.
    fn extract_synthetic_inputs_from_payment_ids(
        &self,
        outputs: &[LightweightTransactionOutput],
        block_height: u64,
    ) -> Result<Vec<TransactionInput>, String> {
        use crate::data_structures::{
            encrypted_data::EncryptedData,
            transaction_input::{TransactionInput, LightweightExecutionStack},
            types::{CompressedPublicKey, MicroMinotari},
        };

        let mut synthetic_inputs = Vec::new();
        let mut debug_stats = (0, 0, 0, 0, 0); // (total_outputs, with_encrypted_data, decrypted_successfully, with_payment_ids, with_sent_hashes)


        // Try to decrypt each output to extract payment IDs
        for (output_index, output) in outputs.iter().enumerate() {
            debug_stats.0 += 1; // total_outputs
            
            if output.encrypted_data.as_bytes().is_empty() {
                continue;
            }
            debug_stats.1 += 1; // with_encrypted_data


            // Try to decrypt with our view key to get the payment ID
            if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_data(
                &self.view_key,
                &output.commitment,
                &output.encrypted_data,
            ) {
                debug_stats.2 += 1; // decrypted_successfully
                console::log_1(&format!("  ✅ Regular decryption successful! Value: {} μT {}", value.as_u64(), hex::encode(output.hash())).into());
                
                // Log detailed PaymentID information
                self.log_payment_id_details(&payment_id, block_height, output_index, "regular");
                
                debug_stats.3 += 1; // with_payment_ids
                
                // Extract sent_output_hashes from TransactionInfo payment IDs
                if let Some(sent_hashes) = payment_id.get_sent_hashes() {
                    if !sent_hashes.is_empty() {
                        debug_stats.4 += 1; // with_sent_hashes
                        
                        for (_hash_index, sent_hash) in sent_hashes.iter().enumerate() {
                            let _commitment_hex = hex::encode(sent_hash.as_bytes());
                            console::log_1(&format!("    Hash {}: {}", _hash_index, _commitment_hex).into());
                            
                            // Create a synthetic TransactionInput from the sent output hash
                            let synthetic_input = TransactionInput::new(
                                1, // version
                                0, // features
                                *sent_hash.as_bytes(), // commitment from hash
                                [0u8; 64], // script_signature (not available)
                                CompressedPublicKey::new([0u8; 32]), // sender_offset_public_key (not available)
                                Vec::new(), // covenant (not available)
                                LightweightExecutionStack::new(), // input_data (not available)
                                *sent_hash.as_bytes(), // output_hash
                                0, // output_features (not available)
                                [0u8; 64], // output_metadata_signature (not available)
                                0, // maturity (not available)
                                MicroMinotari::from(0u64), // value (not available)
                            );

                            synthetic_inputs.push(synthetic_input);
                        }
                    } 
                }
            }
            // Also try one-sided decryption if sender offset key is available
            else if !output.sender_offset_public_key.as_bytes().iter().all(|&b| b == 0) {
                    
                if let Ok((_value, _mask, payment_id)) = EncryptedData::decrypt_one_sided_data(
                    &self.view_key,
                    &output.commitment,
                    &output.sender_offset_public_key,
                    &output.encrypted_data,
                ) {
                    debug_stats.2 += 1; // decrypted_successfully
                    
                    // Log detailed PaymentID information
                    self.log_payment_id_details(&payment_id, block_height, output_index, "one-sided");
                    
                    debug_stats.3 += 1; // with_payment_ids
                    
                    // Extract sent_output_hashes from TransactionInfo payment IDs
                    if let Some(sent_hashes) = payment_id.get_sent_hashes() {
                        if !sent_hashes.is_empty() {
                            debug_stats.4 += 1; // with_sent_hashes
                            
                            for (_hash_index, sent_hash) in sent_hashes.iter().enumerate() {
                                let _commitment_hex = hex::encode(sent_hash.as_bytes());
                                
                                // Create a synthetic TransactionInput from the sent output hash
                                let synthetic_input = TransactionInput::new(
                                    1, // version
                                    0, // features
                                    *sent_hash.as_bytes(), // commitment from hash
                                    [0u8; 64], // script_signature (not available)
                                    CompressedPublicKey::new([0u8; 32]), // sender_offset_public_key (not available)
                                    Vec::new(), // covenant (not available)
                                    LightweightExecutionStack::new(), // input_data (not available)
                                    *sent_hash.as_bytes(), // output_hash
                                    0, // output_features (not available)
                                    [0u8; 64], // output_metadata_signature (not available)
                                    0, // maturity (not available)
                                    MicroMinotari::from(0u64), // value (not available)
                                );

                                synthetic_inputs.push(synthetic_input);
                            }
                        } 
                    } 
                } 
            }
        }

        Ok(synthetic_inputs)
    }

    /// Log detailed information about a PaymentID
    fn log_payment_id_details(&self, payment_id: &PaymentId, _block_height: u64, _output_index: usize, decrypt_method: &str) {
        console::log_1(&format!("  💳 PaymentID Details ({})", decrypt_method).into());
        
        // Log the discriminant (variant type)
        let discriminant = std::mem::discriminant(payment_id);
        console::log_1(&format!("    Variant discriminant: {:?}", discriminant).into());
        
        // Log the raw bytes
        let payment_id_bytes = payment_id.to_bytes();
        console::log_1(&format!("    Raw bytes ({} total): {}", payment_id_bytes.len(), hex::encode(&payment_id_bytes)).into());
        
        // Parse first byte for tag if present
        if !payment_id_bytes.is_empty() {
            console::log_1(&format!("    First byte (tag): 0x{:02x} ({})", payment_id_bytes[0], payment_id_bytes[0]).into());
        }
        
        // Log detailed structure based on variant
        match payment_id {
            PaymentId::Empty => {
                console::log_1(&format!("    Type: Empty").into());
            },
            PaymentId::U256(value) => {
                console::log_1(&format!("    Type: U256").into());
                console::log_1(&format!("    Value: {}", value).into());
            },
            PaymentId::Open { user_data, tx_type } => {
                console::log_1(&format!("    Type: Open").into());
                console::log_1(&format!("    TxType: {:?}", tx_type).into());
                console::log_1(&format!("    User data ({} bytes): {}", user_data.len(), hex::encode(user_data)).into());
                if let Ok(utf8_str) = std::str::from_utf8(user_data) {
                    console::log_1(&format!("    User data (UTF-8): \"{}\"", utf8_str).into());
                }
            },
            PaymentId::AddressAndData { 
                sender_address, 
                sender_one_sided, 
                fee, 
                tx_type, 
                user_data 
            } => {
                console::log_1(&format!("    Type: AddressAndData").into());
                console::log_1(&format!("    Sender address: {}", sender_address.to_base58()).into());
                console::log_1(&format!("    Sender one-sided: {}", sender_one_sided).into());
                console::log_1(&format!("    Fee: {} μT", fee.as_u64()).into());
                console::log_1(&format!("    TxType: {:?}", tx_type).into());
                console::log_1(&format!("    User data ({} bytes): {}", user_data.len(), hex::encode(user_data)).into());
                if let Ok(utf8_str) = std::str::from_utf8(user_data) {
                    console::log_1(&format!("    User data (UTF-8): \"{}\"", utf8_str).into());
                }
            },
            PaymentId::TransactionInfo { 
                recipient_address, 
                sender_one_sided, 
                amount, 
                fee, 
                tx_type, 
                sent_output_hashes, 
                user_data 
            } => {
                console::log_1(&format!("    Type: TransactionInfo").into());
                console::log_1(&format!("    Recipient address: {}", recipient_address.to_base58()).into());
                console::log_1(&format!("    Sender one-sided: {}", sender_one_sided).into());
                console::log_1(&format!("    Amount: {} μT", amount.as_u64()).into());
                console::log_1(&format!("    Fee: {} μT", fee.as_u64()).into());
                console::log_1(&format!("    TxType: {:?}", tx_type).into());
                console::log_1(&format!("    User data ({} bytes): {}", user_data.len(), hex::encode(user_data)).into());
                if let Ok(utf8_str) = std::str::from_utf8(user_data) {
                    console::log_1(&format!("    User data (UTF-8): \"{}\"", utf8_str).into());
                }
                console::log_1(&format!("    🎯 SENT OUTPUT HASHES: {} items", sent_output_hashes.len()).into());
                for (i, hash) in sent_output_hashes.iter().enumerate() {
                    console::log_1(&format!("      Hash {}: {}", i, hex::encode(hash.as_bytes())).into());
                }
                
                // Check if this looks like a V1 vs V2 format
                if sent_output_hashes.is_empty() {
                    console::log_1(&format!("    ⚠️ WARNING: TransactionInfo has empty sent_output_hashes (likely V1 format)").into());
                }
            },
            PaymentId::Raw(bytes) => {
                console::log_1(&format!("    Type: Raw").into());
                console::log_1(&format!("    Raw bytes ({} total): {}", bytes.len(), hex::encode(bytes)).into());
            },
        }
        
        // Log the display representation
        console::log_1(&format!("    Display: {}", payment_id).into());
    }

    /// Convert HTTP output data to LightweightTransactionOutput (minimal viable format)
    fn convert_http_outputs_to_lightweight(&self, http_outputs: &[HttpOutputData]) -> Result<Vec<LightweightTransactionOutput>, String> {
        let mut outputs = Vec::new();

        for http_output in http_outputs {
            // Parse commitment
            if http_output.commitment.len() != 32 {
                return Err("Invalid commitment length, expected 32 bytes".to_string());
            }
            let commitment = CompressedCommitment::new(
                http_output.commitment.clone().try_into()
                    .map_err(|_| "Failed to convert commitment")?
            );

            // Parse sender offset public key
            if http_output.sender_offset_public_key.len() != 32 {
                return Err("Invalid sender offset public key length, expected 32 bytes".to_string());
            }
            let sender_offset_public_key = CompressedPublicKey::new(
                http_output.sender_offset_public_key.clone().try_into()
                    .map_err(|_| "Failed to convert sender offset public key")?
            );

            // Parse encrypted data
            let encrypted_data = EncryptedData::from_bytes(&http_output.encrypted_data)
                .map_err(|e| format!("Invalid encrypted data: {}", e))?;

            // Create LightweightTransactionOutput with minimal viable data
            // HTTP API provides limited data, so we use defaults for missing fields
            let output = LightweightTransactionOutput::new_current_version(
                LightweightOutputFeatures::default(), // Default features (will be 0/Standard)
                commitment,
                None, // Range proof not provided in HTTP API
                LightweightScript::default(), // Script not provided, use empty/default
                sender_offset_public_key,
                LightweightSignature::default(), // Metadata signature not provided, use default
                LightweightCovenant::default(), // Covenant not provided, use default
                encrypted_data,
                MicroMinotari::from(0u64), // Minimum value promise not provided, use 0
            );

            outputs.push(output);
        }

        Ok(outputs)
    }

    /// Process block data (LEGACY METHOD for backward compatibility)
    pub fn process_block(&mut self, block_data: &BlockData) -> ScanResult {
        // Convert legacy format to internal format
        let outputs = match self.convert_legacy_outputs(block_data) {
            Ok(outputs) => outputs,
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

        let inputs = match self.convert_legacy_inputs(block_data) {
            Ok(inputs) => inputs,
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

        let block_hash = match hex::decode(&block_data.hash) {
            Ok(hash) => hash,
            Err(e) => {
                return ScanResult {
                    total_outputs: 0,
                    total_spent: 0,
                    total_value: 0,
                    current_balance: 0,
                    blocks_processed: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(format!("Invalid block hash: {}", e)),
                };
            }
        };

        // Create Block using the same constructor as scanner.rs
        let block = Block::new(
            block_data.height,
            block_hash,
            block_data.timestamp,
            outputs,
            inputs,
        );

        // Use the exact same processing methods as scanner.rs
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

    /// Process single block and return only block-specific results (LEGACY METHOD)
    pub fn process_single_block(&mut self, block_data: &BlockData) -> BlockScanResult {
        // Get wallet state before processing
        let (prev_total_received, prev_total_spent, _prev_balance, _prev_unspent_count, _prev_spent_count) = self.wallet_state.get_summary();
        let prev_transaction_count = self.wallet_state.transactions.len();

        // Convert legacy format to internal format
        let outputs = match self.convert_legacy_outputs(block_data) {
            Ok(outputs) => outputs,
            Err(e) => {
                return BlockScanResult {
                    block_height: block_data.height,
                    block_hash: block_data.hash.clone(),
                    outputs_found: 0,
                    inputs_spent: 0,
                    value_found: 0,
                    value_spent: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(e),
                };
            }
        };

        let inputs = match self.convert_legacy_inputs(block_data) {
            Ok(inputs) => inputs,
            Err(e) => {
                return BlockScanResult {
                    block_height: block_data.height,
                    block_hash: block_data.hash.clone(),
                    outputs_found: 0,
                    inputs_spent: 0,
                    value_found: 0,
                    value_spent: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(e),
                };
            }
        };

        let block_hash = match hex::decode(&block_data.hash) {
            Ok(hash) => hash,
            Err(e) => {
                return BlockScanResult {
                    block_height: block_data.height,
                    block_hash: block_data.hash.clone(),
                    outputs_found: 0,
                    inputs_spent: 0,
                    value_found: 0,
                    value_spent: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(format!("Invalid block hash: {}", e)),
                };
            }
        };

        // Create Block using the same constructor as scanner.rs
        let block = Block::new(
            block_data.height,
            block_hash.clone(),
            block_data.timestamp,
            outputs,
            inputs,
        );

        // Use the exact same processing methods as scanner.rs
        let found_outputs = match block.process_outputs(&self.view_key, &self.entropy, &mut self.wallet_state) {
            Ok(count) => count,
            Err(e) => {
                return BlockScanResult {
                    block_height: block_data.height,
                    block_hash: block_data.hash.clone(),
                    outputs_found: 0,
                    inputs_spent: 0,
                    value_found: 0,
                    value_spent: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(format!("Failed to process outputs: {}", e)),
                };
            }
        };

        let spent_outputs = match block.process_inputs(&mut self.wallet_state) {
            Ok(count) => count,
            Err(e) => {
                return BlockScanResult {
                    block_height: block_data.height,
                    block_hash: block_data.hash.clone(),
                    outputs_found: 0,
                    inputs_spent: 0,
                    value_found: 0,
                    value_spent: 0,
                    transactions: Vec::new(),
                    success: false,
                    error: Some(format!("Failed to process inputs: {}", e)),
                };
            }
        };

        // Get wallet state after processing
        let (new_total_received, new_total_spent, _new_balance, _new_unspent_count, _new_spent_count) = self.wallet_state.get_summary();

        // Calculate block-specific values
        let value_found = new_total_received - prev_total_received;
        let value_spent = new_total_spent - prev_total_spent;

        // Get transactions added in this block
        let block_transactions: Vec<TransactionSummary> = self.wallet_state.transactions
            .iter()
            .skip(prev_transaction_count)
            .filter(|tx| tx.block_height == block_data.height)
            .map(|tx| {
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

        BlockScanResult {
            block_height: block_data.height,
            block_hash: block_data.hash.clone(),
            outputs_found: found_outputs as u64,
            inputs_spent: spent_outputs as u64,
            value_found,
            value_spent,
            transactions: block_transactions,
            success: true,
            error: None,
        }
    }

    /// Convert legacy OutputData to LightweightTransactionOutput
    fn convert_legacy_outputs(&self, block_data: &BlockData) -> Result<Vec<LightweightTransactionOutput>, String> {
        let mut outputs = Vec::new();
        for output_data in &block_data.outputs {
            let output = self.convert_legacy_output_data(output_data)?;
            outputs.push(output);
        }
        Ok(outputs)
    }

    /// Convert legacy InputData to TransactionInput
    fn convert_legacy_inputs(&self, block_data: &BlockData) -> Result<Vec<TransactionInput>, String> {
        let mut inputs = Vec::new();
        for input_data in &block_data.inputs {
            let input = self.convert_legacy_input_data(input_data)?;
            inputs.push(input);
        }
        Ok(inputs)
    }

    /// Convert OutputData to LightweightTransactionOutput (LEGACY)
    fn convert_legacy_output_data(&self, output_data: &OutputData) -> Result<LightweightTransactionOutput, String> {
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

    /// Convert InputData to TransactionInput (LEGACY)
    fn convert_legacy_input_data(&self, input_data: &InputData) -> Result<TransactionInput, String> {
        use crate::data_structures::{
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

/// Create a scanner from view key or seed phrase (WASM export)
/// Automatically detects the input type by trying view key first, then seed phrase
#[wasm_bindgen]
pub fn create_wasm_scanner(data: &str) -> Result<WasmScanner, JsValue> {
    WasmScanner::from_str(data).map_err(|e| JsValue::from_str(&e))
}

/// Initialize HTTP scanner (WASM export) - Returns a Promise
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn initialize_http_scanner(scanner: &mut WasmScanner, base_url: &str) -> Result<(), JsValue> {
    scanner.initialize_http_scanner(base_url).await
        .map_err(|e| JsValue::from_str(&e))
}

/// Process HTTP block response with async support (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen] 
pub async fn process_http_blocks_async(scanner: &mut WasmScanner, http_response_json: &str, base_url: Option<String>) -> Result<String, JsValue> {
    let result = scanner.process_http_blocks_async(http_response_json, base_url.as_deref()).await;
    
    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Process HTTP block response (WASM export) - LEGACY METHOD for backward compatibility
#[wasm_bindgen]
pub fn process_http_blocks(scanner: &mut WasmScanner, http_response_json: &str) -> Result<String, JsValue> {
    let result = scanner.process_http_blocks(http_response_json);
    
    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Scan block data (WASM export) - LEGACY METHOD for backward compatibility
#[wasm_bindgen]
pub fn scan_block_data(scanner: &mut WasmScanner, block_data_json: &str) -> Result<String, JsValue> {
    let block_data: BlockData = serde_json::from_str(block_data_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse block data: {}", e)))?;

    let result = scanner.process_block(&block_data);
    
    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Scan single block and return only block-specific data (WASM export) - LEGACY METHOD  
#[wasm_bindgen]
pub fn scan_single_block(scanner: &mut WasmScanner, block_data_json: &str) -> Result<String, JsValue> {
    let block_data: BlockData = serde_json::from_str(block_data_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse block data: {}", e)))?;

    let result = scanner.process_single_block(&block_data);
    
    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Get cumulative scanner statistics (WASM export)
#[wasm_bindgen]
pub fn get_scanner_stats(scanner: &WasmScanner) -> Result<String, JsValue> {
    let (total_received, _total_spent, balance, unspent_count, spent_count) = scanner.wallet_state.get_summary();
    
    let stats = serde_json::json!({
        "total_outputs": unspent_count,
        "total_spent": spent_count,
        "total_value": total_received,
        "current_balance": balance,
        "total_transactions": scanner.wallet_state.transactions.len(),
    });
    
    serde_json::to_string(&stats)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize stats: {}", e)))
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

/// Get tip info from HTTP scanner (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn get_tip_info(scanner: &mut WasmScanner) -> Result<String, JsValue> {
    if let Some(ref mut http_scanner) = scanner.http_scanner {
        let tip_info = http_scanner.get_tip_info().await
            .map_err(|e| JsValue::from_str(&format!("Failed to get tip info: {}", e)))?;
        
        serde_json::to_string(&tip_info)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize tip info: {}", e)))
    } else {
        Err(JsValue::from_str("HTTP scanner not initialized"))
    }
}
/// Fetch specific blocks by height using HTTP scanner (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn fetch_blocks_by_heights(scanner: &mut WasmScanner, heights_json: &str) -> Result<String, JsValue> {
    if let Some(ref mut http_scanner) = scanner.http_scanner {
        let heights: Vec<u64> = serde_json::from_str(heights_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse heights: {}", e)))?;
        
        let blocks = http_scanner.get_blocks_by_heights(heights).await
            .map_err(|e| JsValue::from_str(&format!("Failed to fetch blocks: {}", e)))?;
        
        // Convert to WASM-serializable format
        let wasm_blocks: Vec<WasmBlockInfo> = blocks.into_iter().map(|block| block.into()).collect();
        
        serde_json::to_string(&wasm_blocks)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize blocks: {}", e)))
    } else {
        Err(JsValue::from_str("HTTP scanner not initialized"))
    }
}

/// Search for UTXOs by commitment using HTTP scanner (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub async fn search_utxos(scanner: &mut WasmScanner, commitments_json: &str) -> Result<String, JsValue> {
    if let Some(ref mut http_scanner) = scanner.http_scanner {
        let commitments: Vec<Vec<u8>> = serde_json::from_str(commitments_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse commitments: {}", e)))?;
        
        let results = http_scanner.search_utxos(commitments).await
            .map_err(|e| JsValue::from_str(&format!("Failed to search UTXOs: {}", e)))?;
        
        serde_json::to_string(&results)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize search results: {}", e)))
    } else {
        Err(JsValue::from_str("HTTP scanner not initialized"))
    }
}

/// Create scan config for HTTP scanner (WASM export)
#[cfg(feature = "http")]
#[wasm_bindgen]
pub fn create_scan_config(scanner: &WasmScanner, start_height: u64, end_height: Option<u64>) -> Result<String, JsValue> {
    let scan_config = ScanConfig {
        start_height,
        end_height,
        batch_size: 100,
        request_timeout: std::time::Duration::from_secs(30),
        extraction_config: ExtractionConfig::with_private_key(scanner.view_key.clone()),
    };
    
    serde_json::to_string(&scan_config)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize scan config: {}", e)))
}

/// Get version information (WASM export)
#[wasm_bindgen]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
