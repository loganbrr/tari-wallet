//! Block processing functionality for wallet scanning
//!
//! This module provides a `Block` struct that encapsulates all the logic for:
//! - Processing transaction outputs to discover wallet outputs
//! - Processing transaction inputs to detect spending
//! - Multiple decryption methods (regular, one-sided, range proof rewinding)
//! - Coinbase output handling with ownership verification
//! - **Parallel processing for performance optimization**

use crate::{
    data_structures::{
        types::PrivateKey,
        encrypted_data::EncryptedData,
        payment_id::PaymentId,
        transaction::{TransactionStatus, TransactionDirection},
        wallet_transaction::WalletState,
        transaction_output::LightweightTransactionOutput,
        transaction_input::TransactionInput,
        wallet_output::LightweightOutputType,
    },
    errors::LightweightWalletResult,
};

#[cfg(feature = "grpc")]
use crate::scanning::BlockInfo;

// Add rayon for parallel processing
#[cfg(feature = "grpc")]
use rayon::prelude::*;

/// A block with wallet-focused processing capabilities
/// 
/// This struct wraps a `BlockInfo` and provides methods to extract wallet outputs
/// and detect spending using various decryption techniques.
pub struct Block {
    /// Block height
    pub height: u64,
    /// Block hash
    pub hash: Vec<u8>,
    /// Block timestamp
    pub timestamp: u64,
    /// Transaction outputs in this block
    pub outputs: Vec<LightweightTransactionOutput>,
    /// Transaction inputs in this block  
    pub inputs: Vec<TransactionInput>,
}

/// Result of processing a single output
#[derive(Debug, Clone)]
struct OutputProcessingResult {
    output_index: usize,
    found: bool,
    value: u64,
    payment_id: PaymentId,
    transaction_status: TransactionStatus,
    is_mature: bool,
}

impl Block {
    /// Create a new Block from BlockInfo (only available with grpc feature)
    #[cfg(feature = "grpc")]
    pub fn from_block_info(block_info: BlockInfo) -> Self {
        Self {
            height: block_info.height,
            hash: block_info.hash,
            timestamp: block_info.timestamp,
            outputs: block_info.outputs,
            inputs: block_info.inputs,
        }
    }

    /// Create a new Block with specified data
    pub fn new(
        height: u64,
        hash: Vec<u8>,
        timestamp: u64,
        outputs: Vec<LightweightTransactionOutput>,
        inputs: Vec<TransactionInput>,
    ) -> Self {
        Self {
            height,
            hash,
            timestamp,
            outputs,
            inputs,
        }
    }

    /// Process all outputs in this block to discover wallet outputs - OPTIMIZED VERSION
    /// 
    /// This method uses parallel processing and optimized decryption attempts to maximize performance
    pub fn process_outputs(
        &self,
        view_key: &PrivateKey,
        _entropy: &[u8; 16],
        wallet_state: &mut WalletState,
    ) -> LightweightWalletResult<usize> {
        if self.outputs.is_empty() {
            return Ok(0);
        }

        // Process outputs in parallel when feature is enabled
        #[cfg(feature = "grpc")]
        let results: Vec<OutputProcessingResult> = self.outputs
            .par_iter()
            .enumerate()
            .filter_map(|(output_index, output)| {
                self.process_single_output_parallel(output_index, output, view_key)
            })
            .collect();

        // Fallback to sequential processing when parallel feature not enabled
        #[cfg(not(feature = "grpc"))]
        let results: Vec<OutputProcessingResult> = self.outputs
            .iter()
            .enumerate()
            .filter_map(|(output_index, output)| {
                self.process_single_output_parallel(output_index, output, view_key)
            })
            .collect();

        // Add all found outputs to wallet state
        let found_count = results.len();
        for result in results {
            wallet_state.add_received_output(
                self.height,
                result.output_index,
                self.outputs[result.output_index].commitment.clone(),
                Some(self.outputs[result.output_index].hash().to_vec()), // Include calculated output hash
                result.value,
                result.payment_id,
                result.transaction_status,
                TransactionDirection::Inbound,
                result.is_mature,
            );
        }

        Ok(found_count)
    }

    /// Process a single output with optimized decryption strategy
    fn process_single_output_parallel(
        &self,
        output_index: usize,
        output: &LightweightTransactionOutput,
        view_key: &PrivateKey,
    ) -> Option<OutputProcessingResult> {
        // Early exit for outputs with no encrypted data (except coinbase)
        let has_encrypted_data = !output.encrypted_data.as_bytes().is_empty();
        let is_coinbase = matches!(output.features.output_type, LightweightOutputType::Coinbase);
        
        if !has_encrypted_data && !is_coinbase {
            return None;
        }

        // Handle coinbase outputs
        if is_coinbase {
            if let Some(result) = self.try_coinbase_output_optimized(output_index, output, view_key) {
                return Some(result);
            }
        }

        // Skip further processing if no encrypted data
        if !has_encrypted_data {
            return None;
        }

        // Try regular decryption first (most common case)
        if let Some(result) = self.try_regular_decryption_optimized(output_index, output, view_key) {
            return Some(result);
        }

        // Try one-sided decryption only if sender offset key is present
        if !output.sender_offset_public_key.as_bytes().is_empty() {
            if let Some(result) = self.try_one_sided_decryption_optimized(output_index, output, view_key) {
                return Some(result);
            }
        }

        None
    }

    /// Optimized coinbase output processing
    fn try_coinbase_output_optimized(
        &self,
        output_index: usize,
        output: &LightweightTransactionOutput,
        view_key: &PrivateKey,
    ) -> Option<OutputProcessingResult> {
        let coinbase_value = output.minimum_value_promise.as_u64();
        if coinbase_value == 0 {
            return None;
        }

        // For coinbase outputs, verify ownership through encrypted data decryption
        let mut is_ours = false;

        if !output.encrypted_data.as_bytes().is_empty() {
            // Try regular decryption for ownership verification first (faster)
            if EncryptedData::decrypt_data(view_key, &output.commitment, &output.encrypted_data).is_ok() {
                is_ours = true;
            }
            // Only try one-sided decryption if regular failed and sender offset key exists
            else if !output.sender_offset_public_key.as_bytes().is_empty() {
                if EncryptedData::decrypt_one_sided_data(
                    view_key, 
                    &output.commitment, 
                    &output.sender_offset_public_key, 
                    &output.encrypted_data
                ).is_ok() {
                    is_ours = true;
                }
            }
        }

        if is_ours {
            // Check if coinbase is mature (can be spent)
            let is_mature = self.height >= output.features.maturity;

            return Some(OutputProcessingResult {
                output_index,
                found: true,
                value: coinbase_value,
                payment_id: PaymentId::Empty, // Coinbase outputs typically have no payment ID
                transaction_status: if is_mature { 
                    TransactionStatus::CoinbaseConfirmed 
                } else { 
                    TransactionStatus::CoinbaseUnconfirmed 
                },
                is_mature,
            });
        }

        None
    }

    /// Optimized regular encrypted data decryption
    fn try_regular_decryption_optimized(
        &self,
        output_index: usize,
        output: &LightweightTransactionOutput,
        view_key: &PrivateKey,
    ) -> Option<OutputProcessingResult> {
        if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_data(
            view_key, 
            &output.commitment, 
            &output.encrypted_data
        ) {
            return Some(OutputProcessingResult {
                output_index,
                found: true,
                value: value.as_u64(),
                payment_id,
                transaction_status: TransactionStatus::MinedConfirmed,
                is_mature: true, // Regular payments are always mature
            });
        }
        None
    }

    /// Optimized one-sided encrypted data decryption
    fn try_one_sided_decryption_optimized(
        &self,
        output_index: usize,
        output: &LightweightTransactionOutput,
        view_key: &PrivateKey,
    ) -> Option<OutputProcessingResult> {
        if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_one_sided_data(
            view_key, 
            &output.commitment, 
            &output.sender_offset_public_key, 
            &output.encrypted_data
        ) {
            return Some(OutputProcessingResult {
                output_index,
                found: true,
                value: value.as_u64(),
                payment_id,
                transaction_status: TransactionStatus::OneSidedConfirmed,
                is_mature: true, // One-sided payments are always mature
            });
        }
        None
    }

    /// Process all inputs in this block to detect spending of wallet outputs
    pub fn process_inputs(&self, wallet_state: &mut WalletState) -> LightweightWalletResult<usize> {
        let mut spent_outputs = 0;

        for (input_index, input) in self.inputs.iter().enumerate() {
            let mut found_spent = false;

            // Try to match by output hash first (for HTTP API)
            // Only attempt if output_hash is not all zeros (HTTP API provides real output hashes)
            if !input.output_hash.iter().all(|&b| b == 0) {
                if wallet_state.mark_output_spent_by_hash(&input.output_hash, self.height, input_index) {
                    spent_outputs += 1;
                    found_spent = true;
                }
            }

            // If output hash matching failed or output_hash is all zeros, try commitment matching (for GRPC API)
            if !found_spent && !input.commitment.iter().all(|&b| b == 0) {
                use crate::data_structures::types::CompressedCommitment;
                let commitment = CompressedCommitment::new(input.commitment);
                if wallet_state.mark_output_spent(&commitment, self.height, input_index) {
                    spent_outputs += 1;
                }
            }
        }

        Ok(spent_outputs)
    }

    /// Scan this block for all wallet activity (outputs and inputs)
    /// 
    /// This is a convenience method that calls both `process_outputs` and `process_inputs`
    pub fn scan_for_wallet_activity(
        &self,
        view_key: &PrivateKey,
        entropy: &[u8; 16],
        wallet_state: &mut WalletState,
    ) -> LightweightWalletResult<(usize, usize)> {
        let found_outputs = self.process_outputs(view_key, entropy, wallet_state)?;
        let spent_outputs = self.process_inputs(wallet_state)?;
        Ok((found_outputs, spent_outputs))
    }

    /// Try to process a coinbase output with ownership verification
    fn try_coinbase_output(
        &self,
        output: &LightweightTransactionOutput,
        output_index: usize,
        view_key: &PrivateKey,
        wallet_state: &mut WalletState,
    ) -> LightweightWalletResult<bool> {
        let coinbase_value = output.minimum_value_promise.as_u64();
        if coinbase_value == 0 {
            return Ok(false);
        }

        // For coinbase outputs, verify ownership through encrypted data decryption
        let mut is_ours = false;

        if !output.encrypted_data.as_bytes().is_empty() {
            // Try regular decryption for ownership verification
            if EncryptedData::decrypt_data(view_key, &output.commitment, &output.encrypted_data).is_ok() {
                is_ours = true;
            }
            // Try one-sided decryption for ownership verification
            else if !output.sender_offset_public_key.as_bytes().is_empty() {
                if EncryptedData::decrypt_one_sided_data(
                    view_key, 
                    &output.commitment, 
                    &output.sender_offset_public_key, 
                    &output.encrypted_data
                ).is_ok() {
                    is_ours = true;
                }
            }
        }

        // Only add to wallet if we can prove ownership
        if is_ours {
            // Check if coinbase is mature (can be spent)
            let is_mature = self.height >= output.features.maturity;

            wallet_state.add_received_output(
                self.height,
                output_index,
                output.commitment.clone(),
                Some(output.hash().to_vec()), // Include calculated output hash
                coinbase_value,
                PaymentId::Empty, // Coinbase outputs typically have no payment ID
                if is_mature { 
                    TransactionStatus::CoinbaseConfirmed 
                } else { 
                    TransactionStatus::CoinbaseUnconfirmed 
                },
                TransactionDirection::Inbound,
                is_mature,
            );
            return Ok(true);
        }

        Ok(false)
    }

    /// Try regular encrypted data decryption
    fn try_regular_decryption(
        &self,
        output: &LightweightTransactionOutput,
        output_index: usize,
        view_key: &PrivateKey,
        wallet_state: &mut WalletState,
    ) -> LightweightWalletResult<bool> {
        if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_data(
            view_key, 
            &output.commitment, 
            &output.encrypted_data
        ) {
            let value_u64 = value.as_u64();
            wallet_state.add_received_output(
                self.height,
                output_index,
                output.commitment.clone(),
                Some(output.hash().to_vec()), // Include calculated output hash
                value_u64,
                payment_id,
                TransactionStatus::MinedConfirmed,
                TransactionDirection::Inbound,
                true, // Regular payments are always mature
            );
            return Ok(true);
        }
        Ok(false)
    }

    /// Try one-sided encrypted data decryption
    fn try_one_sided_decryption(
        &self,
        output: &LightweightTransactionOutput,
        output_index: usize,
        view_key: &PrivateKey,
        wallet_state: &mut WalletState,
    ) -> LightweightWalletResult<bool> {
        if !output.sender_offset_public_key.as_bytes().is_empty() {
            if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_one_sided_data(
                view_key, 
                &output.commitment, 
                &output.sender_offset_public_key, 
                &output.encrypted_data
            ) {
                let value_u64 = value.as_u64();
                wallet_state.add_received_output(
                    self.height,
                    output_index,
                    output.commitment.clone(),
                    Some(output.hash().to_vec()), // Include calculated output hash
                    value_u64,
                    payment_id,
                    TransactionStatus::OneSidedConfirmed,
                    TransactionDirection::Inbound,
                    true, // One-sided payments are always mature
                );
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Get the number of outputs in this block
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Get the number of inputs in this block
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Get block summary information
    pub fn summary(&self) -> BlockSummary {
        BlockSummary {
            height: self.height,
            hash: self.hash.clone(),
            timestamp: self.timestamp,
            output_count: self.outputs.len(),
            input_count: self.inputs.len(),
        }
    }
}

/// Summary information about a block
#[derive(Debug, Clone)]
pub struct BlockSummary {
    /// Block height
    pub height: u64,
    /// Block hash
    pub hash: Vec<u8>,
    /// Block timestamp
    pub timestamp: u64,
    /// Number of outputs in the block
    pub output_count: usize,
    /// Number of inputs in the block
    pub input_count: usize,
}

impl std::fmt::Display for BlockSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Block {} (outputs: {}, inputs: {})",
            self.height, self.output_count, self.input_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_structures::{
        types::MicroMinotari,
        wallet_output::{LightweightOutputFeatures, LightweightRangeProof},
        transaction_kernel::TransactionKernel,
    };

    fn create_test_block() -> Block {
        Block::new(
            1000,
            vec![1, 2, 3, 4],
            1234567890,
            vec![],
            vec![],
        )
    }

    #[test]
    fn test_block_creation() {
        let block = create_test_block();
        assert_eq!(block.height, 1000);
        assert_eq!(block.hash, vec![1, 2, 3, 4]);
        assert_eq!(block.timestamp, 1234567890);
        assert_eq!(block.output_count(), 0);
        assert_eq!(block.input_count(), 0);
    }

    #[test]
    fn test_block_summary() {
        let block = create_test_block();
        let summary = block.summary();
        assert_eq!(summary.height, 1000);
        assert_eq!(summary.output_count, 0);
        assert_eq!(summary.input_count, 0);
    }

    #[test]
    #[cfg(feature = "grpc")]
    fn test_block_from_block_info() {
        let block_info = BlockInfo {
            height: 1000,
            hash: vec![1, 2, 3, 4],
            timestamp: 1234567890,
            outputs: vec![],
            inputs: vec![],
            kernels: vec![],
        };
        
        let block = Block::from_block_info(block_info);
        assert_eq!(block.height, 1000);
        assert_eq!(block.hash, vec![1, 2, 3, 4]);
        assert_eq!(block.timestamp, 1234567890);
    }

    #[test]
    fn test_process_inputs_http_and_grpc_compatibility() {
        use crate::data_structures::{
            transaction_input::TransactionInput,
            types::{CompressedCommitment, CompressedPublicKey, MicroMinotari},
            wallet_transaction::WalletState,
            payment_id::PaymentId,
            transaction::{TransactionStatus, TransactionDirection},
        };

        let mut wallet_state = WalletState::new();
        let commitment = CompressedCommitment::new([1u8; 32]);
        let output_hash = [2u8; 32];

        // Add a received output to wallet state (using both commitment and output hash)
        wallet_state.add_received_output(
            100,
            0,
            commitment.clone(),
            Some(output_hash.to_vec()),
            1000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );

        // Test 1: HTTP-style input (has output hash, zero commitment)
        let http_input = TransactionInput::new(
            1,
            0,
            [0u8; 32], // Zero commitment (HTTP doesn't provide this)
            [0u8; 64],
            CompressedPublicKey::default(),
            Vec::new(),
            crate::data_structures::transaction_input::LightweightExecutionStack::new(),
            output_hash, // Valid output hash from HTTP API
            0,
            [0u8; 64],
            0,
            MicroMinotari::new(0),
        );

        let block_http = Block::new(
            200,
            vec![1, 2, 3],
            123456789,
            vec![],
            vec![http_input],
        );

        // Should find the spent output using output hash matching
        let spent_count = block_http.process_inputs(&mut wallet_state).unwrap();
        assert_eq!(spent_count, 1);
        let (_, _, _, _, spent_count_after) = wallet_state.get_summary();
        assert_eq!(spent_count_after, 1);

        // Reset wallet state for next test
        let mut wallet_state = WalletState::new();
        wallet_state.add_received_output(
            100,
            0,
            commitment.clone(),
            Some(output_hash.to_vec()),
            1000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );

        // Test 2: GRPC-style input (has commitment, may have output hash too)
        let grpc_input = TransactionInput::new(
            1,
            0,
            *commitment.as_bytes(), // Valid commitment from GRPC (copy the array, not convert reference)
            [0u8; 64],
            CompressedPublicKey::default(),
            Vec::new(),
            crate::data_structures::transaction_input::LightweightExecutionStack::new(),
            [0u8; 32], // Zero output hash (or could be valid, but we test commitment fallback)
            0,
            [0u8; 64],
            0,
            MicroMinotari::new(0),
        );

        let block_grpc = Block::new(
            200,
            vec![1, 2, 3],
            123456789,
            vec![],
            vec![grpc_input],
        );

        // Should find the spent output using commitment matching
        let spent_count = block_grpc.process_inputs(&mut wallet_state).unwrap();
        assert_eq!(spent_count, 1);
        let (_, _, _, _, spent_count_after) = wallet_state.get_summary();
        assert_eq!(spent_count_after, 1);

        // Test 3: GRPC-style input with both valid commitment and output hash
        let mut wallet_state = WalletState::new();
        wallet_state.add_received_output(
            100,
            0,
            commitment.clone(),
            Some(output_hash.to_vec()),
            1000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );

        let grpc_input_both = TransactionInput::new(
            1,
            0,
            *commitment.as_bytes(), // Valid commitment from GRPC (copy the array, not convert reference)
            [0u8; 64],
            CompressedPublicKey::default(),
            Vec::new(),
            crate::data_structures::transaction_input::LightweightExecutionStack::new(),
            output_hash, // Also has valid output hash
            0,
            [0u8; 64],
            0,
            MicroMinotari::new(0),
        );

        let block_grpc_both = Block::new(
            200,
            vec![1, 2, 3],
            123456789,
            vec![],
            vec![grpc_input_both],
        );

        // Should find the spent output using output hash matching (preferred method)
        let spent_count = block_grpc_both.process_inputs(&mut wallet_state).unwrap();
        assert_eq!(spent_count, 1);
        let (_, _, _, _, spent_count_after) = wallet_state.get_summary();
        assert_eq!(spent_count_after, 1);
    }
} 