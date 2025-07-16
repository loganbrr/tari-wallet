//! Tests for storage implementations
//! 
//! This module contains tests for the storage trait and its implementations,
//! ensuring data integrity and proper functionality.

#[cfg(feature = "storage")]
#[cfg(test)]
mod storage_tests {
    use super::super::*;
    use crate::data_structures::{
        wallet_transaction::WalletTransaction,
        types::CompressedCommitment,
        transaction::{TransactionStatus, TransactionDirection},
        payment_id::PaymentId,
    };

    #[tokio::test]
    async fn test_sqlite_storage_initialization() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();
        
        // Test that we can get stats from empty storage
        let stats = storage.get_statistics().await.unwrap();
        assert_eq!(stats.total_transactions, 0);
        assert_eq!(stats.current_balance, 0);
        assert_eq!(stats.highest_block, None);
        assert_eq!(stats.lowest_block, None);
    }

    #[tokio::test]
    async fn test_save_and_retrieve_transaction() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        let commitment = CompressedCommitment::new([1u8; 32]);
        let transaction = WalletTransaction::new(
            12345,
            Some(0),
            None,
            commitment.clone(),
            1000000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );

        // Save transaction
        storage.save_transaction(&transaction).await.unwrap();

        // Retrieve by commitment
        let retrieved = storage.get_transaction_by_commitment(&commitment).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved_tx = retrieved.unwrap();
        assert_eq!(retrieved_tx.block_height, 12345);
        assert_eq!(retrieved_tx.value, 1000000);
        assert_eq!(retrieved_tx.commitment, commitment);

        // Test existence check
        assert!(storage.has_commitment(&commitment).await.unwrap());
    }

    #[tokio::test]
    async fn test_batch_save_transactions() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        let transactions = vec![
            WalletTransaction::new(
                100, Some(0), None, CompressedCommitment::new([1u8; 32]),
                1000000, PaymentId::Empty,
                TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
            ),
            WalletTransaction::new(
                200, Some(1), None, CompressedCommitment::new([2u8; 32]),
                2000000, PaymentId::Empty,
                TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
            ),
            WalletTransaction::new(
                300, None, Some(0), CompressedCommitment::new([1u8; 32]),
                1000000, PaymentId::Empty,
                TransactionStatus::MinedConfirmed, TransactionDirection::Outbound, true,
            ),
        ];

        storage.save_transactions(&transactions).await.unwrap();

        let all_transactions = storage.get_transactions(None).await.unwrap();
        assert_eq!(all_transactions.len(), 3);

        let stats = storage.get_statistics().await.unwrap();
        assert_eq!(stats.total_transactions, 3);
        assert_eq!(stats.inbound_count, 2);
        assert_eq!(stats.outbound_count, 1);
    }

    #[tokio::test]
    async fn test_mark_transaction_spent() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        let commitment = CompressedCommitment::new([1u8; 32]);
        let transaction = WalletTransaction::new(
            100, Some(0), None, commitment.clone(),
            1000000, PaymentId::Empty,
            TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
        );

        storage.save_transaction(&transaction).await.unwrap();

        // Mark as spent
        let marked = storage.mark_transaction_spent(&commitment, 200, 5).await.unwrap();
        assert!(marked);

        // Retrieve and verify spent status
        let updated_tx = storage.get_transaction_by_commitment(&commitment).await.unwrap().unwrap();
        assert!(updated_tx.is_spent);
        assert_eq!(updated_tx.spent_in_block, Some(200));
        assert_eq!(updated_tx.spent_in_input, Some(5));

        // Try to mark again (should return false since already spent)
        let marked_again = storage.mark_transaction_spent(&commitment, 300, 10).await.unwrap();
        assert!(!marked_again);
    }

    #[tokio::test]
    async fn test_filtered_queries() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        // Add test transactions
        let transactions = vec![
            WalletTransaction::new(
                100, Some(0), None, CompressedCommitment::new([1u8; 32]),
                1000000, PaymentId::Empty,
                TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
            ),
            WalletTransaction::new(
                200, Some(1), None, CompressedCommitment::new([2u8; 32]),
                2000000, PaymentId::Empty,
                TransactionStatus::CoinbaseConfirmed, TransactionDirection::Inbound, true,
            ),
            WalletTransaction::new(
                300, None, Some(0), CompressedCommitment::new([1u8; 32]),
                1000000, PaymentId::Empty,
                TransactionStatus::MinedConfirmed, TransactionDirection::Outbound, true,
            ),
        ];

        storage.save_transactions(&transactions).await.unwrap();

        // Test filter by direction
        let inbound_filter = TransactionFilter::new().with_direction(TransactionDirection::Inbound);
        let inbound_txs = storage.get_transactions(Some(inbound_filter)).await.unwrap();
        assert_eq!(inbound_txs.len(), 2);

        // Test filter by block range
        let block_filter = TransactionFilter::new().with_block_range(150, 250);
        let block_txs = storage.get_transactions(Some(block_filter)).await.unwrap();
        assert_eq!(block_txs.len(), 1);
        assert_eq!(block_txs[0].block_height, 200);

        // Test filter by status
        let coinbase_filter = TransactionFilter::new().with_status(TransactionStatus::CoinbaseConfirmed);
        let coinbase_txs = storage.get_transactions(Some(coinbase_filter)).await.unwrap();
        assert_eq!(coinbase_txs.len(), 1);
        assert_eq!(coinbase_txs[0].transaction_status, TransactionStatus::CoinbaseConfirmed);

        // Test limit
        let limited_filter = TransactionFilter::new().with_limit(2);
        let limited_txs = storage.get_transactions(Some(limited_filter)).await.unwrap();
        assert_eq!(limited_txs.len(), 2);
    }

    #[tokio::test]
    async fn test_wallet_state_reconstruction() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        let commitment1 = CompressedCommitment::new([1u8; 32]);
        let commitment2 = CompressedCommitment::new([2u8; 32]);

        // Add inbound transactions
        let inbound_tx1 = WalletTransaction::new(
            100, Some(0), None, commitment1.clone(),
            1000000, PaymentId::Empty,
            TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
        );
        let inbound_tx2 = WalletTransaction::new(
            200, Some(1), None, commitment2.clone(),
            2000000, PaymentId::Empty,
            TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
        );

        storage.save_transaction(&inbound_tx1).await.unwrap();
        storage.save_transaction(&inbound_tx2).await.unwrap();

        // Mark one as spent
        storage.mark_transaction_spent(&commitment1, 300, 0).await.unwrap();

        // Load wallet state
        let wallet_state = storage.load_wallet_state().await.unwrap();
        
        // Verify the state
        let (total_received, total_spent, balance, unspent_count, spent_count) = wallet_state.get_summary();
        assert_eq!(total_received, 3000000); // 1M + 2M
        assert_eq!(total_spent, 1000000);    // 1M spent
        assert_eq!(balance, 2000000);        // 2M remaining
        assert_eq!(unspent_count, 1);        // 1 unspent
        assert_eq!(spent_count, 1);          // 1 spent

        let unspent = wallet_state.get_unspent_transactions();
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].commitment, commitment2);

        let spent = wallet_state.get_spent_transactions();
        assert_eq!(spent.len(), 1);
        assert_eq!(spent[0].commitment, commitment1);
    }

    #[tokio::test]
    async fn test_block_range_queries() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        // Add transactions across different blocks
        let transactions = vec![
            WalletTransaction::new(
                100, Some(0), None, CompressedCommitment::new([1u8; 32]),
                1000000, PaymentId::Empty,
                TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
            ),
            WalletTransaction::new(
                500, Some(1), None, CompressedCommitment::new([2u8; 32]),
                2000000, PaymentId::Empty,
                TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
            ),
            WalletTransaction::new(
                1000, Some(2), None, CompressedCommitment::new([3u8; 32]),
                3000000, PaymentId::Empty,
                TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
            ),
        ];

        storage.save_transactions(&transactions).await.unwrap();

        // Test block range queries
        let range_txs = storage.get_transactions_by_block_range(200, 800).await.unwrap();
        assert_eq!(range_txs.len(), 1);
        assert_eq!(range_txs[0].block_height, 500);

        // Test highest/lowest block
        let highest = storage.get_highest_block().await.unwrap();
        let lowest = storage.get_lowest_block().await.unwrap();
        assert_eq!(highest, Some(1000));
        assert_eq!(lowest, Some(100));
    }

    #[tokio::test]
    async fn test_clear_all_transactions() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        // Add some transactions
        let transaction = WalletTransaction::new(
            100, Some(0), None, CompressedCommitment::new([1u8; 32]),
            1000000, PaymentId::Empty,
            TransactionStatus::MinedConfirmed, TransactionDirection::Inbound, true,
        );
        storage.save_transaction(&transaction).await.unwrap();

        // Verify they exist
        let count = storage.get_transaction_count().await.unwrap();
        assert_eq!(count, 1);

        // Clear all
        storage.clear_all_transactions().await.unwrap();

        // Verify they're gone
        let count = storage.get_transaction_count().await.unwrap();
        assert_eq!(count, 0);

        let stats = storage.get_statistics().await.unwrap();
        assert_eq!(stats.total_transactions, 0);
    }
} 