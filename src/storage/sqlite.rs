//! SQLite storage implementation for wallet transactions
//! 
//! This module provides a SQLite-based storage backend that implements the
//! `WalletStorage` trait for persisting wallet transaction data.

#[cfg(feature = "storage")]
use async_trait::async_trait;
#[cfg(feature = "storage")]
use std::path::Path;
#[cfg(feature = "storage")]
use tokio_rusqlite::{Connection, Result as SqliteResult};
#[cfg(feature = "storage")]
use rusqlite::{params, Row};

#[cfg(feature = "storage")]
use crate::{
    data_structures::{
        wallet_transaction::{WalletTransaction, WalletState},
        types::CompressedCommitment,
        transaction::{TransactionStatus, TransactionDirection},
        payment_id::PaymentId,
    },
    errors::{LightweightWalletResult, LightweightWalletError},
    storage::{WalletStorage, TransactionFilter, StorageStats},
};

/// SQLite storage backend for wallet transactions
#[cfg(feature = "storage")]
pub struct SqliteStorage {
    connection: Connection,
}

#[cfg(feature = "storage")]
impl SqliteStorage {
    /// Create a new SQLite storage instance
    pub async fn new<P: AsRef<Path>>(database_path: P) -> LightweightWalletResult<Self> {
        let connection = Connection::open(database_path).await
            .map_err(|e| LightweightWalletError::StorageError(format!("Failed to open SQLite database: {}", e)))?;
        
        Ok(Self { connection })
    }

    /// Create an in-memory SQLite storage instance (useful for testing)
    pub async fn new_in_memory() -> LightweightWalletResult<Self> {
        let connection = Connection::open(":memory:").await
            .map_err(|e| LightweightWalletError::StorageError(format!("Failed to create in-memory database: {}", e)))?;
        
        Ok(Self { connection })
    }

    /// Create the database schema
    async fn create_schema(&self) -> LightweightWalletResult<()> {
        let sql = r#"
            CREATE TABLE IF NOT EXISTS wallet_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_height INTEGER NOT NULL,
                output_index INTEGER,
                input_index INTEGER,
                commitment_hex TEXT NOT NULL UNIQUE,
                commitment_bytes BLOB NOT NULL,
                value INTEGER NOT NULL,
                payment_id_json TEXT NOT NULL,
                is_spent BOOLEAN NOT NULL DEFAULT FALSE,
                spent_in_block INTEGER,
                spent_in_input INTEGER,
                transaction_status INTEGER NOT NULL,
                transaction_direction INTEGER NOT NULL,
                is_mature BOOLEAN NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_commitment_hex ON wallet_transactions(commitment_hex);
            CREATE INDEX IF NOT EXISTS idx_block_height ON wallet_transactions(block_height);
            CREATE INDEX IF NOT EXISTS idx_is_spent ON wallet_transactions(is_spent);
            CREATE INDEX IF NOT EXISTS idx_transaction_direction ON wallet_transactions(transaction_direction);
            CREATE INDEX IF NOT EXISTS idx_transaction_status ON wallet_transactions(transaction_status);
            CREATE INDEX IF NOT EXISTS idx_spent_block ON wallet_transactions(spent_in_block);

            -- Trigger to update updated_at timestamp
            CREATE TRIGGER IF NOT EXISTS update_wallet_transactions_timestamp 
            AFTER UPDATE ON wallet_transactions
            BEGIN
                UPDATE wallet_transactions SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END;
        "#;

        self.connection.call(move |conn| {
            Ok(conn.execute_batch(sql)?)
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to create schema: {}", e)))?;

        Ok(())
    }

    /// Convert a database row to a WalletTransaction
    fn row_to_transaction(row: &Row) -> rusqlite::Result<WalletTransaction> {
        let commitment_bytes: Vec<u8> = row.get("commitment_bytes")?;
        let commitment_array: [u8; 32] = commitment_bytes.try_into()
            .map_err(|_| rusqlite::Error::InvalidColumnType(0, "commitment_bytes".to_string(), rusqlite::types::Type::Blob))?;
        
        let payment_id_json: String = row.get("payment_id_json")?;
        let payment_id: PaymentId = serde_json::from_str(&payment_id_json)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let transaction_status_int: i32 = row.get("transaction_status")?;
        let transaction_status = TransactionStatus::try_from(transaction_status_int)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let transaction_direction_int: i32 = row.get("transaction_direction")?;
        let transaction_direction = TransactionDirection::try_from(transaction_direction_int)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        Ok(WalletTransaction {
            block_height: row.get::<_, i64>("block_height")? as u64,
            output_index: row.get::<_, Option<i64>>("output_index")?.map(|i| i as usize),
            input_index: row.get::<_, Option<i64>>("input_index")?.map(|i| i as usize),
            commitment: CompressedCommitment::new(commitment_array),
            value: row.get::<_, i64>("value")? as u64,
            payment_id,
            is_spent: row.get("is_spent")?,
            spent_in_block: row.get::<_, Option<i64>>("spent_in_block")?.map(|i| i as u64),
            spent_in_input: row.get::<_, Option<i64>>("spent_in_input")?.map(|i| i as usize),
            transaction_status,
            transaction_direction,
            is_mature: row.get("is_mature")?,
        })
    }

    /// Build WHERE clause and parameters from filter
    fn build_filter_clause(filter: &TransactionFilter) -> (String, Vec<Box<dyn rusqlite::ToSql + Send>>) {
        let mut conditions = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql + Send>> = Vec::new();

        if let Some((from, to)) = filter.block_height_range {
            conditions.push("block_height BETWEEN ? AND ?".to_string());
            params.push(Box::new(from as i64));
            params.push(Box::new(to as i64));
        }

        if let Some(direction) = filter.direction {
            conditions.push("transaction_direction = ?".to_string());
            params.push(Box::new(direction as i32));
        }

        if let Some(status) = filter.status {
            conditions.push("transaction_status = ?".to_string());
            params.push(Box::new(status as i32));
        }

        if let Some(is_spent) = filter.is_spent {
            conditions.push("is_spent = ?".to_string());
            params.push(Box::new(is_spent));
        }

        if let Some(is_mature) = filter.is_mature {
            conditions.push("is_mature = ?".to_string());
            params.push(Box::new(is_mature));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        (where_clause, params)
    }
}

#[cfg(feature = "storage")]
#[async_trait]
impl WalletStorage for SqliteStorage {
    async fn initialize(&self) -> LightweightWalletResult<()> {
        self.create_schema().await
    }

    async fn save_transaction(&self, transaction: &WalletTransaction) -> LightweightWalletResult<()> {
        let tx = transaction.clone();
        self.connection.call(move |conn| {
            let payment_id_json = serde_json::to_string(&tx.payment_id)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            conn.execute(
                r#"
                INSERT OR REPLACE INTO wallet_transactions 
                (block_height, output_index, input_index, commitment_hex, commitment_bytes, 
                 value, payment_id_json, is_spent, spent_in_block, spent_in_input, 
                 transaction_status, transaction_direction, is_mature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
                params![
                    tx.block_height as i64,
                    tx.output_index.map(|i| i as i64),
                    tx.input_index.map(|i| i as i64),
                    tx.commitment_hex(),
                    tx.commitment.as_bytes().to_vec(),
                    tx.value as i64,
                    payment_id_json,
                    tx.is_spent,
                    tx.spent_in_block.map(|i| i as i64),
                    tx.spent_in_input.map(|i| i as i64),
                    tx.transaction_status as i32,
                    tx.transaction_direction as i32,
                    tx.is_mature,
                ],
            )?;
            Ok(())
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to save transaction: {}", e)))?;

        Ok(())
    }

    async fn save_transactions(&self, transactions: &[WalletTransaction]) -> LightweightWalletResult<()> {
        let tx_list = transactions.to_vec();
        self.connection.call(move |conn| {
            let tx = conn.transaction()?;
            
            for transaction in &tx_list {
                let payment_id_json = serde_json::to_string(&transaction.payment_id)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

                tx.execute(
                    r#"
                    INSERT OR REPLACE INTO wallet_transactions 
                    (block_height, output_index, input_index, commitment_hex, commitment_bytes, 
                     value, payment_id_json, is_spent, spent_in_block, spent_in_input, 
                     transaction_status, transaction_direction, is_mature)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                    params![
                        transaction.block_height as i64,
                        transaction.output_index.map(|i| i as i64),
                        transaction.input_index.map(|i| i as i64),
                        transaction.commitment_hex(),
                        transaction.commitment.as_bytes().to_vec(),
                        transaction.value as i64,
                        payment_id_json,
                        transaction.is_spent,
                        transaction.spent_in_block.map(|i| i as i64),
                        transaction.spent_in_input.map(|i| i as i64),
                        transaction.transaction_status as i32,
                        transaction.transaction_direction as i32,
                        transaction.is_mature,
                    ],
                )?;
            }
            
            tx.commit()?;
            Ok(())
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to save transactions batch: {}", e)))?;

        Ok(())
    }

    async fn update_transaction(&self, transaction: &WalletTransaction) -> LightweightWalletResult<()> {
        self.save_transaction(transaction).await
    }

    async fn mark_transaction_spent(
        &self,
        commitment: &CompressedCommitment,
        spent_in_block: u64,
        spent_in_input: usize,
    ) -> LightweightWalletResult<bool> {
        let commitment_hex = commitment.to_hex();
        self.connection.call(move |conn| {
            let rows_affected = conn.execute(
                r#"
                UPDATE wallet_transactions 
                SET is_spent = TRUE, spent_in_block = ?, spent_in_input = ?
                WHERE commitment_hex = ? AND is_spent = FALSE
                "#,
                params![spent_in_block as i64, spent_in_input as i64, commitment_hex],
            )?;
            Ok(rows_affected > 0)
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to mark transaction spent: {}", e)))
    }

    async fn get_transaction_by_commitment(
        &self,
        commitment: &CompressedCommitment,
    ) -> LightweightWalletResult<Option<WalletTransaction>> {
        let commitment_hex = commitment.to_hex();
        self.connection.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT * FROM wallet_transactions WHERE commitment_hex = ?"
            )?;
            
            let mut rows = stmt.query_map(params![commitment_hex], Self::row_to_transaction)?;
            
            if let Some(row) = rows.next() {
                Ok(Some(row?))
            } else {
                Ok(None)
            }
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to get transaction by commitment: {}", e)))
    }

    async fn get_transactions(
        &self,
        filter: Option<TransactionFilter>,
    ) -> LightweightWalletResult<Vec<WalletTransaction>> {
        self.connection.call(move |conn| {
            let mut base_query = "SELECT * FROM wallet_transactions".to_string();
            let mut params_values: Vec<Box<dyn rusqlite::ToSql + Send>> = Vec::new();

            if let Some(ref filter) = filter {
                let (where_clause, filter_params) = Self::build_filter_clause(filter);
                if !where_clause.is_empty() {
                    base_query.push(' ');
                    base_query.push_str(&where_clause);
                    params_values.extend(filter_params);
                }

                base_query.push_str(" ORDER BY block_height ASC, id ASC");

                if let Some(limit) = filter.limit {
                    base_query.push_str(&format!(" LIMIT {}", limit));
                }

                if let Some(offset) = filter.offset {
                    base_query.push_str(&format!(" OFFSET {}", offset));
                }
            } else {
                base_query.push_str(" ORDER BY block_height ASC, id ASC");
            }

            let mut stmt = conn.prepare(&base_query)?;
            let param_refs: Vec<&dyn rusqlite::ToSql> = params_values.iter()
                .map(|p| p.as_ref() as &dyn rusqlite::ToSql)
                .collect();
            let rows = stmt.query_map(&param_refs[..], Self::row_to_transaction)?;

            let mut transactions = Vec::new();
            for row in rows {
                transactions.push(row?);
            }

            Ok(transactions)
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to get transactions: {}", e)))
    }

    async fn load_wallet_state(&self) -> LightweightWalletResult<WalletState> {
        let transactions = self.get_transactions(None).await?;
        
        let mut wallet_state = WalletState::new();
        
        // Sort transactions by block height to ensure proper state building
        let mut sorted_transactions = transactions;
        sorted_transactions.sort_by_key(|tx| (tx.block_height, tx.output_index.unwrap_or(0)));
        
        // Rebuild wallet state from transactions
        for transaction in sorted_transactions {
            match transaction.transaction_direction {
                TransactionDirection::Inbound => {
                    wallet_state.add_received_output(
                        transaction.block_height,
                        transaction.output_index.unwrap_or(0),
                        transaction.commitment.clone(),
                        transaction.value,
                        transaction.payment_id.clone(),
                        transaction.transaction_status,
                        transaction.transaction_direction,
                        transaction.is_mature,
                    );
                    
                    // If the transaction is spent, mark it as spent
                    if transaction.is_spent {
                        wallet_state.mark_output_spent(
                            &transaction.commitment,
                            transaction.spent_in_block.unwrap_or(0),
                            transaction.spent_in_input.unwrap_or(0),
                        );
                    }
                },
                TransactionDirection::Outbound => {
                    // Outbound transactions are typically created when marking as spent
                    // They should already be handled by the mark_output_spent logic above
                },
                TransactionDirection::Unknown => {
                    // Handle unknown transactions - add them to the list but don't affect balance
                    wallet_state.transactions.push(transaction);
                }
            }
        }
        
        Ok(wallet_state)
    }

    async fn get_statistics(&self) -> LightweightWalletResult<StorageStats> {
        self.connection.call(|conn| {
            let mut stmt = conn.prepare(r#"
                SELECT 
                    COUNT(*) as total_transactions,
                    SUM(CASE WHEN transaction_direction = 0 THEN 1 ELSE 0 END) as inbound_count,
                    SUM(CASE WHEN transaction_direction = 1 THEN 1 ELSE 0 END) as outbound_count,
                    SUM(CASE WHEN is_spent = FALSE AND transaction_direction = 0 THEN 1 ELSE 0 END) as unspent_count,
                    SUM(CASE WHEN is_spent = TRUE AND transaction_direction = 0 THEN 1 ELSE 0 END) as spent_count,
                    SUM(CASE WHEN transaction_direction = 0 THEN value ELSE 0 END) as total_received,
                    SUM(CASE WHEN transaction_direction = 1 THEN value ELSE 0 END) as total_spent,
                    MAX(block_height) as highest_block,
                    MIN(block_height) as lowest_block
                FROM wallet_transactions
            "#)?;

            let row = stmt.query_row([], |row| {
                let total_received: i64 = row.get("total_received").unwrap_or(0);
                let total_spent: i64 = row.get("total_spent").unwrap_or(0);
                
                Ok(StorageStats {
                    total_transactions: row.get::<_, i64>("total_transactions")? as usize,
                    inbound_count: row.get::<_, i64>("inbound_count")? as usize,
                    outbound_count: row.get::<_, i64>("outbound_count")? as usize,
                    unspent_count: row.get::<_, i64>("unspent_count")? as usize,
                    spent_count: row.get::<_, i64>("spent_count")? as usize,
                    total_received: total_received as u64,
                    total_spent: total_spent as u64,
                    current_balance: total_received - total_spent,
                    highest_block: row.get::<_, Option<i64>>("highest_block")?.map(|h| h as u64),
                    lowest_block: row.get::<_, Option<i64>>("lowest_block")?.map(|h| h as u64),
                })
            })?;

            Ok(row)
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to get statistics: {}", e)))
    }

    async fn get_transactions_by_block_range(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> LightweightWalletResult<Vec<WalletTransaction>> {
        let filter = TransactionFilter::new().with_block_range(from_block, to_block);
        self.get_transactions(Some(filter)).await
    }

    async fn get_unspent_transactions(&self) -> LightweightWalletResult<Vec<WalletTransaction>> {
        let filter = TransactionFilter::new()
            .with_spent_status(false)
            .with_direction(TransactionDirection::Inbound);
        self.get_transactions(Some(filter)).await
    }

    async fn get_spent_transactions(&self) -> LightweightWalletResult<Vec<WalletTransaction>> {
        let filter = TransactionFilter::new()
            .with_spent_status(true)
            .with_direction(TransactionDirection::Inbound);
        self.get_transactions(Some(filter)).await
    }

    async fn has_commitment(&self, commitment: &CompressedCommitment) -> LightweightWalletResult<bool> {
        let commitment_hex = commitment.to_hex();
        self.connection.call(move |conn| {
            let mut stmt = conn.prepare("SELECT 1 FROM wallet_transactions WHERE commitment_hex = ? LIMIT 1")?;
            let exists = stmt.exists(params![commitment_hex])?;
            Ok(exists)
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to check commitment existence: {}", e)))
    }

    async fn get_highest_block(&self) -> LightweightWalletResult<Option<u64>> {
        self.connection.call(|conn| {
            let mut stmt = conn.prepare("SELECT MAX(block_height) FROM wallet_transactions")?;
            let block_height: Option<i64> = stmt.query_row([], |row| row.get(0))?;
            Ok(block_height.map(|h| h as u64))
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to get highest block: {}", e)))
    }

    async fn get_lowest_block(&self) -> LightweightWalletResult<Option<u64>> {
        self.connection.call(|conn| {
            let mut stmt = conn.prepare("SELECT MIN(block_height) FROM wallet_transactions")?;
            let block_height: Option<i64> = stmt.query_row([], |row| row.get(0))?;
            Ok(block_height.map(|h| h as u64))
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to get lowest block: {}", e)))
    }

    async fn clear_all_transactions(&self) -> LightweightWalletResult<()> {
        self.connection.call(|conn| {
            conn.execute("DELETE FROM wallet_transactions", [])?;
            Ok(())
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to clear transactions: {}", e)))
    }

    async fn get_transaction_count(&self) -> LightweightWalletResult<usize> {
        self.connection.call(|conn| {
            let mut stmt = conn.prepare("SELECT COUNT(*) FROM wallet_transactions")?;
            let count: i64 = stmt.query_row([], |row| row.get(0))?;
            Ok(count as usize)
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to get transaction count: {}", e)))
    }

    async fn close(&self) -> LightweightWalletResult<()> {
        // tokio-rusqlite automatically handles connection cleanup on drop
        Ok(())
    }
}

#[cfg(not(feature = "storage"))]
/// Placeholder for when storage feature is not enabled
pub struct SqliteStorage;

#[cfg(not(feature = "storage"))]
impl SqliteStorage {
    pub async fn new<P>(_database_path: P) -> Result<Self, &'static str> {
        Err("Storage feature not enabled")
    }
    
    pub async fn new_in_memory() -> Result<Self, &'static str> {
        Err("Storage feature not enabled")
    }
} 