//! Storage abstraction layer for wallet transactions
//!
//! This module provides a trait-based storage system that allows different
//! storage backends to be used for persisting wallet transaction data.
//! The current implementation includes SQLite support with room for additional
//! backends like PostgreSQL, MongoDB, or other databases.

pub mod sqlite;
pub mod storage_trait;

pub use sqlite::*;
pub use storage_trait::*;
