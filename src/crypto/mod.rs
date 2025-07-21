//! Cryptographic primitives for lightweight wallets
//! 
//! This module re-exports tari-crypto functionality for use in lightweight wallets,
//! avoiding duplication and ensuring compatibility with the main Tari implementation.

// Re-export domain separated hashing from tari-crypto
pub use tari_crypto::hashing::{DomainSeparation, DomainSeparatedHasher, DomainSeparatedHash};

// Re-export Ristretto keys from tari-crypto
pub use tari_crypto::ristretto::{RistrettoSecretKey, RistrettoPublicKey};

// Re-export key traits from tari-crypto
pub use tari_crypto::keys::{SecretKey, PublicKey};

// Re-export signature types from tari-crypto
pub use tari_crypto::signatures::SchnorrSignature;

// Keep our domain definitions but use the tari-crypto traits
pub mod hash_domain;
pub mod signing;

pub use hash_domain::{KeyManagerDomain, WalletMessageSigningDomain}; 