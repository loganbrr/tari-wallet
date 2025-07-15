//! Hash domain definitions for domain separation

use tari_crypto::hashing::DomainSeparation;

/// Domain for key manager operations
pub struct KeyManagerDomain;

impl DomainSeparation for KeyManagerDomain {
    fn version() -> u8 {
        1
    }

    fn domain() -> &'static str {
        "com.tari.base_layer.key_manager"
    }
} 