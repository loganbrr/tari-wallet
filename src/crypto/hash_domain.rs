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

/// Domain for wallet message signing operations
/// This must match the exact domain used by Tari wallet for compatibility
pub struct WalletMessageSigningDomain;

impl DomainSeparation for WalletMessageSigningDomain {
    fn version() -> u8 {
        1
    }

    fn domain() -> &'static str {
        "com.tari.base_layer.wallet.message_signing"
    }
}
