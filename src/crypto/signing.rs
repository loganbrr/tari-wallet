//! Tari-compatible message signing and verification
//!
//! This module implements message signing using Schnorr signatures with domain separation
//! that is compatible with the Tari wallet implementation.

use rand::rngs::OsRng;
use tari_crypto::{
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    signatures::SchnorrSignature,
};
use tari_utilities::hex::Hex;

use super::hash_domain::WalletMessageSigningDomain;
use crate::errors::{LightweightWalletError, ValidationError};

/// Type alias for domain-separated wallet signatures
/// This matches Tari's SignatureWithDomain for wallet message signing
pub type WalletSignature = SchnorrSignature<RistrettoPublicKey, RistrettoSecretKey, WalletMessageSigningDomain>;

/// Signs a message using the provided secret key with Tari wallet-compatible domain separation
///
/// # Arguments
/// * `secret_key` - The secret key to sign with
/// * `message` - The message to sign (will be encoded as UTF-8 bytes)
///
/// # Returns
/// * `Ok(WalletSignature)` - The domain-separated signature
/// * `Err(LightweightWalletError)` - If signing fails
///
/// # Example
/// ```
/// use rand::rngs::OsRng;
/// use tari_crypto::{keys::SecretKey, ristretto::RistrettoSecretKey};
/// use lightweight_wallet_libs::crypto::signing::sign_message;
///
/// let secret_key = RistrettoSecretKey::random(&mut OsRng);
/// let message = "Hello, Tari!";
/// let signature = sign_message(&secret_key, message).unwrap();
/// ```
pub fn sign_message(secret_key: &RistrettoSecretKey, message: &str) -> Result<WalletSignature, LightweightWalletError> {
    let message_bytes = message.as_bytes();
    
    WalletSignature::sign(secret_key, message_bytes, &mut OsRng)
        .map_err(|e| LightweightWalletError::ValidationError(
            ValidationError::SignatureValidationFailed(
                format!("Failed to sign message: {}", e)
            )
        ))
}

/// Signs a message and returns hex-encoded signature components
///
/// # Arguments
/// * `secret_key` - The secret key to sign with
/// * `message` - The message to sign
///
/// # Returns
/// * `Ok((signature_hex, nonce_hex))` - Tuple of hex-encoded signature scalar and public nonce
/// * `Err(LightweightWalletError)` - If signing fails
///
/// # Example
/// ```
/// use rand::rngs::OsRng;
/// use tari_crypto::{keys::SecretKey, ristretto::RistrettoSecretKey};
/// use lightweight_wallet_libs::crypto::signing::sign_message_with_hex_output;
///
/// let secret_key = RistrettoSecretKey::random(&mut OsRng);
/// let message = "Hello, Tari!";
/// let (signature_hex, nonce_hex) = sign_message_with_hex_output(&secret_key, message).unwrap();
/// ```
pub fn sign_message_with_hex_output(
    secret_key: &RistrettoSecretKey, 
    message: &str
) -> Result<(String, String), LightweightWalletError> {
    let signature = sign_message(secret_key, message)?;
    
    let hex_signature = signature.get_signature().to_hex();
    let hex_nonce = signature.get_public_nonce().to_hex();
    
    Ok((hex_signature, hex_nonce))
}

/// Verifies a message signature using the provided public key
///
/// # Arguments
/// * `public_key` - The public key to verify against
/// * `message` - The original message that was signed
/// * `signature` - The signature to verify
///
/// # Returns
/// * `true` if the signature is valid
/// * `false` if the signature is invalid
///
/// # Example
/// ```
/// use rand::rngs::OsRng;
/// use tari_crypto::{keys::{PublicKey, SecretKey}, ristretto::{RistrettoPublicKey, RistrettoSecretKey}};
/// use lightweight_wallet_libs::crypto::signing::{sign_message, verify_message};
///
/// let secret_key = RistrettoSecretKey::random(&mut OsRng);
/// let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
/// let message = "Hello, Tari!";
/// 
/// let signature = sign_message(&secret_key, message).unwrap();
/// let is_valid = verify_message(&public_key, message, &signature);
/// assert!(is_valid);
/// ```
pub fn verify_message(
    public_key: &RistrettoPublicKey, 
    message: &str,
    signature: &WalletSignature
) -> bool {
    let message_bytes = message.as_bytes();
    signature.verify(public_key, message_bytes)
}

/// Verifies a message signature from hex-encoded components
///
/// # Arguments
/// * `public_key` - The public key to verify against
/// * `message` - The original message that was signed
/// * `hex_signature` - Hex-encoded signature scalar
/// * `hex_nonce` - Hex-encoded public nonce
///
/// # Returns
/// * `Ok(true)` if the signature is valid
/// * `Ok(false)` if the signature is invalid but properly formatted
/// * `Err(LightweightWalletError)` if the hex components are malformed
///
/// # Example
/// ```
/// use rand::rngs::OsRng;
/// use tari_crypto::{keys::{PublicKey, SecretKey}, ristretto::{RistrettoPublicKey, RistrettoSecretKey}};
/// use lightweight_wallet_libs::crypto::signing::{sign_message_with_hex_output, verify_message_from_hex};
///
/// let secret_key = RistrettoSecretKey::random(&mut OsRng);
/// let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
/// let message = "Hello, Tari!";
/// 
/// let (sig_hex, nonce_hex) = sign_message_with_hex_output(&secret_key, message).unwrap();
/// let is_valid = verify_message_from_hex(&public_key, message, &sig_hex, &nonce_hex).unwrap();
/// assert!(is_valid);
/// ```
pub fn verify_message_from_hex(
    public_key: &RistrettoPublicKey,
    message: &str,
    hex_signature: &str,
    hex_nonce: &str,
) -> Result<bool, LightweightWalletError> {
    // Parse signature components from hex
    let signature_scalar = RistrettoSecretKey::from_hex(hex_signature)
        .map_err(|e| LightweightWalletError::ValidationError(
            ValidationError::SignatureValidationFailed(
                format!("Invalid signature hex: {}", e)
            )
        ))?;
    
    let public_nonce = RistrettoPublicKey::from_hex(hex_nonce)
        .map_err(|e| LightweightWalletError::ValidationError(
            ValidationError::SignatureValidationFailed(
                format!("Invalid nonce hex: {}", e)
            )
        ))?;
    
    // Reconstruct the signature
    let signature = WalletSignature::new(public_nonce, signature_scalar);
    
    Ok(verify_message(public_key, message, &signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use tari_crypto::keys::{PublicKey, SecretKey};

    #[test]
    fn test_sign_and_verify_message() {
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        let message = "Hello, Tari!";

        // Sign the message
        let signature = sign_message(&secret_key, message).unwrap();

        // Verify the signature
        assert!(verify_message(&public_key, message, &signature));

        // Verify with wrong message should fail
        assert!(!verify_message(&public_key, "Wrong message", &signature));
    }

    #[test]
    fn test_sign_and_verify_with_hex() {
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        let message = "Hello, Tari!";

        // Sign and get hex components
        let (hex_signature, hex_nonce) = sign_message_with_hex_output(&secret_key, message).unwrap();

        // Verify from hex components
        let is_valid = verify_message_from_hex(&public_key, message, &hex_signature, &hex_nonce).unwrap();
        assert!(is_valid);

        // Verify with wrong message should fail
        let is_invalid = verify_message_from_hex(&public_key, "Wrong message", &hex_signature, &hex_nonce).unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_hex_parsing_errors() {
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        let message = "Hello, Tari!";

        // Test invalid hex signature
        let result = verify_message_from_hex(&public_key, message, "invalid_hex", "0000000000000000000000000000000000000000000000000000000000000000");
        assert!(result.is_err());

        // Test invalid hex nonce
        let result = verify_message_from_hex(&public_key, message, "0000000000000000000000000000000000000000000000000000000000000000", "invalid_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_different_keys() {
        let secret_key1 = RistrettoSecretKey::random(&mut OsRng);
        let secret_key2 = RistrettoSecretKey::random(&mut OsRng);
        let public_key1 = RistrettoPublicKey::from_secret_key(&secret_key1);
        let public_key2 = RistrettoPublicKey::from_secret_key(&secret_key2);
        let message = "Hello, Tari!";

        // Sign with key1
        let signature = sign_message(&secret_key1, message).unwrap();

        // Verify with correct key should succeed
        assert!(verify_message(&public_key1, message, &signature));

        // Verify with wrong key should fail
        assert!(!verify_message(&public_key2, message, &signature));
    }

    #[test]
    fn test_empty_message() {
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        let message = "";

        let signature = sign_message(&secret_key, message).unwrap();
        assert!(verify_message(&public_key, message, &signature));
    }

    #[test]
    fn test_unicode_message() {
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        let message = "Hello, 世界! 🚀";

        let signature = sign_message(&secret_key, message).unwrap();
        assert!(verify_message(&public_key, message, &signature));
    }
}
