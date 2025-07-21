//! Example demonstrating Tari-compatible message signing and verification
//!
//! This example shows how to use the lightweight wallet libraries to sign and verify
//! messages using Schnorr signatures with domain separation compatible with Tari wallet.

use rand::rngs::OsRng;
use tari_crypto::keys::{PublicKey, SecretKey};
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use tari_utilities::hex::Hex;

use lightweight_wallet_libs::crypto::signing::{
    sign_message, sign_message_with_hex_output, verify_message, verify_message_from_hex,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Tari Message Signing Example");
    println!("================================\n");

    // Generate a random keypair
    let secret_key = RistrettoSecretKey::random(&mut OsRng);
    let public_key = RistrettoPublicKey::from_secret_key(&secret_key);

    println!("🔑 Generated keypair:");
    println!("Public key: {}", public_key.to_hex());
    println!("Secret key: {}\n", secret_key.to_hex());

    // Message to sign
    let message = "Hello, Tari! This is a signed message.";
    println!("📝 Message to sign: \"{}\"", message);

    // Example 1: Basic signing and verification
    println!("\n🔏 Example 1: Basic Signing");
    println!("---------------------------");
    
    let signature = sign_message(&secret_key, message)?;
    println!("✅ Message signed successfully");
    
    let is_valid = verify_message(&public_key, message, &signature);
    println!("✅ Signature verification: {}", if is_valid { "VALID" } else { "INVALID" });

    // Example 2: Signing with hex output (for transport/storage)
    println!("\n🔏 Example 2: Hex-encoded Signature Components");
    println!("----------------------------------------------");
    
    let (hex_signature, hex_nonce) = sign_message_with_hex_output(&secret_key, message)?;
    println!("Signature scalar (hex): {}", hex_signature);
    println!("Public nonce (hex):     {}", hex_nonce);

    // Example 3: Verification from hex components
    println!("\n🔓 Example 3: Verification from Hex Components");
    println!("----------------------------------------------");
    
    let is_valid_from_hex = verify_message_from_hex(&public_key, message, &hex_signature, &hex_nonce)?;
    println!("✅ Hex verification result: {}", if is_valid_from_hex { "VALID" } else { "INVALID" });

    // Example 4: Cross-verification (signature object vs hex components)
    println!("\n🔄 Example 4: Cross-verification");
    println!("--------------------------------");
    
    // Get hex from signature object
    let sig_hex_from_obj = signature.get_signature().to_hex();
    let nonce_hex_from_obj = signature.get_public_nonce().to_hex();
    
    println!("Original signature hex matches: {}", hex_signature == sig_hex_from_obj);
    println!("Original nonce hex matches:     {}", hex_nonce == nonce_hex_from_obj);

    // Example 5: Testing with different messages (should fail)
    println!("\n❌ Example 5: Invalid Signature Test");
    println!("------------------------------------");
    
    let wrong_message = "This is a different message";
    let is_invalid = verify_message(&public_key, wrong_message, &signature);
    println!("Wrong message verification: {}", if is_invalid { "VALID" } else { "INVALID (expected)" });

    // Example 6: Testing with different keys (should fail)
    println!("\n❌ Example 6: Wrong Key Test");
    println!("----------------------------");
    
    let wrong_secret_key = RistrettoSecretKey::random(&mut OsRng);
    let wrong_public_key = RistrettoPublicKey::from_secret_key(&wrong_secret_key);
    
    let is_invalid_key = verify_message(&wrong_public_key, message, &signature);
    println!("Wrong key verification: {}", if is_invalid_key { "VALID" } else { "INVALID (expected)" });

    // Example 7: Unicode message support
    println!("\n🌍 Example 7: Unicode Message Support");
    println!("-------------------------------------");
    
    let unicode_message = "Hello, 世界! 🚀 Tari supports Unicode";
    let unicode_signature = sign_message(&secret_key, unicode_message)?;
    let unicode_valid = verify_message(&public_key, unicode_message, &unicode_signature);
    println!("Unicode message: \"{}\"", unicode_message);
    println!("Unicode verification: {}", if unicode_valid { "VALID" } else { "INVALID" });

    println!("\n✨ All examples completed successfully!");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_workflows() {
        // This test ensures the example code actually works
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        let message = "Test message";

        // Test basic workflow
        let signature = sign_message(&secret_key, message).unwrap();
        assert!(verify_message(&public_key, message, &signature));

        // Test hex workflow
        let (hex_sig, hex_nonce) = sign_message_with_hex_output(&secret_key, message).unwrap();
        let is_valid = verify_message_from_hex(&public_key, message, &hex_sig, &hex_nonce).unwrap();
        assert!(is_valid);

        // Test cross-verification
        assert_eq!(hex_sig, signature.get_signature().to_hex());
        assert_eq!(hex_nonce, signature.get_public_nonce().to_hex());
    }
}
