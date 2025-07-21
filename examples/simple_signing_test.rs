//! Simple test to verify message signing functionality works

use rand::rngs::OsRng;
use tari_crypto::keys::{PublicKey, SecretKey};
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use tari_utilities::hex::Hex;

use lightweight_wallet_libs::crypto::signing::{
    sign_message, sign_message_with_hex_output, verify_message, verify_message_from_hex,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Testing Tari Message Signing Implementation");
    println!("==============================================");

    // Generate a test keypair
    let secret_key = RistrettoSecretKey::random(&mut OsRng);
    let public_key = RistrettoPublicKey::from_secret_key(&secret_key);

    let message = "Hello, Tari! This is a test message.";
    println!("📝 Test message: \"{}\"", message);

    // Test 1: Basic signing and verification
    println!("\n🔐 Test 1: Basic Signing and Verification");
    let signature = sign_message(&secret_key, message)?;
    let is_valid = verify_message(&public_key, message, &signature);
    println!("✅ Signature valid: {}", is_valid);
    assert!(is_valid, "Signature should be valid");

    // Test 2: Hex encoding/decoding
    println!("\n🔐 Test 2: Hex Encoding/Decoding");
    let (hex_signature, hex_nonce) = sign_message_with_hex_output(&secret_key, message)?;
    let is_valid_hex = verify_message_from_hex(&public_key, message, &hex_signature, &hex_nonce)?;
    println!("✅ Hex signature valid: {}", is_valid_hex);
    assert!(is_valid_hex, "Hex signature should be valid");

    // Test 3: Cross-verification (both signatures should validate the same message)
    println!("\n🔄 Test 3: Cross-verification");
    let sig_hex_from_obj = signature.get_signature().to_hex();
    let nonce_hex_from_obj = signature.get_public_nonce().to_hex();
    
    // Verify the original signature can be reconstructed and verified from hex
    let is_reconstructed_valid = verify_message_from_hex(&public_key, message, &sig_hex_from_obj, &nonce_hex_from_obj)?;
    println!("Reconstructed signature valid: {}", is_reconstructed_valid);
    assert!(is_reconstructed_valid, "Reconstructed signature should be valid");
    
    // Note: hex_signature and sig_hex_from_obj will be different because 
    // each signing operation uses a new random nonce
    println!("Different signatures for same message (expected due to random nonce): {} != {}", 
             hex_signature != sig_hex_from_obj, hex_nonce != nonce_hex_from_obj);

    // Test 4: Invalid message (should fail)
    println!("\n❌ Test 4: Invalid Message Test");
    let wrong_message = "This is a different message";
    let is_invalid = verify_message(&public_key, wrong_message, &signature);
    println!("Wrong message verification: {}", if is_invalid { "VALID" } else { "INVALID (expected)" });
    assert!(!is_invalid, "Wrong message should be invalid");

    // Test 5: Invalid key (should fail)
    println!("\n❌ Test 5: Invalid Key Test");
    let wrong_secret_key = RistrettoSecretKey::random(&mut OsRng);
    let wrong_public_key = RistrettoPublicKey::from_secret_key(&wrong_secret_key);
    let is_invalid_key = verify_message(&wrong_public_key, message, &signature);
    println!("Wrong key verification: {}", if is_invalid_key { "VALID" } else { "INVALID (expected)" });
    assert!(!is_invalid_key, "Wrong key should be invalid");

    // Test 6: Unicode message
    println!("\n🌍 Test 6: Unicode Message Test");
    let unicode_message = "Hello, 世界! 🚀 Tari supports Unicode";
    let unicode_signature = sign_message(&secret_key, unicode_message)?;
    let unicode_valid = verify_message(&public_key, unicode_message, &unicode_signature);
    println!("Unicode message: \"{}\"", unicode_message);
    println!("Unicode verification: {}", if unicode_valid { "VALID" } else { "INVALID" });
    assert!(unicode_valid, "Unicode message should be valid");

    println!("\n🎉 All tests passed! Tari message signing implementation is working correctly.");
    
    Ok(())
}
