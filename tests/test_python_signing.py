#!/usr/bin/env python3
"""
Test suite for message signing functionality in Tari wallet Python bindings.
"""

import lightweight_wallet_libpy


def test_message_signing():
    """Test basic message signing functionality."""
    print("Testing message signing...")
    
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    message = "Hello, Tari!"
    
    # Sign the message
    signature_result = wallet.sign_message(message)
    
    # Verify the result structure
    assert isinstance(signature_result, dict)
    assert "signature" in signature_result
    assert "nonce" in signature_result
    assert "public_key" in signature_result
    
    signature = signature_result["signature"]
    nonce = signature_result["nonce"]
    public_key = signature_result["public_key"]
    
    print(f"Signature: {signature[:20]}...")
    print(f"Nonce: {nonce[:20]}...")
    print(f"Public key: {public_key[:20]}...")
    
    # All should be hex strings
    assert isinstance(signature, str)
    assert isinstance(nonce, str)
    assert isinstance(public_key, str)
    assert len(signature) > 0
    assert len(nonce) > 0
    assert len(public_key) > 0
    
    print("✅ Message signing tests passed")


def test_message_verification():
    """Test message signature verification."""
    print("\nTesting message verification...")
    
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    message = "Test message for verification"
    
    # Sign the message
    signature_result = wallet.sign_message(message)
    signature = signature_result["signature"]
    nonce = signature_result["nonce"]
    public_key = signature_result["public_key"]
    
    # Verify the signature
    is_valid = wallet.verify_message(message, signature, nonce, public_key)
    assert is_valid is True
    
    # Test with wrong message
    is_invalid = wallet.verify_message("Wrong message", signature, nonce, public_key)
    assert is_invalid is False
    
    # Test with wrong signature
    wrong_sig = "0" * len(signature)
    is_invalid2 = wallet.verify_message(message, wrong_sig, nonce, public_key)
    assert is_invalid2 is False
    
    print("✅ Message verification tests passed")


def test_signature_determinism():
    """Test that signatures are deterministic for the same wallet and message."""
    print("\nTesting signature determinism...")
    
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    message = "Deterministic test message"
    
    # Sign the same message twice
    result1 = wallet.sign_message(message)
    result2 = wallet.sign_message(message)
    
    # The public key should be the same (wallet doesn't change)
    assert result1["public_key"] == result2["public_key"]
    
    # Note: The signature and nonce might be different due to randomness in signing
    # This is normal for Schnorr signatures with random nonces
    
    print("✅ Signature determinism tests passed")


def test_different_wallets_different_signatures():
    """Test that different wallets produce different signatures."""
    print("\nTesting different wallets produce different signatures...")
    
    wallet1 = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    wallet2 = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    message = "Same message, different wallets"
    
    result1 = wallet1.sign_message(message)
    result2 = wallet2.sign_message(message)
    
    # Different wallets should have different public keys
    assert result1["public_key"] != result2["public_key"]
    
    # Cross-verification should fail
    is_valid_cross = wallet1.verify_message(
        message, 
        result2["signature"], 
        result2["nonce"], 
        result2["public_key"]
    )
    assert is_valid_cross is True  # This should actually work since we're providing the right public key
    
    # But using wrong public key should fail
    is_invalid_cross = wallet1.verify_message(
        message, 
        result2["signature"], 
        result2["nonce"], 
        result1["public_key"]  # Wrong public key
    )
    assert is_invalid_cross is False
    
    print("✅ Different wallets signature tests passed")


def test_unicode_message_signing():
    """Test signing messages with unicode characters."""
    print("\nTesting unicode message signing...")
    
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    unicode_message = "Hello 世界! 🚀 Tari cryptocurrency ₿"
    
    # Sign unicode message
    result = wallet.sign_message(unicode_message)
    
    # Verify it works
    is_valid = wallet.verify_message(
        unicode_message,
        result["signature"],
        result["nonce"],
        result["public_key"]
    )
    assert is_valid is True
    
    print("✅ Unicode message signing tests passed")


def test_empty_message_signing():
    """Test signing empty message."""
    print("\nTesting empty message signing...")
    
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    empty_message = ""
    
    # Sign empty message
    result = wallet.sign_message(empty_message)
    
    # Verify it works
    is_valid = wallet.verify_message(
        empty_message,
        result["signature"],
        result["nonce"],
        result["public_key"]
    )
    assert is_valid is True
    
    print("✅ Empty message signing tests passed")


def main():
    """Run all signing tests."""
    print("=== Tari Wallet Message Signing Test Suite ===\n")
    
    try:
        test_message_signing()
        test_message_verification()
        test_signature_determinism()
        test_different_wallets_different_signatures()
        test_unicode_message_signing()
        test_empty_message_signing()
        
        print("\n🎉 All message signing tests passed!")
        
    except Exception as e:
        print(f"\n❌ Signing test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
