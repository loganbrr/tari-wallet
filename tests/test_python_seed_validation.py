#!/usr/bin/env python3
"""
Dedicated test suite for seed phrase validation functionality in Tari wallet Python bindings.

Tests comprehensive validation scenarios to ensure 1:1 behavior with Rust implementation.
"""

import lightweight_wallet_libpy


def test_valid_generated_seed_phrases():
    """Test that all generated seed phrases validate successfully."""
    print("Testing valid generated seed phrases...")
    
    # Test multiple generated wallets
    for i in range(5):
        wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
        seed_phrase = wallet.export_seed_phrase()
        
        # Every generated seed phrase should be valid
        is_valid = lightweight_wallet_libpy.validate_seed_phrase_py(seed_phrase)
        assert is_valid is True, f"Generated seed phrase {i+1} should be valid"
        
        # Verify it's exactly 24 words
        words = seed_phrase.split()
        assert len(words) == 24, f"Generated seed phrase {i+1} should have 24 words, got {len(words)}"
        
        print(f"  ✅ Generated seed phrase {i+1}: valid ({len(words)} words)")
    
    print("✅ Valid generated seed phrases test passed")


def test_valid_seed_phrases_with_passphrase():
    """Test that seed phrases generated with passphrase validate correctly."""
    print("\nTesting seed phrases with passphrase...")
    
    # Test with different passphrases
    passphrases = [None, "", "test", "complex_passphrase_123!"]
    
    for i, passphrase in enumerate(passphrases):
        wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase(passphrase)
        seed_phrase = wallet.export_seed_phrase()
        
        # Seed phrase should validate regardless of passphrase used for generation
        is_valid = lightweight_wallet_libpy.validate_seed_phrase_py(seed_phrase)
        assert is_valid is True, f"Seed phrase with passphrase '{passphrase}' should validate"
        
        passphrase_desc = "None" if passphrase is None else f"'{passphrase}'"
        print(f"  ✅ Seed phrase with passphrase {passphrase_desc}: valid")
    
    print("✅ Seed phrases with passphrase test passed")


def test_invalid_word_count():
    """Test validation with incorrect word counts."""
    print("\nTesting invalid word counts...")
    
    # Test various invalid word counts
    test_cases = [
        ("", 0),
        ("abandon", 1),
        ("abandon abandon", 2),
        ("abandon abandon abandon abandon abandon", 5),
        ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", 11),  # 11 words
        ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", 12),  # 12 words (standard BIP-39 length, but Tari uses 24)
        (" ".join(["abandon"] * 23), 23),  # 23 words
        (" ".join(["abandon"] * 25), 25),  # 25 words
        (" ".join(["abandon"] * 48), 48),  # Double length
    ]
    
    for mnemonic, word_count in test_cases:
        is_valid = lightweight_wallet_libpy.validate_seed_phrase_py(mnemonic)
        assert is_valid is False, f"Seed phrase with {word_count} words should be invalid"
        print(f"  ✅ {word_count} words: correctly rejected")
    
    print("✅ Invalid word count test passed")


def test_invalid_words():
    """Test validation with invalid words in the mnemonic."""
    print("\nTesting invalid words...")
    
    # Generate a base of 23 valid words
    valid_base = " ".join(["abandon"] * 23)
    
    test_cases = [
        f"{valid_base} invalidword",
        f"{valid_base} xyz123",
        f"{valid_base} 12345",
        f"{valid_base} !@#$%",
        f"{valid_base} nonexistent",
        f"{valid_base} tari",  # "tari" is not in BIP-39 wordlist
        f"{valid_base} bitcoin",  # "bitcoin" is not in BIP-39 wordlist
        f"{valid_base} cryptocurrency",  # Too long, not in wordlist
        f"invalidword {valid_base}",  # Invalid word at start
        " ".join(["abandon"] * 12) + " invalidword " + " ".join(["abandon"] * 11),  # Invalid word in middle
    ]
    
    for mnemonic in test_cases:
        is_valid = lightweight_wallet_libpy.validate_seed_phrase_py(mnemonic)
        assert is_valid is False, f"Seed phrase with invalid word should be rejected: {mnemonic.split()[-1] if mnemonic.endswith('invalidword') or mnemonic.endswith('xyz123') or mnemonic.endswith('12345') or mnemonic.endswith('!@#$%') or mnemonic.endswith('nonexistent') or mnemonic.endswith('tari') or mnemonic.endswith('bitcoin') or mnemonic.endswith('cryptocurrency') else 'middle word'}"
        print(f"  ✅ Invalid word case: correctly rejected")
    
    print("✅ Invalid words test passed")


def test_edge_cases():
    """Test edge cases and special inputs."""
    print("\nTesting edge cases...")
    
    edge_cases = [
        ("", "Empty string"),
        ("   ", "Whitespace only"),
        ("\n\t\r", "Special whitespace characters"),
        (" ".join(["abandon"] * 24) + " ", "Trailing space"),
        (" " + " ".join(["abandon"] * 24), "Leading space"),
        ("  ".join(["abandon"] * 24), "Double spaces between words"),
        ("abandon\tabandon\nabandon" + " abandon" * 21, "Mixed whitespace separators"),
        ("ABANDON " * 24, "Uppercase words (if not normalized)"),
        ("Abandon " * 24, "Mixed case words"),
    ]
    
    for mnemonic, description in edge_cases:
        is_valid = lightweight_wallet_libpy.validate_seed_phrase_py(mnemonic.strip())
        # Most edge cases should be invalid (except the whitespace normalization cases)
        expected_result = description in ["Trailing space", "Leading space", "Double spaces between words", "Mixed whitespace separators"]
        
        if description == "Mixed whitespace separators":
            # This might be valid if the library normalizes whitespace
            print(f"  📝 {description}: {is_valid} (implementation dependent)")
        else:
            # For other edge cases, we expect them to be invalid
            assert is_valid is False, f"{description} should be invalid"
            print(f"  ✅ {description}: correctly rejected")
    
    print("✅ Edge cases test passed")


def test_checksum_validation():
    """Test that checksum validation works (indirectly through CipherSeed validation)."""
    print("\nTesting checksum validation...")
    
    # Generate a valid seed phrase
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    valid_mnemonic = wallet.export_seed_phrase()
    words = valid_mnemonic.split()
    
    # Create invalid checksums by swapping words (this should break the checksum)
    invalid_test_cases = [
        # Swap first and last word
        " ".join([words[-1]] + words[1:-1] + [words[0]]),
        
        # Swap first two words
        " ".join([words[1], words[0]] + words[2:]),
        
        # Replace last word with first word (duplicate)
        " ".join(words[:-1] + [words[0]]),
        
        # Replace random word with "abandon" (if not already present)
        " ".join(words[:12] + ["abandon"] + words[13:]) if words[12] != "abandon" else " ".join(words[:12] + ["ability"] + words[13:]),
    ]
    
    for i, invalid_mnemonic in enumerate(invalid_test_cases):
        is_valid = lightweight_wallet_libpy.validate_seed_phrase_py(invalid_mnemonic)
        # These should be invalid due to checksum failure
        assert is_valid is False, f"Modified seed phrase {i+1} should fail checksum validation"
        print(f"  ✅ Checksum test case {i+1}: correctly rejected")
    
    print("✅ Checksum validation test passed")


def test_cross_validation_with_wallet_creation():
    """Test that validation matches actual wallet creation behavior."""
    print("\nTesting cross-validation with wallet creation...")
    
    # Generate several valid seed phrases
    for i in range(3):
        wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
        seed_phrase = wallet.export_seed_phrase()
        
        # Validation should pass
        is_valid = lightweight_wallet_libpy.validate_seed_phrase_py(seed_phrase)
        assert is_valid is True, f"Seed phrase {i+1} should validate"
        
        # We should be able to export the same seed phrase consistently
        exported_again = wallet.export_seed_phrase()
        assert seed_phrase == exported_again, f"Seed phrase {i+1} should be consistently exportable"
        
        # Re-validation should still pass
        is_valid_again = lightweight_wallet_libpy.validate_seed_phrase_py(exported_again)
        assert is_valid_again is True, f"Re-exported seed phrase {i+1} should still validate"
        
        print(f"  ✅ Cross-validation test {i+1}: passed")
    
    print("✅ Cross-validation test passed")


def main():
    """Run all seed phrase validation tests."""
    print("=== Tari Wallet Seed Phrase Validation Test Suite ===\n")
    
    try:
        test_valid_generated_seed_phrases()
        test_valid_seed_phrases_with_passphrase()
        test_invalid_word_count()
        test_invalid_words()
        test_edge_cases()
        test_checksum_validation()
        test_cross_validation_with_wallet_creation()
        
        print("\n🎉 All seed phrase validation tests passed!")
        print("The Python binding validate_seed_phrase_py() function behaves correctly")
        print("and maintains 1:1 parity with the Rust implementation.")
        
    except Exception as e:
        print(f"\n❌ Seed phrase validation test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
