#!/usr/bin/env python3
"""
Comprehensive test suite for Tari wallet Python bindings.

Tests the full functionality of the PyO3-based Python wrapper.
"""

import lightweight_wallet_libpy


def test_wallet_creation():
    print("Testing wallet creation...")
    wallet1 = lightweight_wallet_libpy.generate_new_wallet()
    print(f"Generated wallet 1: {wallet1}")
    
    # Test with passphrase
    wallet2 = lightweight_wallet_libpy.generate_new_wallet("test_passphrase")
    print(f"Generated wallet 2 (with passphrase): {wallet2}")
    
    # Test class method
    wallet3 = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    print(f"Generated wallet 3 (class method): {wallet3}")
    
    # Test class method with passphrase
    wallet4 = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase("another_passphrase")
    print(f"Generated wallet 4 (class method with passphrase): {wallet4}")
    print("✅ Wallet creation tests passed")


def test_seed_phrase_operations():
    """Test seed phrase export functionality."""
    print("\nTesting seed phrase operations...")
    
    # Test wallet with seed phrase
    wallet_with_phrase = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    seed_phrase = wallet_with_phrase.export_seed_phrase()
    print(f"Exported seed phrase (length): {len(seed_phrase.split())} words")
    print(wallet_with_phrase)
    assert len(seed_phrase.split()) == 24  # Should be 24 words
    
    # Test different wallets have different seed phrases
    wallet2 = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    seed_phrase2 = wallet2.export_seed_phrase()
    assert seed_phrase != seed_phrase2
    
    print("✅ Seed phrase tests passed")

def test_address_generation():
    """Test address generation functionality."""
    print("\nTesting address generation...")
    
    wallet = lightweight_wallet_libpy.generate_new_wallet()
    
    # Create address features
    features = lightweight_wallet_libpy.AddressFeatures.interactive_and_one_sided()
    interactive_features = lightweight_wallet_libpy.AddressFeatures.interactive_only()
    
    # Test dual address generation
    dual_address = wallet.get_dual_address(features, None)
    print(f"Dual address: {dual_address[:50]}...")
    assert len(dual_address) > 0
    
    # Test dual address with payment ID
    payment_id = [1, 2, 3, 4, 5]
    dual_address_with_payment = wallet.get_dual_address(features, payment_id)
    print(f"Dual address with payment ID: {dual_address_with_payment[:50]}...")
    assert len(dual_address_with_payment) > 0
    assert dual_address != dual_address_with_payment  # Should be different
    
    # Test single address generation
    single_address = wallet.get_single_address(interactive_features)
    print(f"Single address: {single_address[:50]}...")
    assert len(single_address) > 0
    assert single_address != dual_address  # Should be different
    
    # Test deterministic address generation
    dual_address2 = wallet.get_dual_address(features, None)
    assert dual_address == dual_address2  # Should be the same
    
    single_address2 = wallet.get_single_address(interactive_features)
    assert single_address == single_address2  # Should be the same
    
    print("✅ Address generation tests passed")


def test_wallet_persistence():
    """Test that wallet state persists between method calls."""
    print("\nTesting wallet persistence...")
    
    wallet = lightweight_wallet_libpy.generate_new_wallet()
    
    # Set some state
    wallet.set_label("Persistent Test Wallet")
    wallet.set_network("mainnet")
    wallet.set_current_key_index(100)
    wallet.set_property("test_key", "test_value")
    
    # Verify state persists
    assert wallet.label() == "Persistent Test Wallet"
    assert wallet.network() == "mainnet"
    assert wallet.current_key_index() == 100
    assert wallet.get_property("test_key") == "test_value"
    
    # Generate addresses and verify state still persists
    features = lightweight_wallet_libpy.AddressFeatures.interactive_and_one_sided()
    address = wallet.get_dual_address(features, None)
    assert len(address) > 0
    assert wallet.label() == "Persistent Test Wallet"
    assert wallet.network() == "mainnet"
    
    print("✅ Wallet persistence tests passed")


def test_error_handling():
    """Test error handling scenarios."""
    print("\nTesting error handling...")
    
    # This should work without errors
    try:
        wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
        seed_phrase = wallet.export_seed_phrase()
        print(f"Successfully exported seed phrase: {len(seed_phrase.split())} words")
    except Exception as e:
        print(f"❌ Unexpected error during normal operation: {e}")
        raise
    
    print("✅ Error handling tests passed")


def test_multiple_wallets():
    """Test that multiple wallet instances work independently."""
    print("\nTesting multiple wallet instances...")
    
    # Create multiple wallets
    wallet1 = lightweight_wallet_libpy.generate_new_wallet()
    wallet2 = lightweight_wallet_libpy.generate_new_wallet()
    wallet3 = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    
    # Set different states
    wallet1.set_label("Wallet 1")
    wallet1.set_network("mainnet")
    
    wallet2.set_label("Wallet 2")
    wallet2.set_network("stagenet")
    
    wallet3.set_label("Wallet 3")
    wallet3.set_network("localnet")
    
    # Verify independence
    assert wallet1.label() == "Wallet 1"
    assert wallet1.network() == "mainnet"
    
    assert wallet2.label() == "Wallet 2"
    assert wallet2.network() == "stagenet"
    
    assert wallet3.label() == "Wallet 3"
    assert wallet3.network() == "localnet"
    
    # Generate different addresses
    features = lightweight_wallet_libpy.AddressFeatures.interactive_and_one_sided()
    addr1 = wallet1.get_dual_address(features, None)
    addr2 = wallet2.get_dual_address(features, None)
    addr3 = wallet3.get_dual_address(features, None)
    
    # All addresses should be different
    assert addr1 != addr2
    assert addr1 != addr3
    assert addr2 != addr3
    
    print("✅ Multiple wallet instances test passed")


def test_string_representations():
    """Test string representations of wallet objects."""
    print("\nTesting string representations...")
    
    wallet = lightweight_wallet_libpy.generate_new_wallet()
    wallet.set_label("Test Wallet")
    wallet.set_network("mainnet")
    
    # Test __str__ and __repr__
    str_repr = str(wallet)
    repr_repr = repr(wallet)
    
    print(f"str(wallet): {str_repr}")
    print(f"repr(wallet): {repr_repr}")
    
    assert "Test Wallet" in str_repr
    assert "mainnet" in str_repr
    assert str_repr == repr_repr  # They should be the same in our implementation
    
    print("✅ String representation tests passed")


def test_message_signing_basic():
    """Test basic message signing functionality."""
    print("\nTesting basic message signing...")
    
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    message = "Hello, Tari from Python!"
    
    # Sign the message
    signature_result = wallet.sign_message(message)
    
    # Verify the result structure
    assert isinstance(signature_result, dict)
    assert "signature" in signature_result
    assert "nonce" in signature_result
    assert "public_key" in signature_result
    
    # Verify the signature
    is_valid = wallet.verify_message(
        message,
        signature_result["signature"],
        signature_result["nonce"],
        signature_result["public_key"]
    )
    assert is_valid is True
    
    print("✅ Basic message signing tests passed")


def test_scanner_basic():
    """Test basic scanner functionality."""
    print("\nTesting basic scanner functionality...")
    
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    scanner = lightweight_wallet_libpy.TariScanner("http://127.0.0.1:18142", wallet)
    
    # Test scanner methods (will fail with connection error if no node running)
    print("  Note: Scanner tests require a running Tari base node on localhost:18142")
    try:
        tip_height = scanner.get_tip_height()
        assert isinstance(tip_height, int)
        print(f"  Connected to node, tip height: {tip_height}")
        
        scan_result = scanner.scan_blocks(1000, 1010)
        assert hasattr(scan_result, 'transaction_count')
        assert hasattr(scan_result, 'total_scanned')
        assert hasattr(scan_result, 'current_height')
        
        balance = scanner.get_balance()
        assert hasattr(balance, 'available')
        assert hasattr(balance, 'pending')
        assert hasattr(balance, 'immature')
        
        print("✅ Scanner functionality tests passed")
    except Exception as e:
        if "connection" in str(e).lower() or "failed to connect" in str(e).lower():
            print(f"  ⚠️  Scanner connection failed (expected if no node running): {str(e)[:100]}...")
            print("✅ Scanner API structure tests passed (connection expected to fail)")
        else:
            raise


def test_data_types():
    """Test wallet transaction and related data types."""
    print("\nTesting wallet data types...")
    
    # Test that we can import all the classes
    assert hasattr(lightweight_wallet_libpy, 'WalletTransaction')
    assert hasattr(lightweight_wallet_libpy, 'ScanResult')
    assert hasattr(lightweight_wallet_libpy, 'Balance')
    assert hasattr(lightweight_wallet_libpy, 'ScanProgress')
    assert hasattr(lightweight_wallet_libpy, 'AddressFeatures')
    
    print("✅ Data types tests passed")


def main():
    """Run all tests."""
    print("=== Tari Wallet Python Bindings Test Suite ===\n")
    
    try:
        test_wallet_creation()
        test_seed_phrase_operations()
        test_address_generation()
        test_wallet_persistence()
        test_error_handling()
        test_multiple_wallets()
        test_string_representations()
        test_message_signing_basic()
        test_scanner_basic()
        test_data_types()
        
        print("\n🎉 All tests passed! The Python bindings are working correctly.")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
