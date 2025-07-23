#!/usr/bin/env python3
"""
Test suite for blockchain scanning functionality in Tari wallet Python bindings.
"""

import lightweight_wallet_libpy


def test_scanner_creation():
    """Test scanner creation."""
    print("Testing scanner creation...")
    
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    base_node_url = "http://127.0.0.1:18142"
    
    # Create scanner
    scanner = lightweight_wallet_libpy.TariScanner(base_node_url, wallet)
    assert scanner is not None
    
    print("✅ Scanner creation tests passed")


def test_get_tip_height():
    """Test getting tip height (placeholder implementation)."""
    print("\nTesting get tip height...")
    
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    scanner = lightweight_wallet_libpy.TariScanner("http://127.0.0.1:18142", wallet)
    
    # Get tip height (should return 0 in placeholder implementation)
    tip_height = scanner.get_tip_height()
    assert isinstance(tip_height, int)
    assert tip_height == 0  # Placeholder returns 0
    
    print(f"Tip height: {tip_height}")
    print("✅ Get tip height tests passed")


def test_scan_blocks():
    """Test block scanning (placeholder implementation)."""
    print("\nTesting block scanning...")
    
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    scanner = lightweight_wallet_libpy.TariScanner("http://127.0.0.1:18142", wallet)
    
    # Scan blocks
    result = scanner.scan_blocks(1000, 1010)
    
    # Verify result structure
    assert hasattr(result, 'transaction_count')
    assert hasattr(result, 'total_scanned')
    assert hasattr(result, 'current_height')
    
    assert result.transaction_count == 0  # Placeholder
    assert result.total_scanned == 11  # 1000 to 1010 inclusive
    assert result.current_height == 1010
    
    print(f"Scan result: {result}")
    print("✅ Block scanning tests passed")


def test_scan_blocks_no_end_height():
    """Test block scanning without end height."""
    print("\nTesting block scanning without end height...")
    
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    scanner = lightweight_wallet_libpy.TariScanner("http://127.0.0.1:18142", wallet)
    
    # Scan blocks without end height
    result = scanner.scan_blocks(1000, None)
    
    # Should default to start + 100
    assert result.total_scanned == 101  # 1000 to 1100 inclusive
    assert result.current_height == 1100
    
    print(f"Scan result (no end): {result}")
    print("✅ Block scanning without end height tests passed")


def test_get_balance():
    """Test getting wallet balance (placeholder implementation)."""
    print("\nTesting get balance...")
    
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    scanner = lightweight_wallet_libpy.TariScanner("http://127.0.0.1:18142", wallet)
    
    # Get balance
    balance = scanner.get_balance()
    
    # Verify balance structure
    assert hasattr(balance, 'available')
    assert hasattr(balance, 'pending')
    assert hasattr(balance, 'immature')
    assert hasattr(balance, 'total')
    
    assert balance.available == 0  # Placeholder
    assert balance.pending == 0    # Placeholder
    assert balance.immature == 0   # Placeholder
    assert balance.total() == 0    # Should be sum of all
    
    print(f"Balance: {balance}")
    print("✅ Get balance tests passed")


def test_scan_result_repr():
    """Test ScanResult string representation."""
    print("\nTesting ScanResult representation...")
    
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    scanner = lightweight_wallet_libpy.TariScanner("http://127.0.0.1:18142", wallet)
    
    result = scanner.scan_blocks(100, 200)
    result_str = str(result)
    result_repr = repr(result)
    
    print(f"ScanResult str: {result_str}")
    print(f"ScanResult repr: {result_repr}")
    
    assert "ScanResult" in result_str
    assert "transaction_count=0" in result_str
    assert "total_scanned=101" in result_str
    assert "current_height=200" in result_str
    
    print("✅ ScanResult representation tests passed")


def test_balance_repr():
    """Test Balance string representation."""
    print("\nTesting Balance representation...")
    
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    scanner = lightweight_wallet_libpy.TariScanner("http://127.0.0.1:18142", wallet)
    
    balance = scanner.get_balance()
    balance_str = str(balance)
    balance_repr = repr(balance)
    
    print(f"Balance str: {balance_str}")
    print(f"Balance repr: {balance_repr}")
    
    assert "Balance" in balance_str
    assert "available=0" in balance_str
    assert "pending=0" in balance_str
    assert "immature=0" in balance_str
    assert "total=0" in balance_str
    
    print("✅ Balance representation tests passed")


def test_multiple_scanners():
    """Test that multiple scanner instances work independently."""
    print("\nTesting multiple scanner instances...")
    
    wallet1 = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    wallet2 = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    
    scanner1 = lightweight_wallet_libpy.TariScanner("http://127.0.0.1:18142", wallet1)
    scanner2 = lightweight_wallet_libpy.TariScanner("http://127.0.0.1:28142", wallet2)
    
    # Both should work independently
    result1 = scanner1.scan_blocks(1000, 1100)
    result2 = scanner2.scan_blocks(2000, 2050)
    
    assert result1.current_height == 1100
    assert result2.current_height == 2050
    assert result1.total_scanned == 101
    assert result2.total_scanned == 51
    
    print("✅ Multiple scanner instances tests passed")


def main():
    """Run all scanning tests."""
    print("=== Tari Wallet Blockchain Scanning Test Suite ===\n")
    
    try:
        test_scanner_creation()
        test_get_tip_height()
        test_scan_blocks()
        test_scan_blocks_no_end_height()
        test_get_balance()
        test_scan_result_repr()
        test_balance_repr()
        test_multiple_scanners()
        
        print("\n🎉 All blockchain scanning tests passed!")
        print("Note: These tests use placeholder implementations.")
        print("Real blockchain scanning requires async implementation.")
        
    except Exception as e:
        print(f"\n❌ Scanning test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
