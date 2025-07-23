#!/usr/bin/env python3
"""
Tari Wallet Python Bindings Example

This example demonstrates how to use the Tari Lightweight Wallet Libraries
from Python using the native PyO3 bindings.
"""

import lightweight_wallet_libpy
import time


def main():
    print("=== Tari Wallet Python Bindings Example ===\n")
    
    # Create a new wallet
    print("1. Creating a new wallet...")
    wallet = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    print(f"   Created: {wallet}")
    
    # Set wallet properties
    print("\n2. Setting wallet properties...")
    wallet.set_label("Python Example Wallet")
    wallet.set_network("mainnet")
    wallet.set_birthday(100000)
    wallet.set_property("environment", "example")
    print(f"   Updated: {wallet}")
    
    # Export seed phrase
    print("\n3. Exporting seed phrase...")
    seed_phrase = wallet.export_seed_phrase()
    print(f"   Seed phrase: {seed_phrase[:50]}... ({len(seed_phrase.split())} words)")
    
    # Generate addresses
    print("\n4. Generating addresses...")
    dual_address = wallet.get_dual_address(None)
    single_address = wallet.get_single_address()
    print(f"   Dual address: {dual_address[:50]}...")
    print(f"   Single address: {single_address[:50]}...")
    
    # Generate address with payment ID
    payment_id = [1, 2, 3, 4, 5, 6, 7, 8]
    dual_with_payment = wallet.get_dual_address(payment_id)
    print(f"   Dual with payment: {dual_with_payment[:50]}...")
    
    # Message signing example
    print("\n5. Message signing example...")
    message = "Hello from Tari Python bindings!"
    print(f"   Message: {message}")
    
    signature_result = wallet.sign_message(message)
    print(f"   Signature: {signature_result['signature'][:32]}...")
    print(f"   Nonce: {signature_result['nonce'][:32]}...")
    print(f"   Public Key: {signature_result['public_key'][:32]}...")
    
    # Verify the signature
    is_valid = wallet.verify_message(
        message,
        signature_result['signature'],
        signature_result['nonce'],
        signature_result['public_key']
    )
    print(f"   Signature valid: {is_valid}")
    
    # Test with wrong message
    wrong_is_valid = wallet.verify_message(
        "Wrong message",
        signature_result['signature'],
        signature_result['nonce'],
        signature_result['public_key']
    )
    print(f"   Wrong message valid: {wrong_is_valid}")
    
    # Blockchain scanner example
    print("\n6. Blockchain scanner example...")
    scanner = lightweight_wallet_libpy.TariScanner("http://127.0.0.1:18142", wallet)
    print(f"   Scanner created for base node: http://127.0.0.1:18142")
    
    # Get tip height (placeholder)
    tip_height = scanner.get_tip_height()
    print(f"   Tip height: {tip_height}")
    
    # Scan some blocks (placeholder)
    print("   Scanning blocks 1000-1010...")
    scan_result = scanner.scan_blocks(1000, 1010)
    print(f"   {scan_result}")
    
    # Get balance (placeholder)
    balance = scanner.get_balance()
    print(f"   {balance}")
    
    # Multiple wallets example
    print("\n7. Multiple wallets example...")
    wallet2 = lightweight_wallet_libpy.TariWallet.generate_new_with_seed_phrase()
    wallet2.set_label("Second Wallet")
    
    # Different wallets should produce different signatures
    message2 = "Test cross-wallet signatures"
    sig1 = wallet.sign_message(message2)
    sig2 = wallet2.sign_message(message2)
    
    print(f"   Wallet 1 public key: {sig1['public_key'][:32]}...")
    print(f"   Wallet 2 public key: {sig2['public_key'][:32]}...")
    print(f"   Keys are different: {sig1['public_key'] != sig2['public_key']}")
    
    # Cross-verification (should work with correct public key)
    cross_valid = wallet.verify_message(
        message2,
        sig2['signature'],
        sig2['nonce'],
        sig2['public_key']  # Using wallet2's public key
    )
    print(f"   Cross-verification valid: {cross_valid}")
    
    # Properties access
    print("\n8. Wallet properties...")
    print(f"   Label: {wallet.label()}")
    print(f"   Network: {wallet.network()}")
    print(f"   Birthday: {wallet.birthday()}")
    print(f"   Key index: {wallet.current_key_index()}")
    print(f"   Environment property: {wallet.get_property('environment')}")
    
    # Unicode message signing
    print("\n9. Unicode message signing...")
    unicode_message = "Hello 世界! 🚀 Tari cryptocurrency ₿"
    unicode_sig = wallet.sign_message(unicode_message)
    unicode_valid = wallet.verify_message(
        unicode_message,
        unicode_sig['signature'],
        unicode_sig['nonce'],
        unicode_sig['public_key']
    )
    print(f"   Unicode message: {unicode_message}")
    print(f"   Unicode signature valid: {unicode_valid}")
    
    print("\n✅ All examples completed successfully!")
    print("\nNote: Blockchain scanning operations use placeholder implementations.")
    print("Real blockchain scanning requires async implementation to be completed.")


if __name__ == "__main__":
    main()
