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
    
    # Generate addresses with different features
    print("\n4. Generating addresses with address features...")
    
    # Create different address features
    interactive_and_one_sided = lightweight_wallet_libpy.AddressFeatures.interactive_and_one_sided()
    interactive_only = lightweight_wallet_libpy.AddressFeatures.interactive_only()
    one_sided_only = lightweight_wallet_libpy.AddressFeatures.one_sided_only()
    
    print(f"   Address features available:")
    print(f"     - {interactive_and_one_sided}")
    print(f"     - {interactive_only}")
    print(f"     - {one_sided_only}")
    
    # Generate dual address (supports both interactive and one-sided payments)
    dual_address = wallet.get_dual_address(interactive_and_one_sided, None)
    print(f"   Dual address (interactive + one-sided): {dual_address[:50]}...")
    
    # Generate single addresses with different features
    single_interactive = wallet.get_single_address(interactive_only)
    single_one_sided = wallet.get_single_address(one_sided_only)
    print(f"   Single address (interactive only): {single_interactive[:50]}...")
    print(f"   Single address (one-sided only): {single_one_sided[:50]}...")
    
    # Generate address with payment ID
    payment_id = [1, 2, 3, 4, 5, 6, 7, 8]
    dual_with_payment = wallet.get_dual_address(interactive_and_one_sided, payment_id)
    print(f"   Dual with payment ID: {dual_with_payment[:50]}...")
    
    # Show that different features produce different addresses
    print(f"   Different features produce different addresses:")
    print(f"     - Interactive+One-sided != Interactive-only: {dual_address != single_interactive}")
    print(f"     - Interactive-only != One-sided-only: {single_interactive != single_one_sided}")
    print(f"     - With payment ID != without: {dual_address != dual_with_payment}")
    
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
    
    # Python help() system integration example
    print("\n10. Python help() system integration...")
    print("   The updated API provides proper signatures visible in Python help:")
    print("   - help(wallet.get_dual_address) shows: (features, payment_id=None)")
    print("   - help(wallet.get_single_address) shows: (features)")
    print("   - help(lightweight_wallet_libpy.TariScanner) shows constructor signature")
    print("   Try running help() on these methods in an interactive Python session!")
    
    print("\n✅ All examples completed successfully!")
    print("\nNote: Blockchain scanning operations use placeholder implementations.")
    print("Real blockchain scanning requires async implementation to be completed.")
    print("\nAPI Changes Summary:")
    print("- get_dual_address now requires AddressFeatures parameter")
    print("- get_single_address now requires AddressFeatures parameter") 
    print("- AddressFeatures provides type-safe feature selection")
    print("- Constructor documentation improved with PyO3 signatures")


if __name__ == "__main__":
    main()
