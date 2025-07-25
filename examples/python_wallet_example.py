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
    
    print("   Note: Scanner requires a running Tari base node on localhost:18142")
    
    try:
        # Get tip height
        tip_height = scanner.get_tip_height()
        print(f"   Tip height: {tip_height}")
        
        # Scan some blocks
        print("   Scanning blocks 1000-1010...")
        scan_result = scanner.scan_blocks(1000, 1010)
        print(f"   {scan_result}")
        
        # Note: Balance API now requires storage integration
        print("   Balance calculation requires storage (see storage example below)")
        
    except Exception as e:
        if "connection" in str(e).lower() or "failed to connect" in str(e).lower():
            print(f"   ⚠️  Connection failed (expected if no node running): {str(e)[:80]}...")
            print("   Scanner API is working but requires a running Tari base node")
        else:
            raise
    
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
    
    # Storage and Balance example
    print("\n9. Storage and Balance integration example...")
    
    # Create storage instance
    print("   Creating storage instance...")
    storage = lightweight_wallet_libpy.TariWalletStorage("example_wallet.db")
    storage.initialize()
    
    # Save a wallet to storage  
    print("   Saving wallet to storage...")
    wallet_dict = {
        "name": "Example Wallet",
        "seed_phrase": seed_phrase,
        "view_key_hex": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "spend_key_hex": "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
        "birthday_block": 100000,
        "scan_from_block": 100000
    }
    wallet_id = storage.save_wallet(wallet_dict)
    print(f"   Saved wallet with ID: {wallet_id}")
    
    # Create balance instance using storage
    print("   Creating balance instance...")
    balance = lightweight_wallet_libpy.TariBalance(storage, wallet_id)
    print(f"   {balance}")
    
    # Access balance methods
    print("   Balance methods:")
    print(f"     Running balance: {balance.get_running_balance()}")
    print(f"     Available balance: {balance.available()}")
    print(f"     Pending balance: {balance.pending()}")
    print(f"     Immature balance: {balance.immature()}")
    print(f"     Total balance: {balance.total()}")
    
    # Get detailed stats
    stats = balance.get_stats()
    print(f"   Balance stats: received={stats[0]}, spent={stats[1]}, balance={stats[2]}, unspent_count={stats[3]}, spent_count={stats[4]}")
    
    # Clean up storage
    storage.close()
    print("   Storage closed")

    print("\n✅ All examples completed successfully!")
    print("\nNote: Blockchain scanning operations use placeholder implementations.")
    print("Real blockchain scanning requires async implementation to be completed.")
    print("\nAPI Changes Summary:")
    print("- OLD Balance struct removed from scanner")
    print("- NEW TariBalance class provides Rust-native balance calculation")
    print("- get_dual_address now requires AddressFeatures parameter")
    print("- get_single_address now requires AddressFeatures parameter") 
    print("- AddressFeatures provides type-safe feature selection")
    print("- Balance calculation now requires storage integration")
    print("- TariBalance uses actual WalletState.running_balance")
    print("- Constructor documentation improved with PyO3 signatures")


def chunked_validation_example():
    """
    Demonstrate chunked batch validation for memory-efficient processing
    of large datasets.
    """
    print("\n=== Chunked Validation Example ===\n")
    
    try:
        # Import validation classes
        from lightweight_wallet_libpy import (
            TariCommitmentValidator, 
            TariRangeProofValidator,
            TariSignatureValidator,
            TariEncryptedDataValidator
        )
        
        print("1. Memory-efficient commitment validation...")
        validator = TariCommitmentValidator()
        
        # Generator for memory-efficient data generation
        def generate_commitment_chunks(total_count, chunk_size=1000):
            """Generate commitment data in chunks to demonstrate memory efficiency."""
            for start in range(0, total_count, chunk_size):
                end = min(start + chunk_size, total_count)
                chunk = [f"08{'12' * 31}" for _ in range(end - start)]  # Mock commitments
                yield chunk, end - start
        
        # Process large dataset in chunks
        total_processed = 0
        total_items = 5000
        
        print(f"   Processing {total_items} commitments in chunks...")
        
        for chunk_data, chunk_size in generate_commitment_chunks(total_items, chunk_size=500):
            try:
                # Use chunked validation with custom chunk size for memory management
                result = validator.batch_validate_commitments(chunk_data, chunk_size=100)
                total_processed += result.total_count
                print(f"   Processed chunk: {result.total_count} items (Total: {total_processed})")
            except Exception as e:
                print(f"   Chunk validation failed (expected for mock data): {e}")
                total_processed += chunk_size  # Count as processed for demo
        
        print(f"   Total processed: {total_processed} items")
        
        print("\n2. Range proof validation with chunking...")
        range_validator = TariRangeProofValidator()
        
        # Generate mock range proof data
        proof_commitment_pairs = [
            ("deadbeef" * 64, "08" + "12" * 31) for _ in range(1000)
        ]
        minimum_values = [1000] * 1000
        
        try:
            # Use small chunks for memory efficiency
            result = range_validator.batch_validate_range_proofs(
                proof_commitment_pairs[:100],  # Use smaller dataset for demo
                minimum_values[:100],
                chunk_size=25  # Very small chunks
            )
            print(f"   Range proofs processed: {result.total_count}")
        except Exception as e:
            print(f"   Range proof validation failed (expected for mock data): {e}")
        
        print("\n3. Signature validation with chunking...")
        sig_validator = TariSignatureValidator()
        
        # Generate mock signature data
        signature_data = [
            ("deadbeef" * 8, "cafebabe" * 8, f"Message {i}", "12345678" * 8)
            for i in range(200)
        ]
        
        try:
            # Process with custom chunk size
            result = sig_validator.batch_validate_signatures(signature_data, chunk_size=50)
            print(f"   Signatures processed: {result.total_count}")
        except Exception as e:
            print(f"   Signature validation failed (expected for mock data): {e}")
        
        print("\n4. Encrypted data validation with chunking...")
        enc_validator = TariEncryptedDataValidator()
        
        # Generate mock encrypted data
        encrypted_data = [f"deadbeef{'12' * 31}" for _ in range(300)]
        
        try:
            # Process with chunking
            result = enc_validator.batch_validate_encrypted_data(encrypted_data, chunk_size=75)
            print(f"   Encrypted data items processed: {result.total_count}")
        except Exception as e:
            print(f"   Encrypted data validation failed (expected for mock data): {e}")
        
        print("\n=== Chunked Validation Best Practices ===")
        print("- Use generators to avoid loading large datasets into memory")
        print("- Configure chunk sizes based on available memory (default: 1000)")
        print("- Smaller chunks reduce memory usage but may increase overhead")
        print("- Process chunks sequentially for predictable memory usage")
        print("- Monitor memory usage and adjust chunk sizes accordingly")
        print("- Use chunked validation for datasets > 10,000 items")
        
    except ImportError as e:
        print(f"Validation modules not available: {e}")
        print("Make sure the wallet library is built with validation support")


if __name__ == "__main__":
    main()
    
    # Uncomment to run chunked validation example
    # chunked_validation_example()
