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
    print("\n11. Python help() system integration...")
    print("   The updated API provides proper signatures visible in Python help:")
    print("   - help(wallet.get_dual_address) shows: (features, payment_id=None)")
    print("   - help(wallet.get_single_address) shows: (features)")
    print("   - help(lightweight_wallet_libpy.TariScanner) shows constructor signature")
    print("   - help(lightweight_wallet_libpy.TariKeyManager) shows key derivation methods")
    print("   - help(lightweight_wallet_libpy.TariStealthAddress) shows stealth operations")
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
    
    # Stealth Address example
    print("\n10. Stealth Address functionality example...")
    
    try:
        # Key management for stealth addresses
        print("   Creating key manager from wallet...")
        key_manager = lightweight_wallet_libpy.TariKeyManager.from_wallet(wallet)
        
        # Derive view and spend keys
        keys = key_manager.derive_view_and_spend_keys()
        print(f"   Derived view key: {keys['view_key'][:16]}...")
        print(f"   Derived spend key: {keys['spend_key'][:16]}...")
        
        # Create stealth address service
        print("   Creating stealth address service...")
        stealth_service = lightweight_wallet_libpy.TariStealthAddress()
        
        # Generate shared secret (Diffie-Hellman)
        sender_private_key = "deadbeef" * 8  # Mock sender private key
        sender_public_key = "cafebabe" * 8   # Mock sender public key
        shared_secret = stealth_service.generate_shared_secret(sender_private_key, sender_public_key)
        print(f"   Generated shared secret: {shared_secret[:16]}...")
        
        # Create stealth address
        print("   Creating stealth address...")
        stealth_addr = stealth_service.create_stealth_address(
            keys['view_key'],
            keys['spend_key'], 
            sender_private_key
        )
        
        print(f"   Stealth address info:")
        print(f"     View public key: {stealth_addr.view_public_key[:16]}...")
        print(f"     Spend public key: {stealth_addr.spend_public_key[:16]}...")
        print(f"     Stealth spending key: {stealth_addr.stealth_spending_key[:16]}...")
        print(f"     Sender offset key: {stealth_addr.sender_offset_public_key[:16]}...")
        
        # Mock output scanning (will return empty results with mock data)
        print("   Scanning mock outputs...")
        mock_outputs = [
            {"sender_offset": "deadbeef" * 8, "script_key": "cafebabe" * 8},
            {"sender_offset": "12345678" * 8, "script_key": "87654321" * 8}
        ]
        
        scan_result = stealth_service.scan_for_outputs(
            keys['view_key'],
            keys['spend_key'],
            mock_outputs
        )
        
        print(f"   Scan result: {scan_result}")
        print(f"   Total scanned: {scan_result.total_scanned}")
        print(f"   Addresses found: {scan_result.addresses_found}")
        print(f"   Success: {scan_result.is_successful()}")
        
        # Key derivation examples
        print("   Key derivation examples...")
        derivation_path = lightweight_wallet_libpy.KeyDerivationPath.from_string("m/44'/0'/1")
        print(f"   Derivation path: {derivation_path}")
        
        # Set custom entropy and derive key
        key_manager.set_entropy("0123456789abcdef" * 2)
        derived_key = key_manager.derive_key_from_path(derivation_path)
        print(f"   Derived key from path: {derived_key[:16]}...")
        
    except Exception as e:
        print(f"   Stealth address example failed: {e}")
        print("   This is expected if stealth address modules are not available")

    print("\n✅ All examples completed successfully!")
    print("\nNote: Blockchain scanning operations use placeholder implementations.")
    print("Real blockchain scanning requires async implementation to be completed.")
    print("\nSimplified API Summary:")
    print("- Core stealth address functionality through TariStealthAddress")
    print("- Key derivation via TariKeyManager with hierarchical path support")
    print("- Stealth address generation, key recovery, and output scanning")
    print("- Fixed chunking (1000 items) for memory-efficient batch processing")
    print("- Removed Python-specific convenience methods for API purity")
    print("- Direct mapping to Rust core functionality for security")
    print("- get_dual_address/get_single_address require AddressFeatures parameter")
    print("- TariBalance provides Rust-native balance calculation with storage")
    print("- PyO3 help() integration shows proper method signatures")
    print("\nStealth Address Features:")
    print("- create_stealth_address(): Generate stealth addresses from keys")
    print("- recover_stealth_key(): Attempt key recovery from outputs")
    print("- scan_for_outputs(): Batch scan outputs with fixed chunking")
    print("- generate_shared_secret(): Diffie-Hellman key agreement")
    print("- Memory-efficient processing without configurable chunk sizes")
    print("- Error handling for invalid inputs and mock data scenarios")


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


def enhanced_utxo_validation_example():
    """
    Demonstrate enhanced UTXO validation capabilities with ownership detection,
    script pattern filtering, and batch processing.
    """
    print("\n=== Enhanced UTXO Validation Example ===")
    
    try:
        # Import enhanced validation classes
        from lightweight_wallet_libpy import (
            TariUTXOValidator, UTXOValidationConfig, TariUTXOBatchValidator,
            UTXOFilter, PyScriptPattern
        )
        
        print("\n1. Creating UTXO validator configuration...")
        
        # Create validation configuration
        config = UTXOValidationConfig(
            validate_ownership=True,
            extract_values=True,
            extract_payment_ids=True,
            validate_range_proofs=True
        )
        print(f"   Configuration: {config}")
        
        # Mock wallet keys for demonstration
        view_key = "a" * 64  # 32 bytes as hex
        spend_key = "b" * 64  # 32 bytes as hex
        
        print("\n2. Creating UTXO validator...")
        validator = TariUTXOValidator(view_key, spend_key, config)
        print(f"   Validator: {validator}")
        
        print("\n3. Enhanced UTXO filtering with validation integration...")
        
        # Create enhanced filter with multiple criteria
        enhanced_filter = (UTXOFilter()
                          .with_wallet_id(1)
                          .with_value_range(1000000, 10000000)  # 1-10 Tari
                          .by_ownership(True)
                          .by_maturity_at_height(100000)
                          .by_script_pattern(PyScriptPattern.Standard())
                          .validate_before_filter(True)
                          .set_validator(validator)
                          .with_limit(50))
        
        print(f"   Enhanced filter: {enhanced_filter}")
        
        print("\n4. Script pattern filtering options...")
        patterns = [
            PyScriptPattern.Standard(),
            PyScriptPattern.UnrecognizedOneSided(),
            PyScriptPattern.UnrecognizedStealth(),
            PyScriptPattern.Unknown()
        ]
        
        for pattern in patterns:
            filter_for_pattern = UTXOFilter().by_script_pattern(pattern)
            print(f"   - {pattern}: Filter configured")
        
        print("\n5. Batch validation setup...")
        batch_validator = TariUTXOBatchValidator(chunk_size=1000)
        print(f"   Batch validator chunk size: {batch_validator.chunk_size}")
        
        # Mock UTXO data for demonstration
        mock_utxos = [
            {
                "commitment": "a" * 64,
                "range_proof": "b" * 128,
                "encrypted_data": "c" * 256,
            }
        ]
        
        print("\n6. Single UTXO validation (mock data)...")
        try:
            result = validator.validate_utxo(mock_utxos[0])
            print(f"   Validation result: {result}")
        except Exception as e:
            print(f"   Expected validation failure with mock data: {type(e).__name__}")
        
        print("\n✓ Enhanced UTXO validation features demonstrated")
        print("\nKey features:")
        print("- Enhanced filtering with ownership validation")
        print("- Script pattern filtering for output types")
        print("- Maturity-based filtering for spendable outputs")
        print("- Batch validation with memory-efficient chunking")
        print("- Integration with existing storage and UTXO management")
        
    except ImportError as e:
        print(f"Enhanced validation modules not available: {e}")
        print("Make sure the wallet library is built with enhanced UTXO validation support")


def demonstrate_extraction_functionality():
    """Demonstrate UTXO extraction and batch validation functionality."""
    print("Testing extraction functionality with mock data...")
    
    try:
        # Create extraction configuration
        print("\n  Creating extraction configuration...")
        config = lightweight_wallet_libpy.TariExtractionConfig()
        
        # Set extraction options
        config.set_enable_key_derivation(True)
        config.set_validate_range_proofs(True)
        config.set_validate_signatures(False)  # Disable for performance
        config.set_handle_special_outputs(True)
        config.set_detect_corruption(True)
        
        print(f"    Config: {config}")
        
        # Create private key for extraction
        test_private_key = b'a' * 32  # 32-byte test key
        config.set_private_key(test_private_key)
        print("    Set private key for extraction")
        
        # Create decryption options
        print("\n  Creating decryption options...")
        decryption_options = lightweight_wallet_libpy.DecryptionOptions()
        decryption_options.set_try_all_keys(True)
        decryption_options.set_validate_decrypted_data(True)
        decryption_options.set_max_keys_to_try(5)  # Limit for security
        decryption_options.set_return_partial_results(False)
        
        print(f"    Options: {decryption_options}")
        
        # Create batch validation options
        print("\n  Creating batch validation options...")
        batch_options = lightweight_wallet_libpy.BatchValidationOptions()
        batch_options.set_continue_on_error(True)
        batch_options.set_max_errors_per_output(3)
        batch_options.set_validate_range_proofs(True)
        batch_options.set_validate_signatures(False)  # Performance
        batch_options.set_validate_commitments(True)
        
        print(f"    Batch options: {batch_options}")
        
        # Test batch validation with empty list (should succeed)
        print("\n  Testing batch validation with empty list...")
        try:
            empty_outputs = []
            result = lightweight_wallet_libpy.validate_output_batch(empty_outputs, batch_options)
            print(f"    Empty batch validation: {result}")
            print(f"    Valid: {result.is_valid}")
            print(f"    Summary: {result.summary}")
        except Exception as e:
            print(f"    Empty batch validation not supported: {e}")
        
        # Test extraction configuration creation methods
        print("\n  Testing configuration creation methods...")
        
        # Test with_private_key
        try:
            config_with_private_key = lightweight_wallet_libpy.TariExtractionConfig.with_private_key(test_private_key)
            print("    ✓ with_private_key() works")
        except Exception as e:
            print(f"    ✗ with_private_key() failed: {e}")
        
        # Test with_public_key
        try:
            test_public_key = b'b' * 32  # 32-byte test key
            config_with_public_key = lightweight_wallet_libpy.TariExtractionConfig.with_public_key(test_public_key)
            print("    ✓ with_public_key() works")
        except Exception as e:
            print(f"    ✗ with_public_key() failed: {e}")
        
        # Test custom decryption options
        print("\n  Testing custom decryption options...")
        try:
            custom_options = lightweight_wallet_libpy.DecryptionOptions.with_options(
                try_all_keys=False,
                validate_decrypted_data=True,
                max_keys_to_try=3,
                return_partial_results=True
            )
            print(f"    Custom options: {custom_options}")
            print("    ✓ Custom decryption options work")
        except Exception as e:
            print(f"    ✗ Custom decryption options failed: {e}")
        
        # Test custom batch validation options
        print("\n  Testing custom batch validation options...")
        try:
            custom_batch_options = lightweight_wallet_libpy.BatchValidationOptions.with_options(
                continue_on_error=False,
                max_errors_per_output=1,
                validate_range_proofs=False,
                validate_signatures=False,
                validate_commitments=True
            )
            print(f"    Custom batch options: {custom_batch_options}")
            print("    ✓ Custom batch validation options work")
        except Exception as e:
            print(f"    ✗ Custom batch validation options failed: {e}")
        
        # Test error handling
        print("\n  Testing error handling...")
        
        # Test invalid key length
        try:
            invalid_key = b'short'  # Invalid length
            lightweight_wallet_libpy.TariExtractionConfig.with_private_key(invalid_key)
            print("    ✗ Invalid key validation failed")
        except Exception as e:
            print(f"    ✓ Invalid key properly rejected: {type(e).__name__}")
        
        # Check for parallel validation function
        print("\n  Checking for parallel validation support...")
        if hasattr(lightweight_wallet_libpy, 'validate_output_batch_parallel'):
            print("    ✓ Parallel batch validation available (grpc feature enabled)")
            try:
                empty_outputs = []
                result = lightweight_wallet_libpy.validate_output_batch_parallel(empty_outputs, batch_options)
                print(f"    Parallel validation result: {result}")
            except Exception as e:
                print(f"    Parallel validation test failed: {e}")
        else:
            print("    ℹ Parallel batch validation not available (grpc feature disabled)")
        
        print("\n  ✓ Extraction functionality demonstration completed")
        
    except Exception as e:
        print(f"  ✗ Extraction functionality demonstration failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
    
    # Run extraction examples
    print("\n=== 11. Extraction Functionality ===")
    demonstrate_extraction_functionality()
    
    # Uncomment to run validation examples
    # chunked_validation_example()
    # enhanced_utxo_validation_example()
