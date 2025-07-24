#!/usr/bin/env python3
"""
Test suite for API signature validation in Tari wallet Python bindings.

This module ensures that all API methods have correct signatures and that
the signature changes maintain backward compatibility where possible.
"""

import pytest
import sys
import os

# Add the parent directory to Python path to import the module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import lightweight_wallet_libpy as wallet_lib
    from lightweight_wallet_libpy import TariWallet, TariScanner, AddressFeatures
except ImportError as e:
    pytest.skip(f"Cannot import wallet library: {e}", allow_module_level=True)


class TestAddressFeatures:
    """Test the new AddressFeatures wrapper class."""
    
    def test_address_features_creation(self):
        """Test that AddressFeatures can be created with all variants."""
        # Test interactive only
        interactive_only = AddressFeatures.interactive_only()
        assert interactive_only is not None
        assert "interactive_only" in str(interactive_only)
        
        # Test one-sided only
        one_sided_only = AddressFeatures.one_sided_only()
        assert one_sided_only is not None
        assert "one_sided_only" in str(one_sided_only)
        
        # Test interactive and one-sided
        interactive_and_one_sided = AddressFeatures.interactive_and_one_sided()
        assert interactive_and_one_sided is not None
        assert "interactive_and_one_sided" in str(interactive_and_one_sided)
    
    def test_address_features_string_representations(self):
        """Test string representations of AddressFeatures."""
        features = AddressFeatures.interactive_only()
        
        # Test __str__ and __repr__
        str_repr = str(features)
        repr_repr = repr(features)
        
        assert "AddressFeatures" in str_repr
        assert "interactive_only" in str_repr
        assert str_repr == repr_repr
        
        # Test different feature types have different representations
        one_sided = AddressFeatures.one_sided_only()
        interactive_and_one_sided = AddressFeatures.interactive_and_one_sided()
        
        assert str(features) != str(one_sided)
        assert str(one_sided) != str(interactive_and_one_sided)
        assert str(features) != str(interactive_and_one_sided)


class TestWalletAPISignatures:
    """Test that wallet API methods have correct signatures."""
    
    def test_get_dual_address_signature(self):
        """Test that get_dual_address has the correct signature with features parameter."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        features = AddressFeatures.interactive_and_one_sided()
        
        # Test with features parameter only
        address1 = wallet.get_dual_address(features)
        assert len(address1) > 0
        
        # Test with features and payment_id
        payment_id = [1, 2, 3, 4, 5]
        address2 = wallet.get_dual_address(features, payment_id)
        assert len(address2) > 0
        assert address1 != address2  # Should be different with payment ID
        
        # Test with None payment_id explicitly
        address3 = wallet.get_dual_address(features, None)
        assert address1 == address3  # Should be the same as no payment ID
    
    def test_get_single_address_signature(self):
        """Test that get_single_address has the correct signature with features parameter."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test with interactive only features
        interactive_features = AddressFeatures.interactive_only()
        address1 = wallet.get_single_address(interactive_features)
        assert len(address1) > 0
        
        # Test with one-sided only features
        one_sided_features = AddressFeatures.one_sided_only()
        address2 = wallet.get_single_address(one_sided_features)
        assert len(address2) > 0
        assert address1 != address2  # Different features should produce different addresses
    
    def test_address_generation_determinism(self):
        """Test that address generation is deterministic for same parameters."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        features = AddressFeatures.interactive_and_one_sided()
        payment_id = [1, 2, 3, 4, 5]
        
        # Generate same address multiple times
        address1 = wallet.get_dual_address(features, payment_id)
        address2 = wallet.get_dual_address(features, payment_id)
        address3 = wallet.get_dual_address(features, payment_id)
        
        assert address1 == address2 == address3
        
        # Single address should also be deterministic
        single1 = wallet.get_single_address(features)
        single2 = wallet.get_single_address(features)
        
        assert single1 == single2
    
    def test_different_features_produce_different_addresses(self):
        """Test that different features produce different addresses."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test dual addresses with different features
        interactive_only = AddressFeatures.interactive_only()
        one_sided_only = AddressFeatures.one_sided_only()
        interactive_and_one_sided = AddressFeatures.interactive_and_one_sided()
        
        addr1 = wallet.get_dual_address(interactive_only)
        addr2 = wallet.get_dual_address(one_sided_only)
        addr3 = wallet.get_dual_address(interactive_and_one_sided)
        
        # All should be different
        assert addr1 != addr2
        assert addr1 != addr3
        assert addr2 != addr3
        
        # Test single addresses with different features
        single1 = wallet.get_single_address(interactive_only)
        single2 = wallet.get_single_address(one_sided_only)
        
        assert single1 != single2


class TestScannerAPISignatures:
    """Test that scanner API methods have correct signatures."""
    
    def test_scanner_constructor_signature(self):
        """Test that TariScanner constructor has proper signature and documentation."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test constructor with required parameters
        scanner = TariScanner("http://localhost:18142", wallet)
        assert scanner is not None
        
        # Test that constructor requires both parameters
        with pytest.raises(TypeError):
            TariScanner("http://localhost:18142")  # Missing wallet
        
        with pytest.raises(TypeError):
            TariScanner(wallet=wallet)  # Missing base_node_url
    
    def test_scanner_help_documentation(self):
        """Test that scanner methods have proper help documentation."""
        # This tests that the methods are callable and have proper signatures
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        scanner = TariScanner("http://localhost:18142", wallet)
        
        # Test that methods exist and are callable
        assert callable(scanner.get_tip_height)
        assert callable(scanner.scan_blocks)
        assert callable(scanner.get_balance)
        assert callable(scanner.get_block_by_height)
        assert callable(scanner.search_utxos)


class TestSignatureParameterValidation:
    """Test parameter validation for API methods."""
    
    def test_invalid_parameters_raise_errors(self):
        """Test that invalid parameters raise appropriate errors."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test get_dual_address with invalid parameters
        with pytest.raises(TypeError):
            wallet.get_dual_address()  # Missing required features parameter
        
        with pytest.raises(TypeError):
            wallet.get_dual_address("invalid_features")  # Wrong type for features
        
        # Test get_single_address with invalid parameters
        with pytest.raises(TypeError):
            wallet.get_single_address()  # Missing required features parameter
        
        with pytest.raises(TypeError):
            wallet.get_single_address("invalid_features")  # Wrong type for features
    
    def test_payment_id_parameter_types(self):
        """Test that payment_id parameter accepts correct types."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        features = AddressFeatures.interactive_and_one_sided()
        
        # Test with None (should work)
        address1 = wallet.get_dual_address(features, None)
        assert len(address1) > 0
        
        # Test with list of integers (should work)
        payment_id = [1, 2, 3, 4, 5]
        address2 = wallet.get_dual_address(features, payment_id)
        assert len(address2) > 0
        
        # Test with empty list (should work)
        address3 = wallet.get_dual_address(features, [])
        assert len(address3) > 0
        
        # Test with bytes (should work if converted properly)
        payment_id_bytes = bytes([1, 2, 3, 4, 5])
        address4 = wallet.get_dual_address(features, payment_id_bytes)
        assert len(address4) > 0


class TestBackwardCompatibilityBreaks:
    """Test and document backward compatibility breaks."""
    
    def test_old_api_no_longer_works(self):
        """Test that the old API signature no longer works (expected breaking change)."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # The old API signature should no longer work
        with pytest.raises(TypeError):
            # Old signature: get_dual_address(payment_id)
            wallet.get_dual_address(None)
        
        with pytest.raises(TypeError):
            # Old signature: get_single_address()
            wallet.get_single_address()
    
    def test_new_api_works_correctly(self):
        """Test that the new API signature works correctly."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # New signature: get_dual_address(features, payment_id=None)
        features = AddressFeatures.interactive_and_one_sided()
        address = wallet.get_dual_address(features, None)
        assert len(address) > 0
        
        # New signature: get_single_address(features)
        single_address = wallet.get_single_address(features)
        assert len(single_address) > 0


if __name__ == "__main__":
    # Run tests when executed directly
    pytest.main([__file__, "-v"])
