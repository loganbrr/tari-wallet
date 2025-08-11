#!/usr/bin/env python3
"""
Test suite for TariAddressFeatures wrapper class functionality.

This module tests the new TariAddressFeatures Python wrapper and ensures
proper type safety and feature selection for address generation.
"""

import pytest
import sys
import os

# Add the parent directory to Python path to import the module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import lightweight_wallet_libpy as wallet_lib
    from lightweight_wallet_libpy import TariWallet, TariAddressFeatures, Network
except ImportError as e:
    pytest.skip(f"Cannot import wallet library: {e}", allow_module_level=True)


class TestTariAddressFeaturesCreation:
    """Test TariAddressFeatures creation methods."""
    
    def test_interactive_only_creation(self):
        """Test creating interactive-only address features."""
        features = TariAddressFeatures.interactive_only()
        assert features is not None
        
        # Test string representation
        str_repr = str(features)
        assert "TariAddressFeatures" in str_repr
        assert "interactive=true" in str_repr and "one_sided=false" in str_repr
        
        # Test repr
        repr_str = repr(features)
        assert "bits=" in repr_str
    
    def test_one_sided_only_creation(self):
        """Test creating one-sided-only address features."""
        features = TariAddressFeatures.one_sided_only()
        assert features is not None
        
        # Test string representation
        str_repr = str(features)
        assert "TariAddressFeatures" in str_repr
        assert "interactive=false" in str_repr and "one_sided=true" in str_repr
    
    def test_interactive_and_one_sided_creation(self):
        """Test creating interactive and one-sided address features."""
        features = TariAddressFeatures.interactive_and_one_sided()
        assert features is not None
        
        # Test string representation
        str_repr = str(features)
        assert "TariAddressFeatures" in str_repr
        assert "interactive=true" in str_repr and "one_sided=true" in str_repr
    
    def test_different_features_have_different_representations(self):
        """Test that different feature types have distinct string representations."""
        interactive_only = TariAddressFeatures.interactive_only()
        one_sided_only = TariAddressFeatures.one_sided_only()
        interactive_and_one_sided = TariAddressFeatures.interactive_and_one_sided()
        
        # All should have different string representations
        assert str(interactive_only) != str(one_sided_only)
        assert str(interactive_only) != str(interactive_and_one_sided)
        assert str(one_sided_only) != str(interactive_and_one_sided)


class TestTariAddressFeaturesWithWallet:
    """Test TariAddressFeatures integration with wallet address generation."""
    
    def test_dual_address_with_different_features(self):
        """Test dual address generation with different features."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        wallet.set_network(Network.mainnet())
        
        # Test with each feature type
        interactive_only = TariAddressFeatures.interactive_only()
        one_sided_only = TariAddressFeatures.one_sided_only()
        interactive_and_one_sided = TariAddressFeatures.interactive_and_one_sided()
        
        addr1 = wallet.get_dual_address(interactive_only, None)
        addr2 = wallet.get_dual_address(one_sided_only, None)
        addr3 = wallet.get_dual_address(interactive_and_one_sided, None)
        
        # All addresses should be valid hex strings
        assert len(addr1.to_hex()) > 0
        assert len(addr2.to_hex()) > 0
        assert len(addr3.to_hex()) > 0
        
        # All addresses should be different
        assert addr1.to_hex() != addr2.to_hex()
        assert addr1.to_hex() != addr3.to_hex()
        assert addr2.to_hex() != addr3.to_hex()
    
    def test_single_address_with_different_features(self):
        """Test single address generation with different features."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        wallet.set_network(Network.mainnet())
        
        # Test with features that make sense for single addresses
        interactive_only = TariAddressFeatures.interactive_only()
        one_sided_only = TariAddressFeatures.one_sided_only()
        
        addr1 = wallet.get_single_address(interactive_only)
        addr2 = wallet.get_single_address(one_sided_only)
        
        # Both addresses should be valid
        assert len(addr1.to_hex()) > 0
        assert len(addr2.to_hex()) > 0
        
        # Addresses should be different
        assert addr1.to_hex() != addr2.to_hex()
    
    def test_deterministic_address_generation(self):
        """Test that same features produce same addresses."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        wallet.set_network(Network.mainnet())
        features = TariAddressFeatures.interactive_and_one_sided()
        
        # Generate same address multiple times
        addr1 = wallet.get_dual_address(features, None)
        addr2 = wallet.get_dual_address(features, None)
        addr3 = wallet.get_dual_address(features, None)
        
        # All should be identical
        assert addr1.to_hex() == addr2.to_hex() == addr3.to_hex()
        
        # Same for single addresses
        single1 = wallet.get_single_address(features)
        single2 = wallet.get_single_address(features)
        
        assert single1.to_hex() == single2.to_hex()
    
    def test_features_with_payment_id(self):
        """Test address features with payment IDs."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        wallet.set_network(Network.mainnet())
        features = TariAddressFeatures.interactive_and_one_sided()
        
        payment_id = [1, 2, 3, 4, 5]
        
        # Address without payment ID
        addr_no_payment = wallet.get_dual_address(features, None)
        
        # Address with payment ID
        import binascii
        pid_bytes = bytes(payment_id)
        addr_with_payment = wallet.get_dual_address(features, pid_bytes)
        
        # Should be different
        assert addr_no_payment.to_hex() != addr_with_payment.to_hex()
        
        # Same payment ID should produce same address
        addr_with_payment2 = wallet.get_dual_address(features, pid_bytes)
        assert addr_with_payment.to_hex() == addr_with_payment2.to_hex()


class TestTariAddressFeaturesEdgeCases:
    """Test edge cases and error conditions for TariAddressFeatures."""
    
    def test_features_can_be_reused(self):
        """Test that TariAddressFeatures objects can be reused across wallets."""
        wallet1 = TariWallet.generate_new_with_seed_phrase(None)
        wallet1.set_network(Network.mainnet())
        wallet2 = TariWallet.generate_new_with_seed_phrase(None)
        wallet2.set_network(Network.mainnet())
        
        # Same features object used with different wallets
        features = TariAddressFeatures.interactive_and_one_sided()
        
        addr1 = wallet1.get_dual_address(features, None)
        addr2 = wallet2.get_dual_address(features, None)
        
        # Addresses should be different (different wallets)
        assert addr1.to_hex() != addr2.to_hex()
        
        # But both should be valid
        assert len(addr1.to_hex()) > 0
        assert len(addr2.to_hex()) > 0
    
    def test_features_object_immutability(self):
        """Test that TariAddressFeatures objects behave as immutable."""
        features1 = TariAddressFeatures.interactive_only()
        features2 = TariAddressFeatures.interactive_only()
        
        # Should have same string representation
        assert str(features1) == str(features2)
        
        # Should produce same results when used
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        wallet.set_network(Network.mainnet())
        addr1 = wallet.get_dual_address(features1, None)
        addr2 = wallet.get_dual_address(features2, None)
        
        assert addr1.to_hex() == addr2.to_hex()


class TestTariAddressFeaturesDocumentation:
    """Test that TariAddressFeatures has proper documentation."""
    
    def test_class_is_documented(self):
        """Test that TariAddressFeatures class is properly documented."""
        # Class should exist and be importable
        assert TariAddressFeatures is not None
        
        # Static methods should exist
        assert hasattr(TariAddressFeatures, 'interactive_only')
        assert hasattr(TariAddressFeatures, 'one_sided_only')
        assert hasattr(TariAddressFeatures, 'interactive_and_one_sided')
        
        # Methods should be callable
        assert callable(TariAddressFeatures.interactive_only)
        assert callable(TariAddressFeatures.one_sided_only)
        assert callable(TariAddressFeatures.interactive_and_one_sided)
    
    def test_string_methods_work(self):
        """Test that string representation methods work correctly."""
        features = TariAddressFeatures.interactive_only()
        
        # Should have both str and repr
        str_result = str(features)
        repr_result = repr(features)
        
        assert isinstance(str_result, str)
        assert isinstance(repr_result, str)
        assert len(str_result) > 0
        assert len(repr_result) > 0
        
        # Should contain meaningful information
        assert "TariAddressFeatures" in str_result
        assert "interactive=true" in str_result and "one_sided=false" in str_result


class TestTariAddressFeaturesAPISignatures:
    """Test TariAddressFeatures API signatures and integration with wallet methods."""
    
    def test_get_dual_address_signature(self):
        """Test that get_dual_address has the correct signature with features parameter."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        wallet.set_network(Network.mainnet())
        features = TariAddressFeatures.interactive_and_one_sided()
        
        # Test with features parameter only
        address1 = wallet.get_dual_address(features, None)
        assert len(address1.to_hex()) > 0
        
        # Test with features and payment_id
        payment_id = bytes([1, 2, 3, 4, 5])
        address2 = wallet.get_dual_address(features, payment_id)
        assert len(address2.to_hex()) > 0
        assert address1.to_hex() != address2.to_hex()  # Should be different with payment ID
        
        # Test with None payment_id explicitly
        address3 = wallet.get_dual_address(features, None)
        assert address1.to_hex() == address3.to_hex()  # Should be the same as no payment ID
    
    def test_get_single_address_signature(self):
        """Test that get_single_address has the correct signature with features parameter."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        wallet.set_network(Network.mainnet())
        
        # Test with interactive only features
        interactive_features = TariAddressFeatures.interactive_only()
        address1 = wallet.get_single_address(interactive_features)
        assert len(address1.to_hex()) > 0
        
        # Test with one-sided only features
        one_sided_features = TariAddressFeatures.one_sided_only()
        address2 = wallet.get_single_address(one_sided_features)
        assert len(address2.to_hex()) > 0
        assert address1.to_hex() != address2.to_hex()  # Different features should produce different addresses
    
    def test_different_features_produce_different_addresses(self):
        """Test that different address features produce different addresses."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        wallet.set_network(Network.mainnet())
        
        # Test all feature combinations
        interactive_only = TariAddressFeatures.interactive_only()
        one_sided_only = TariAddressFeatures.one_sided_only()
        interactive_and_one_sided = TariAddressFeatures.interactive_and_one_sided()
        
        # Generate addresses with different features
        addr1 = wallet.get_dual_address(interactive_only, None)
        addr2 = wallet.get_dual_address(one_sided_only, None)
        addr3 = wallet.get_dual_address(interactive_and_one_sided, None)
        
        # All addresses should be different
        assert addr1.to_hex() != addr2.to_hex()
        assert addr1.to_hex() != addr3.to_hex()
        assert addr2.to_hex() != addr3.to_hex()
        
        # All addresses should be valid hex strings
        assert len(addr1.to_hex()) > 0
        assert len(addr2.to_hex()) > 0
        assert len(addr3.to_hex()) > 0
    
    def test_backward_compatibility_breaks(self):
        """Test that old API no longer works and new API works correctly."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        wallet.set_network(Network.mainnet())
        features = TariAddressFeatures.interactive_only()
        
        # Test that old API (without features) no longer works
        with pytest.raises(Exception):
            wallet.get_dual_address()  # Missing required features parameter
        
        # Test that new API works correctly
        address = wallet.get_dual_address(features, None)
        assert len(address.to_hex()) > 0


if __name__ == "__main__":
    # Run tests when executed directly
    pytest.main([__file__, "-v"])
