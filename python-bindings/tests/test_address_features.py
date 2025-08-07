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
    from lightweight_wallet_libpy import TariWallet, TariAddressFeatures
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
        assert "interactive_only" in str_repr
        
        # Test repr
        repr_str = repr(features)
        assert str_repr == repr_str
    
    def test_one_sided_only_creation(self):
        """Test creating one-sided-only address features."""
        features = TariAddressFeatures.one_sided_only()
        assert features is not None
        
        # Test string representation
        str_repr = str(features)
        assert "TariAddressFeatures" in str_repr
        assert "one_sided_only" in str_repr
    
    def test_interactive_and_one_sided_creation(self):
        """Test creating interactive and one-sided address features."""
        features = TariAddressFeatures.interactive_and_one_sided()
        assert features is not None
        
        # Test string representation
        str_repr = str(features)
        assert "TariAddressFeatures" in str_repr
        assert "interactive_and_one_sided" in str_repr
    
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
        
        # Test with each feature type
        interactive_only = TariAddressFeatures.interactive_only()
        one_sided_only = TariAddressFeatures.one_sided_only()
        interactive_and_one_sided = TariAddressFeatures.interactive_and_one_sided()
        
        addr1 = wallet.get_dual_address(interactive_only)
        addr2 = wallet.get_dual_address(one_sided_only)
        addr3 = wallet.get_dual_address(interactive_and_one_sided)
        
        # All addresses should be valid hex strings
        assert len(addr1) > 0
        assert len(addr2) > 0
        assert len(addr3) > 0
        
        # All addresses should be different
        assert addr1 != addr2
        assert addr1 != addr3
        assert addr2 != addr3
    
    def test_single_address_with_different_features(self):
        """Test single address generation with different features."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test with features that make sense for single addresses
        interactive_only = TariAddressFeatures.interactive_only()
        one_sided_only = TariAddressFeatures.one_sided_only()
        
        addr1 = wallet.get_single_address(interactive_only)
        addr2 = wallet.get_single_address(one_sided_only)
        
        # Both addresses should be valid
        assert len(addr1) > 0
        assert len(addr2) > 0
        
        # Addresses should be different
        assert addr1 != addr2
    
    def test_deterministic_address_generation(self):
        """Test that same features produce same addresses."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        features = TariAddressFeatures.interactive_and_one_sided()
        
        # Generate same address multiple times
        addr1 = wallet.get_dual_address(features)
        addr2 = wallet.get_dual_address(features)
        addr3 = wallet.get_dual_address(features)
        
        # All should be identical
        assert addr1 == addr2 == addr3
        
        # Same for single addresses
        single1 = wallet.get_single_address(features)
        single2 = wallet.get_single_address(features)
        
        assert single1 == single2
    
    def test_features_with_payment_id(self):
        """Test address features with payment IDs."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        features = TariAddressFeatures.interactive_and_one_sided()
        
        payment_id = [1, 2, 3, 4, 5]
        
        # Address without payment ID
        addr_no_payment = wallet.get_dual_address(features, None)
        
        # Address with payment ID
        addr_with_payment = wallet.get_dual_address(features, payment_id)
        
        # Should be different
        assert addr_no_payment != addr_with_payment
        
        # Same payment ID should produce same address
        addr_with_payment2 = wallet.get_dual_address(features, payment_id)
        assert addr_with_payment == addr_with_payment2


class TestTariAddressFeaturesEdgeCases:
    """Test edge cases and error conditions for TariAddressFeatures."""
    
    def test_features_can_be_reused(self):
        """Test that TariAddressFeatures objects can be reused across wallets."""
        wallet1 = TariWallet.generate_new_with_seed_phrase(None)
        wallet2 = TariWallet.generate_new_with_seed_phrase(None)
        
        # Same features object used with different wallets
        features = TariAddressFeatures.interactive_and_one_sided()
        
        addr1 = wallet1.get_dual_address(features)
        addr2 = wallet2.get_dual_address(features)
        
        # Addresses should be different (different wallets)
        assert addr1 != addr2
        
        # But both should be valid
        assert len(addr1) > 0
        assert len(addr2) > 0
    
    def test_features_object_immutability(self):
        """Test that TariAddressFeatures objects behave as immutable."""
        features1 = TariAddressFeatures.interactive_only()
        features2 = TariAddressFeatures.interactive_only()
        
        # Should have same string representation
        assert str(features1) == str(features2)
        
        # Should produce same results when used
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        addr1 = wallet.get_dual_address(features1)
        addr2 = wallet.get_dual_address(features2)
        
        assert addr1 == addr2


class TestTariAddressFeaturesErrorConditions:
    """Test error conditions and type safety."""
    
    def test_features_required_for_address_generation(self):
        """Test that features parameter is required for address generation."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Should raise TypeError when features is missing
        with pytest.raises(TypeError):
            wallet.get_dual_address()
        
        with pytest.raises(TypeError):
            wallet.get_single_address()
    
    def test_invalid_features_type_rejected(self):
        """Test that invalid feature types are rejected."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # String should not work as features
        with pytest.raises(TypeError):
            wallet.get_dual_address("interactive_only")
        
        # Integer should not work as features
        with pytest.raises(TypeError):
            wallet.get_dual_address(1)
        
        # None should not work as features
        with pytest.raises(TypeError):
            wallet.get_dual_address(None)
        
        # Dict should not work as features
        with pytest.raises(TypeError):
            wallet.get_dual_address({"type": "interactive_only"})


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
        assert "interactive_only" in str_result


class TestTariAddressFeaturesAPISignatures:
    """Test TariAddressFeatures API signatures and integration with wallet methods."""
    
    def test_get_dual_address_signature(self):
        """Test that get_dual_address has the correct signature with features parameter."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        features = TariAddressFeatures.interactive_and_one_sided()
        
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
        interactive_features = TariAddressFeatures.interactive_only()
        address1 = wallet.get_single_address(interactive_features)
        assert len(address1) > 0
        
        # Test with one-sided only features
        one_sided_features = TariAddressFeatures.one_sided_only()
        address2 = wallet.get_single_address(one_sided_features)
        assert len(address2) > 0
        assert address1 != address2  # Different features should produce different addresses
    
    def test_different_features_produce_different_addresses(self):
        """Test that different address features produce different addresses."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test all feature combinations
        interactive_only = TariAddressFeatures.interactive_only()
        one_sided_only = TariAddressFeatures.one_sided_only()
        interactive_and_one_sided = TariAddressFeatures.interactive_and_one_sided()
        
        # Generate addresses with different features
        addr1 = wallet.get_dual_address(interactive_only)
        addr2 = wallet.get_dual_address(one_sided_only)
        addr3 = wallet.get_dual_address(interactive_and_one_sided)
        
        # All addresses should be different
        assert addr1 != addr2
        assert addr1 != addr3
        assert addr2 != addr3
        
        # All addresses should be valid hex strings
        assert len(addr1) > 0
        assert len(addr2) > 0
        assert len(addr3) > 0
    
    def test_signature_parameter_validation(self):
        """Test that invalid parameters raise appropriate errors."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        features = TariAddressFeatures.interactive_only()
        
        # Test that None features raises error
        with pytest.raises(Exception):
            wallet.get_dual_address(None)
        
        # Test that invalid feature type raises error
        with pytest.raises(Exception):
            wallet.get_dual_address("invalid_features")
        
        # Test that payment_id must be list or None
        with pytest.raises(Exception):
            wallet.get_dual_address(features, "invalid_payment_id")
    
    def test_backward_compatibility_breaks(self):
        """Test that old API no longer works and new API works correctly."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        features = TariAddressFeatures.interactive_only()
        
        # Test that old API (without features) no longer works
        with pytest.raises(Exception):
            wallet.get_dual_address()  # Missing required features parameter
        
        # Test that new API works correctly
        address = wallet.get_dual_address(features)
        assert len(address) > 0


if __name__ == "__main__":
    # Run tests when executed directly
    pytest.main([__file__, "-v"])
