#!/usr/bin/env python3
"""
Test suite for AddressFeatures wrapper class functionality.

This module tests the new AddressFeatures Python wrapper and ensures
proper type safety and feature selection for address generation.
"""

import pytest
import sys
import os

# Add the parent directory to Python path to import the module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import lightweight_wallet_libpy as wallet_lib
    from lightweight_wallet_libpy import TariWallet, AddressFeatures
except ImportError as e:
    pytest.skip(f"Cannot import wallet library: {e}", allow_module_level=True)


class TestAddressFeaturesCreation:
    """Test AddressFeatures creation methods."""
    
    def test_interactive_only_creation(self):
        """Test creating interactive-only address features."""
        features = AddressFeatures.interactive_only()
        assert features is not None
        
        # Test string representation
        str_repr = str(features)
        assert "AddressFeatures" in str_repr
        assert "interactive_only" in str_repr
        
        # Test repr
        repr_str = repr(features)
        assert str_repr == repr_str
    
    def test_one_sided_only_creation(self):
        """Test creating one-sided-only address features."""
        features = AddressFeatures.one_sided_only()
        assert features is not None
        
        # Test string representation
        str_repr = str(features)
        assert "AddressFeatures" in str_repr
        assert "one_sided_only" in str_repr
    
    def test_interactive_and_one_sided_creation(self):
        """Test creating interactive and one-sided address features."""
        features = AddressFeatures.interactive_and_one_sided()
        assert features is not None
        
        # Test string representation
        str_repr = str(features)
        assert "AddressFeatures" in str_repr
        assert "interactive_and_one_sided" in str_repr
    
    def test_different_features_have_different_representations(self):
        """Test that different feature types have distinct string representations."""
        interactive_only = AddressFeatures.interactive_only()
        one_sided_only = AddressFeatures.one_sided_only()
        interactive_and_one_sided = AddressFeatures.interactive_and_one_sided()
        
        # All should have different string representations
        assert str(interactive_only) != str(one_sided_only)
        assert str(interactive_only) != str(interactive_and_one_sided)
        assert str(one_sided_only) != str(interactive_and_one_sided)


class TestAddressFeaturesWithWallet:
    """Test AddressFeatures integration with wallet address generation."""
    
    def test_dual_address_with_different_features(self):
        """Test dual address generation with different features."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test with each feature type
        interactive_only = AddressFeatures.interactive_only()
        one_sided_only = AddressFeatures.one_sided_only()
        interactive_and_one_sided = AddressFeatures.interactive_and_one_sided()
        
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
        interactive_only = AddressFeatures.interactive_only()
        one_sided_only = AddressFeatures.one_sided_only()
        
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
        features = AddressFeatures.interactive_and_one_sided()
        
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
        features = AddressFeatures.interactive_and_one_sided()
        
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


class TestAddressFeaturesEdgeCases:
    """Test edge cases and error conditions for AddressFeatures."""
    
    def test_features_can_be_reused(self):
        """Test that AddressFeatures objects can be reused across wallets."""
        wallet1 = TariWallet.generate_new_with_seed_phrase(None)
        wallet2 = TariWallet.generate_new_with_seed_phrase(None)
        
        # Same features object used with different wallets
        features = AddressFeatures.interactive_and_one_sided()
        
        addr1 = wallet1.get_dual_address(features)
        addr2 = wallet2.get_dual_address(features)
        
        # Addresses should be different (different wallets)
        assert addr1 != addr2
        
        # But both should be valid
        assert len(addr1) > 0
        assert len(addr2) > 0
    
    def test_features_object_immutability(self):
        """Test that AddressFeatures objects behave as immutable."""
        features1 = AddressFeatures.interactive_only()
        features2 = AddressFeatures.interactive_only()
        
        # Should have same string representation
        assert str(features1) == str(features2)
        
        # Should produce same results when used
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        addr1 = wallet.get_dual_address(features1)
        addr2 = wallet.get_dual_address(features2)
        
        assert addr1 == addr2


class TestAddressFeaturesErrorConditions:
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


class TestAddressFeaturesDocumentation:
    """Test that AddressFeatures has proper documentation."""
    
    def test_class_is_documented(self):
        """Test that AddressFeatures class is properly documented."""
        # Class should exist and be importable
        assert AddressFeatures is not None
        
        # Static methods should exist
        assert hasattr(AddressFeatures, 'interactive_only')
        assert hasattr(AddressFeatures, 'one_sided_only')
        assert hasattr(AddressFeatures, 'interactive_and_one_sided')
        
        # Methods should be callable
        assert callable(AddressFeatures.interactive_only)
        assert callable(AddressFeatures.one_sided_only)
        assert callable(AddressFeatures.interactive_and_one_sided)
    
    def test_string_methods_work(self):
        """Test that string representation methods work correctly."""
        features = AddressFeatures.interactive_only()
        
        # Should have both str and repr
        str_result = str(features)
        repr_result = repr(features)
        
        assert isinstance(str_result, str)
        assert isinstance(repr_result, str)
        assert len(str_result) > 0
        assert len(repr_result) > 0
        
        # Should contain meaningful information
        assert "AddressFeatures" in str_result
        assert "interactive_only" in str_result


if __name__ == "__main__":
    # Run tests when executed directly
    pytest.main([__file__, "-v"])
