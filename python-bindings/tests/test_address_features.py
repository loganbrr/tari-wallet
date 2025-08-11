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
        features = TariAddressFeatures.interactive_only()
        assert features is not None
        str_repr = str(features)
        assert "TariAddressFeatures" in str_repr
        assert "interactive=true" in str_repr and "one_sided=false" in str_repr
        repr_str = repr(features)
        assert "bits=" in repr_str
    
    def test_one_sided_only_creation(self):
        features = TariAddressFeatures.one_sided_only()
        assert features is not None
        str_repr = str(features)
        assert "TariAddressFeatures" in str_repr
        assert "interactive=false" in str_repr and "one_sided=true" in str_repr
    
    def test_interactive_and_one_sided_creation(self):
        features = TariAddressFeatures.interactive_and_one_sided()
        assert features is not None
        str_repr = str(features)
        assert "TariAddressFeatures" in str_repr
        assert "interactive=true" in str_repr and "one_sided=true" in str_repr
    
    def test_different_features_have_different_representations(self):
        interactive_only = TariAddressFeatures.interactive_only()
        one_sided_only = TariAddressFeatures.one_sided_only()
        both = TariAddressFeatures.interactive_and_one_sided()
        assert str(interactive_only) != str(one_sided_only)
        assert str(interactive_only) != str(both)
        assert str(one_sided_only) != str(both)


class TestTariAddressFeaturesWithWallet:
    """Test TariAddressFeatures integration with wallet address generation."""
    
    def test_dual_address_with_different_features(self):
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        interactive_only = TariAddressFeatures.interactive_only()
        one_sided_only = TariAddressFeatures.one_sided_only()
        both = TariAddressFeatures.interactive_and_one_sided()
        a1 = wallet.get_dual_address(interactive_only)
        a2 = wallet.get_dual_address(one_sided_only)
        a3 = wallet.get_dual_address(both)
        assert len(a1.to_hex()) > 0
        assert len(a2.to_hex()) > 0
        assert len(a3.to_hex()) > 0
        assert a1.to_hex() != a2.to_hex() or a1.to_hex() != a3.to_hex()
    
    def test_single_address_with_different_features(self):
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        interactive_only = TariAddressFeatures.interactive_only()
        one_sided_only = TariAddressFeatures.one_sided_only()
        addr1 = wallet.get_single_address(interactive_only)
        addr2 = wallet.get_single_address(one_sided_only)
        assert len(addr1.to_hex()) > 0
        assert len(addr2.to_hex()) > 0
        assert addr1.to_hex() != addr2.to_hex()
    
    def test_deterministic_address_generation(self):
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        features = TariAddressFeatures.interactive_and_one_sided()
        addr1 = wallet.get_dual_address(features)
        addr2 = wallet.get_dual_address(features)
        addr3 = wallet.get_dual_address(features)
        assert addr1.to_hex() == addr2.to_hex() == addr3.to_hex()
    
    def test_features_with_payment_id(self):
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        features = TariAddressFeatures.interactive_and_one_sided()
        payment_id = bytes([1, 2, 3, 4, 5])
        addr_no_payment = wallet.get_dual_address(features)
        addr_with_payment = wallet.get_dual_address(features, payment_id)
        assert addr_no_payment.to_hex() != addr_with_payment.to_hex()
        addr_with_payment2 = wallet.get_dual_address(features, payment_id)
        assert addr_with_payment.to_hex() == addr_with_payment2.to_hex()


class TestTariAddressFeaturesDocumentation:
    """Test that TariAddressFeatures has proper documentation."""
    
    def test_class_is_documented(self):
        assert TariAddressFeatures is not None
        assert hasattr(TariAddressFeatures, 'interactive_only')
        assert hasattr(TariAddressFeatures, 'one_sided_only')
        assert hasattr(TariAddressFeatures, 'interactive_and_one_sided')
        assert callable(TariAddressFeatures.interactive_only)
        assert callable(TariAddressFeatures.one_sided_only)
        assert callable(TariAddressFeatures.interactive_and_one_sided)
    
    def test_string_methods_work(self):
        features = TariAddressFeatures.interactive_only()
        str_result = str(features)
        repr_result = repr(features)
        assert isinstance(str_result, str)
        assert isinstance(repr_result, str)
        assert len(str_result) > 0
        assert len(repr_result) > 0
        assert "TariAddressFeatures" in str_result
        assert "interactive=true" in str_result and "one_sided=false" in str_result


class TestTariAddressFeaturesAPISignatures:
    """Test TariAddressFeatures API signatures and integration with wallet methods."""
    
    def test_get_dual_address_signature(self):
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        features = TariAddressFeatures.interactive_and_one_sided()
        address1 = wallet.get_dual_address(features)
        assert len(address1.to_hex()) > 0
        payment_id = bytes([1, 2, 3, 4, 5])
        address2 = wallet.get_dual_address(features, payment_id)
        assert len(address2.to_hex()) > 0
        assert address1.to_hex() != address2.to_hex()
        address3 = wallet.get_dual_address(features, None)
        assert address1.to_hex() == address3.to_hex()
    
    def test_get_single_address_signature(self):
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        interactive_features = TariAddressFeatures.interactive_only()
        address1 = wallet.get_single_address(interactive_features)
        assert len(address1.to_hex()) > 0
        one_sided_features = TariAddressFeatures.one_sided_only()
        address2 = wallet.get_single_address(one_sided_features)
        assert len(address2.to_hex()) > 0
        assert address1.to_hex() != address2.to_hex()
    
    def test_different_features_produce_different_addresses(self):
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        interactive_only = TariAddressFeatures.interactive_only()
        one_sided_only = TariAddressFeatures.one_sided_only()
        both = TariAddressFeatures.interactive_and_one_sided()
        addr1 = wallet.get_dual_address(interactive_only)
        addr2 = wallet.get_dual_address(one_sided_only)
        addr3 = wallet.get_dual_address(both)
        assert addr1.to_hex() != addr2.to_hex() or addr1.to_hex() != addr3.to_hex()
        assert len(addr1.to_hex()) > 0
        assert len(addr2.to_hex()) > 0
        assert len(addr3.to_hex()) > 0
    
    def test_backward_compatibility_breaks(self):
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        features = TariAddressFeatures.interactive_only()
        with pytest.raises(Exception):
            wallet.get_dual_address()  # Missing required features parameter
        address = wallet.get_dual_address(features)
        assert len(address.to_hex()) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
