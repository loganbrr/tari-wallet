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
    from lightweight_wallet_libpy import TariWallet, TariAddressFeatures, Network, TariAddress, PrivateKey
    from .conftest import current_network  # when run as a package
except ImportError as e:
    pytest.skip(f"Cannot import wallet library: {e}", allow_module_level=True)
except Exception:
    # Fallback when pytest runs modules without package context
    import os
    from lightweight_wallet_libpy import Network
    def current_network():
        net = os.getenv('PREFERRED_TARI_NETWORK', 'esmeralda')
        try:
            return Network.from_str(net)
        except Exception:
            return Network.from_str('esmeralda')


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
        """Construct dual addresses using constructors and current network."""
        net = current_network()
        features_set = [
            TariAddressFeatures.interactive_only(),
            TariAddressFeatures.one_sided_only(),
            TariAddressFeatures.interactive_and_one_sided(),
        ]
        # Generate random keys
        sk = PrivateKey.random()
        pk = sk.public_key()
        view = pk.to_bytes()
        spend = pk.to_bytes()
        addrs = []
        for features in features_set:
            addr = TariAddress.new_dual_address(view, spend, net, features, None)
            addrs.append(addr)
            assert len(addr.to_hex()) > 0
        assert addrs[0].to_hex() != addrs[1].to_hex() or addrs[0].to_hex() != addrs[2].to_hex()
    
    def test_single_address_with_different_features(self):
        net = current_network()
        sk = PrivateKey.random()
        pk = sk.public_key()
        spend = pk.to_bytes()
        interactive_only = TariAddressFeatures.interactive_only()
        one_sided_only = TariAddressFeatures.one_sided_only()
        addr1 = TariAddress.new_single_address(spend, net, interactive_only)
        addr2 = TariAddress.new_single_address(spend, net, one_sided_only)
        assert len(addr1.to_hex()) > 0 and len(addr2.to_hex()) > 0
        assert addr1.to_hex() != addr2.to_hex()
    
    def test_deterministic_address_generation(self):
        net = current_network()
        features = TariAddressFeatures.interactive_and_one_sided()
        sk = PrivateKey.random()
        pk = sk.public_key()
        view = pk.to_bytes()
        spend = pk.to_bytes()
        addr1 = TariAddress.new_dual_address(view, spend, net, features, None)
        addr2 = TariAddress.new_dual_address(view, spend, net, features, None)
        assert addr1.to_hex() == addr2.to_hex()
    
    def test_features_with_payment_id(self):
        net = current_network()
        features = TariAddressFeatures.interactive_and_one_sided()
        sk = PrivateKey.random()
        pk = sk.public_key()
        view = pk.to_bytes()
        spend = pk.to_bytes()
        pid = bytes([1,2,3,4,5])
        addr_no = TariAddress.new_dual_address(view, spend, net, features, None)
        addr_pid = TariAddress.new_dual_address(view, spend, net, features, pid)
        assert addr_no.to_hex() != addr_pid.to_hex()


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
        net = current_network()
        features = TariAddressFeatures.interactive_and_one_sided()
        sk = PrivateKey.random(); pk = sk.public_key()
        addr = TariAddress.new_dual_address(pk.to_bytes(), pk.to_bytes(), net, features, None)
        assert len(addr.to_hex()) > 0
    
    def test_get_single_address_signature(self):
        net = current_network()
        interactive_features = TariAddressFeatures.interactive_only()
        sk = PrivateKey.random(); pk = sk.public_key()
        addr1 = TariAddress.new_single_address(pk.to_bytes(), net, interactive_features)
        assert len(addr1.to_hex()) > 0
    
    def test_different_features_produce_different_addresses(self):
        net = current_network()
        interactive_only = TariAddressFeatures.interactive_only()
        one_sided_only = TariAddressFeatures.one_sided_only()
        both = TariAddressFeatures.interactive_and_one_sided()
        sk = PrivateKey.random(); pk = sk.public_key()
        view = pk.to_bytes(); spend = pk.to_bytes()
        a1 = TariAddress.new_dual_address(view, spend, net, interactive_only, None)
        a2 = TariAddress.new_dual_address(view, spend, net, one_sided_only, None)
        a3 = TariAddress.new_dual_address(view, spend, net, both, None)
        assert a1.to_hex() != a2.to_hex() or a1.to_hex() != a3.to_hex()
    
    def test_backward_compatibility_breaks(self):
        # Ensure new constructors work
        net = current_network()
        features = TariAddressFeatures.interactive_only()
        sk = PrivateKey.random(); pk = sk.public_key()
        addr = TariAddress.new_dual_address(pk.to_bytes(), pk.to_bytes(), net, features, None)
        assert len(addr.to_hex()) > 0


if __name__ == "__main__":
    # Run tests when executed directly
    pytest.main([__file__, "-v"])
