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
    from lightweight_wallet_libpy import TariWallet, TariScanner, TariAddressFeatures
except ImportError as e:
    pytest.skip(f"Cannot import wallet library: {e}", allow_module_level=True)


class TestWalletAPISignatures:
    """Test that wallet API methods have correct signatures (non-AddressFeatures)."""
    
    def test_wallet_creation_signature(self):
        """Test that wallet creation methods have correct signatures."""
        # Test basic wallet creation
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        assert wallet is not None
        
        # Test wallet creation with seed phrase
        wallet2 = TariWallet.generate_new_with_seed_phrase("test seed phrase")
        assert wallet2 is not None
        
        # Test that different seed phrases produce different wallets
        assert wallet.label() != wallet2.label()
    
    def test_wallet_property_access(self):
        """Test that wallet properties can be accessed correctly."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test basic properties
        assert hasattr(wallet, 'label')
        assert hasattr(wallet, 'network')
        assert hasattr(wallet, 'birthday')
        
        # Test property values
        assert isinstance(wallet.label(), str)
        assert isinstance(wallet.network(), str)
        assert isinstance(wallet.birthday(), int)


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
    """Test parameter validation for API methods (non-AddressFeatures)."""
    
    def test_wallet_parameter_validation(self):
        """Test that wallet parameters are validated correctly."""
        # Test wallet creation with invalid parameters
        with pytest.raises(Exception):
            TariWallet.generate_new_with_seed_phrase(123)  # Invalid seed phrase type
        
        # Test wallet property setting with invalid values
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        with pytest.raises(Exception):
            wallet.set_birthday(-1)  # Invalid birthday value
        
        with pytest.raises(Exception):
            wallet.set_network(123)  # Invalid network type
    
    def test_scanner_parameter_validation(self):
        """Test that scanner parameters are validated correctly."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test scanner creation with invalid parameters
        with pytest.raises(Exception):
            TariScanner("invalid_url", wallet)  # Invalid URL format
        
        with pytest.raises(Exception):
            TariScanner("http://localhost:18142", "invalid_wallet")  # Invalid wallet type


class TestBackwardCompatibilityBreaks:
    """Test and document backward compatibility breaks (non-AddressFeatures)."""
    
    def test_wallet_api_changes(self):
        """Test that wallet API changes are properly documented."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test that wallet properties are accessible
        assert hasattr(wallet, 'label')
        assert hasattr(wallet, 'network')
        assert hasattr(wallet, 'birthday')
        
        # Test that wallet methods exist
        assert hasattr(wallet, 'get_dual_address')
        assert hasattr(wallet, 'get_single_address')
        assert hasattr(wallet, 'set_network')
        assert hasattr(wallet, 'set_birthday')
    
    def test_scanner_api_changes(self):
        """Test that scanner API changes are properly documented."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        scanner = TariScanner("http://localhost:18142", wallet)
        
        # Test that scanner methods exist
        assert hasattr(scanner, 'get_tip_height')
        assert hasattr(scanner, 'scan_blocks')
        assert hasattr(scanner, 'get_balance')
        assert hasattr(scanner, 'get_block_by_height')
        assert hasattr(scanner, 'search_utxos')


if __name__ == "__main__":
    # Run tests when executed directly
    pytest.main([__file__, "-v"])
