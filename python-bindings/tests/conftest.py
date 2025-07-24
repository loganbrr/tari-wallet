#!/usr/bin/env python3
"""
Pytest configuration and fixtures for Tari wallet Python bindings tests.

This module provides common fixtures and configuration for all test modules.
"""

import pytest
import sys
import os

# Add the parent directory to Python path to import the module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import lightweight_wallet_libpy as wallet_lib
    from lightweight_wallet_libpy import TariWallet, TariScanner, AddressFeatures
    WALLET_LIB_AVAILABLE = True
except ImportError as e:
    WALLET_LIB_AVAILABLE = False
    IMPORT_ERROR = str(e)


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", 
        "skip_if_no_wallet: skip test if wallet library is not available"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to skip tests if wallet library is not available."""
    if not WALLET_LIB_AVAILABLE:
        skip_wallet = pytest.mark.skip(reason=f"Wallet library not available: {IMPORT_ERROR}")
        for item in items:
            item.add_marker(skip_wallet)


@pytest.fixture(scope="session")
def wallet_lib_module():
    """Provide the wallet library module for tests."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    return wallet_lib


@pytest.fixture
def test_wallet():
    """Provide a fresh test wallet for each test."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    return TariWallet.generate_new_with_seed_phrase(None)


@pytest.fixture
def test_wallet_with_label():
    """Provide a test wallet with a label set."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    wallet = TariWallet.generate_new_with_seed_phrase(None)
    wallet.set_label("Test Wallet")
    return wallet


@pytest.fixture
def address_features_interactive_only():
    """Provide interactive-only address features."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    return AddressFeatures.interactive_only()


@pytest.fixture
def address_features_one_sided_only():
    """Provide one-sided-only address features."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    return AddressFeatures.one_sided_only()


@pytest.fixture
def address_features_interactive_and_one_sided():
    """Provide interactive and one-sided address features."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    return AddressFeatures.interactive_and_one_sided()


@pytest.fixture
def test_scanner(test_wallet):
    """Provide a test scanner instance."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    # Use localhost with a test port
    return TariScanner("http://localhost:18142", test_wallet)


@pytest.fixture
def sample_payment_id():
    """Provide a sample payment ID for testing."""
    return [1, 2, 3, 4, 5]


@pytest.fixture
def multiple_test_wallets():
    """Provide multiple wallets for independence testing."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    wallets = []
    for i in range(3):
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        wallet.set_label(f"Test Wallet {i+1}")
        wallet.set_network(["mainnet", "stagenet", "localnet"][i])
        wallets.append(wallet)
    
    return wallets


@pytest.fixture(scope="session")
def test_message():
    """Provide a test message for signing tests."""
    return "Hello, Tari from Python test suite!"


@pytest.fixture(scope="session")
def unicode_test_message():
    """Provide a unicode test message for comprehensive testing."""
    return "🚀 Tari wallet test with émojis and àccénts! 测试"


@pytest.fixture
def invalid_base_node_urls():
    """Provide a list of invalid base node URLs for error testing."""
    return [
        "not-a-url",
        "ftp://wrong-protocol.com",
        "http://",
        "://missing-protocol.com",
        "http://192.0.2.1:12345",  # RFC 3330 test IP
        "http://127.0.0.1:65534",  # High port unlikely to be open
        "http://space in url.com",
    ]


class TestWalletContext:
    """Context manager for test wallets that need cleanup."""
    
    def __init__(self, passphrase=None):
        self.passphrase = passphrase
        self.wallet = None
    
    def __enter__(self):
        if not WALLET_LIB_AVAILABLE:
            pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
        
        self.wallet = TariWallet.generate_new_with_seed_phrase(self.passphrase)
        return self.wallet
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Cleanup if needed (currently wallet cleanup is automatic)
        pass


@pytest.fixture
def wallet_context():
    """Provide a wallet context manager for tests that need explicit lifecycle control."""
    return TestWalletContext


# Performance test helpers
@pytest.fixture
def performance_threshold_seconds():
    """Provide performance threshold for timing-sensitive tests."""
    return {
        'wallet_creation': 2.0,
        'address_generation': 1.0,
        'message_signing': 1.0,
        'error_handling': 5.0,
    }


# Test data generators
@pytest.fixture
def generate_test_payment_ids():
    """Generate various payment ID formats for testing."""
    def _generator():
        return [
            None,                                    # No payment ID
            [],                                      # Empty payment ID
            [1],                                     # Single byte
            [1, 2, 3, 4, 5],                         # Multiple bytes
            list(range(32)),                         # Maximum size payment ID
            bytes([1, 2, 3, 4, 5]),                  # Bytes object
        ]
    return _generator


@pytest.fixture
def all_address_features():
    """Provide all available address feature types."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    return [
        AddressFeatures.interactive_only(),
        AddressFeatures.one_sided_only(),
        AddressFeatures.interactive_and_one_sided(),
    ]


# Test configuration helpers
def pytest_runtest_setup(item):
    """Setup for each test run."""
    # Add any per-test setup here if needed
    pass


def pytest_runtest_teardown(item, nextitem):
    """Teardown after each test run."""
    # Add any per-test cleanup here if needed
    pass


# Custom assertion helpers
def assert_valid_hex_address(address):
    """Assert that an address is a valid hex string."""
    assert isinstance(address, str), f"Address should be string, got {type(address)}"
    assert len(address) > 0, "Address should not be empty"
    
    # Check if it's valid hex (basic check)
    try:
        int(address, 16)
    except ValueError:
        pytest.fail(f"Address '{address[:50]}...' is not valid hex")


def assert_different_addresses(*addresses):
    """Assert that all provided addresses are different from each other."""
    address_list = list(addresses)
    for i, addr1 in enumerate(address_list):
        for j, addr2 in enumerate(address_list[i+1:], i+1):
            assert addr1 != addr2, f"Addresses at positions {i} and {j} are identical: {addr1[:50]}..."


# Register custom assertion helpers with pytest
pytest.assert_valid_hex_address = assert_valid_hex_address
pytest.assert_different_addresses = assert_different_addresses
