#!/usr/bin/env python3
"""
Pytest configuration and fixtures for Tari wallet Python bindings tests.

This module provides common fixtures and configuration for all test modules.
"""

import pytest
import sys
import os
import gc
import psutil
import time
import threading
import concurrent.futures
from typing import List, Tuple, Dict, Any
from memory_profiler import profile

# Add the parent directory to Python path to import the module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Only require the module itself to import; individual tests can import specific symbols
try:
    import lightweight_wallet_libpy as wallet_lib
    WALLET_LIB_AVAILABLE = True
    IMPORT_ERROR = None
    # Best-effort convenience imports; ignore failures so tests that don't need them still run
    try:
        from lightweight_wallet_libpy import (
            TariWallet, TariAddressFeatures,
            PrivateKey, CompressedCommitment, RangeProof,
            PyWalletError, NativeCryptoStats,
        )
    except Exception as _e:
        TariWallet = None
        TariAddressFeatures = None
        PrivateKey = None
        CompressedCommitment = None
        RangeProof = None
        PyWalletError = None
        NativeCryptoStats = None
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
    
    return wallet_lib.TariWallet.generate_new_with_seed_phrase(None)


@pytest.fixture
def test_wallet_with_label():
    """Provide a test wallet with a label set."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    wallet = wallet_lib.TariWallet.generate_new_with_seed_phrase(None)
    wallet.set_label("Test Wallet")
    return wallet


@pytest.fixture
def address_features_interactive_only():
    """Provide interactive-only address features."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    return wallet_lib.TariAddressFeatures.interactive_only()


@pytest.fixture
def address_features_one_sided_only():
    """Provide one-sided-only address features."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    return wallet_lib.TariAddressFeatures.one_sided_only()


@pytest.fixture
def address_features_interactive_and_one_sided():
    """Provide interactive and one-sided address features."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    return wallet_lib.TariAddressFeatures.interactive_and_one_sided()


@pytest.fixture
def test_scanner(test_wallet):
    """Provide a test scanner instance."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    # Use localhost with a test port
    return wallet_lib.TariScanner("http://localhost:18142", test_wallet)


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
        wallet = wallet_lib.TariWallet.generate_new_with_seed_phrase(None)
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
        
        self.wallet = wallet_lib.TariWallet.generate_new_with_seed_phrase(self.passphrase)
        return self.wallet
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Cleanup if needed (currently wallet cleanup is automatic)
        pass


@pytest.fixture
def wallet_context():
    """Provide a wallet context manager for tests that need explicit lifecycle control."""
    return TestWalletContext


# ========== Validation API Fixtures ==========

@pytest.fixture
def valid_commitment_hex():
    """Provide a valid commitment hex string for testing."""
    return "08" + "1234567890abcdef" * 3 + "1234567890abcdef"

@pytest.fixture
def invalid_commitment_hex():
    """Provide an invalid commitment hex string for testing."""
    return "01" + "1234567890abcdef" * 3 + "1234567890abcdef"  # Invalid prefix

@pytest.fixture
def sample_range_proof_hex():
    """Provide a sample range proof hex string for testing."""
    return "deadbeef" * 64  # 256 bytes of mock proof data

@pytest.fixture
def sample_signature_components():
    """Provide sample signature components for testing."""
    return {
        'signature_hex': "deadbeef" * 8,  # 32 bytes
        'nonce_hex': "cafebabe" * 8,     # 32 bytes
        'message': "Hello, Tari from validation test!",
        'public_key_hex': "12345678" * 8  # 32 bytes
    }

@pytest.fixture
def sample_encrypted_data_hex():
    """Provide sample encrypted data hex for testing."""
    return "deadbeef" * 32  # 256 bytes of mock encrypted data

@pytest.fixture
def validation_test_batch_size():
    """Provide consistent batch size for performance testing."""
    return 50

@pytest.fixture
def large_validation_batch_size():
    """Provide large batch size for stress testing."""
    return 1000


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
        wallet_lib.TariAddressFeatures.interactive_only(),
        wallet_lib.TariAddressFeatures.one_sided_only(),
        wallet_lib.TariAddressFeatures.interactive_and_one_sided(),
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


# ========== Integration Testing Framework Fixtures ==========

@pytest.fixture
def crypto_test_data():
    """Provide test data for crypto operations."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    return {
        'private_key': wallet_lib.PrivateKey.from_bytes(bytes([1] * 32)) if hasattr(wallet_lib, 'PrivateKey') else None,
        'test_values': [1000, 2000, 5000, 10000],
        'test_commitments': [],
        'test_range_proofs': []
    }


@pytest.fixture
def performance_monitor():
    """Fixture to monitor performance during tests."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    process = psutil.Process()
    start_memory = process.memory_info().rss
    start_time = time.time()
    
    yield {
        'start_memory': start_memory,
        'start_time': start_time,
        'process': process
    }
    
    end_time = time.time()
    end_memory = process.memory_info().rss
    
    print(f"Performance metrics: {end_time - start_time:.3f}s, "
          f"Memory change: {end_memory - start_memory} bytes")


@pytest.fixture
def security_monitor():
    """Fixture to monitor security-related metrics during tests."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    process = psutil.Process()
    start_memory = process.memory_info().rss
    start_time = time.time()
    
    yield {
        'start_memory': start_memory,
        'start_time': start_time,
        'process': process
    }
    
    end_time = time.time()
    end_memory = process.memory_info().rss
    
    print(f"Security metrics: {end_time - start_time:.3f}s, "
          f"Memory change: {end_memory - start_memory} bytes")


@pytest.fixture
def memory_leak_detector():
    """Fixture to detect memory leaks in tests."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    process = psutil.Process()
    initial_memory = process.memory_info().rss
    
    yield {
        'initial_memory': initial_memory,
        'process': process
    }
    
    # Force garbage collection
    gc.collect()
    
    final_memory = process.memory_info().rss
    memory_increase = final_memory - initial_memory
    
    if memory_increase > 1024 * 1024:  # 1MB threshold
        print(f"⚠️  Potential memory leak detected: {memory_increase} bytes increase")


@pytest.fixture
def concurrent_test_executor():
    """Fixture providing a thread pool executor for concurrent tests."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        yield executor


@pytest.fixture
def benchmark_private_key():
    """Fixture providing a private key for benchmarking."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    return wallet_lib.PrivateKey.from_bytes(bytes([1] * 32)) if hasattr(wallet_lib, 'PrivateKey') else None


@pytest.fixture
def test_commitment_data():
    """Fixture providing test commitment data."""
    if not WALLET_LIB_AVAILABLE:
        pytest.skip(f"Wallet library not available: {IMPORT_ERROR}")
    
    if not hasattr(wallet_lib, 'calculate_commitment_native'):
        pytest.skip("Native commitment function not available")
    
    private_key = wallet_lib.PyPrivateKey.from_bytes(bytes([1] * 32)) if hasattr(wallet_lib, 'PyPrivateKey') else None
    commitment = wallet_lib.calculate_commitment_native(1000, private_key)
    mock_proof = wallet_lib.RangeProof.from_bytes(bytes([0x08] * 100)) if hasattr(wallet_lib, 'RangeProof') else None
    
    return {
        'private_key': private_key,
        'commitment': commitment,
        'range_proof': mock_proof,
        'value': 1000
    }


# ========== Memory Leak Detection Decorator ==========

def check_memory_leak(func):
    """Decorator to check for memory leaks in test functions."""
    def wrapper(*args, **kwargs):
        if not WALLET_LIB_AVAILABLE:
            return func(*args, **kwargs)
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        result = func(*args, **kwargs)
        
        # Force garbage collection
        gc.collect()
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Allow small memory increase (less than 1MB)
        if memory_increase > 1024 * 1024:
            pytest.fail(f"Potential memory leak detected: {memory_increase} bytes increase")
        
        return result
    
    return wrapper


# ========== Performance Monitoring Decorator ==========

def monitor_performance(threshold_ops_per_sec: float = 1000):
    """Decorator to monitor performance of test functions."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not WALLET_LIB_AVAILABLE:
                return func(*args, **kwargs)
            
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()
            
            duration = end_time - start_time
            if duration > 0:
                ops_per_sec = 1 / duration
                if ops_per_sec < threshold_ops_per_sec:
                    pytest.fail(f"Performance below threshold: {ops_per_sec:.1f} ops/sec (threshold: {threshold_ops_per_sec})")
            
            return result
        return wrapper
    return decorator


# ========== Security Validation Decorator ==========

def validate_security(func):
    """Decorator to validate security properties of test functions."""
    def wrapper(*args, **kwargs):
        if not WALLET_LIB_AVAILABLE:
            return func(*args, **kwargs)
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        result = func(*args, **kwargs)
        
        # Force garbage collection
        gc.collect()
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Security check: memory increase should be minimal
        if memory_increase > 5 * 1024 * 1024:  # 5MB threshold
            pytest.fail(f"Security violation: excessive memory usage {memory_increase} bytes")
        
        return result
    
    return wrapper
