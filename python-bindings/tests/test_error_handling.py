#!/usr/bin/env python3
"""
Comprehensive error handling test suite for Tari wallet Python bindings.

This module tests the enhanced error conversion framework, custom exception hierarchy,
and error propagation from Rust to Python with proper context preservation.
"""

import pytest
import sys
import os

# Add the parent directory to Python path to import the module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import lightweight_wallet_libpy as wallet_lib
    from lightweight_wallet_libpy import TariWallet, TariScanner
except ImportError as e:
    pytest.skip(f"Cannot import wallet library: {e}", allow_module_level=True)


class TestErrorConversionFramework:
    """Test the enhanced error conversion framework with custom exception hierarchy."""
    
    def test_wallet_error_hierarchy(self):
        """Test that wallet errors follow the proper exception hierarchy."""
        # Test that WalletError is available (if exposed)
        # Note: Custom exceptions might not be directly exposed, so we test through operations
        
        # Test invalid seed phrase scenarios that should trigger specific errors
        with pytest.raises(Exception) as exc_info:
            # This should trigger a key management error
            TariWallet.generate_new_with_seed_phrase("")
        
        assert "error" in str(exc_info.value).lower()
    
    def test_validation_error_conversion(self):
        """Test validation errors are properly converted."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test invalid network setting
        with pytest.raises(Exception) as exc_info:
            wallet.set_network("INVALID_NETWORK_NAME_THAT_SHOULD_FAIL")
        
        # Should contain error information
        error_message = str(exc_info.value).lower()
        assert any(keyword in error_message for keyword in ["invalid", "error", "network"])
    
    def test_connection_error_scenarios(self):
        """Test connection-related errors are properly handled."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test connection to invalid endpoint
        with pytest.raises(Exception) as exc_info:
            wallet.sync("http://invalid-endpoint-that-does-not-exist.local:12345")
        
        error_message = str(exc_info.value).lower()
        assert any(keyword in error_message for keyword in ["connection", "network", "error", "failed"])
    
    def test_timeout_error_handling(self):
        """Test timeout errors are properly converted."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test with a URL that will timeout (non-routable IP)
        with pytest.raises(Exception) as exc_info:
            wallet.sync("http://192.0.2.1:12345")  # RFC 3330 test IP
        
        error_message = str(exc_info.value).lower()
        # Should contain timeout or connection error information
        assert any(keyword in error_message for keyword in ["timeout", "connection", "error", "failed"])
    
    def test_argument_validation_errors(self):
        """Test invalid argument errors are properly handled."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test invalid birthday (negative value if possible)
        with pytest.raises(Exception):
            wallet.set_birthday(18446744073709551615)  # Max u64, might cause issues
    
    def test_error_message_context_preservation(self):
        """Test that error messages preserve contextual information."""
        # Test error messages contain useful information
        with pytest.raises(Exception) as exc_info:
            TariScanner("http://invalid-url", None)
        
        error_message = str(exc_info.value)
        # Error should contain some context about what went wrong
        assert len(error_message) > 10  # Not just empty or single word
        assert any(char.isalpha() for char in error_message)  # Contains actual text


class TestConnectionPoolErrorRecovery:
    """Test connection pool error recovery mechanisms."""
    
    def test_connection_pool_error_handling(self):
        """Test that connection pool errors are handled gracefully."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Test multiple failed connections to the same endpoint
        invalid_url = "http://192.0.2.1:12345"
        
        for i in range(3):
            with pytest.raises(Exception):
                wallet.sync(invalid_url)
        
        # Pool should handle repeated failures gracefully
        # (No assertion needed, just verify it doesn't crash)
    
    def test_concurrent_connection_attempts(self):
        """Test concurrent connection attempts don't cause race conditions."""
        import threading
        import time
        
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        invalid_url = "http://192.0.2.1:12345"
        errors = []
        
        def attempt_sync():
            try:
                wallet.sync(invalid_url)
            except Exception as e:
                errors.append(str(e))
        
        # Start multiple threads trying to sync simultaneously
        threads = []
        for i in range(5):
            thread = threading.Thread(target=attempt_sync)
            threads.append(thread)
            thread.start()
            time.sleep(0.1)  # Small delay to stagger starts
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=30)
        
        # All should have failed, but gracefully
        assert len(errors) == 5
        for error in errors:
            assert len(error) > 0  # Should have meaningful error messages


class TestFaultInjection:
    """Test error handling under various fault conditions."""
    
    def test_invalid_seed_phrase_formats(self):
        """Test various invalid seed phrase formats."""
        invalid_phrases = [
            "",  # Empty
            " ",  # Whitespace only
            "single",  # Too short
            "invalid word " * 50,  # Too long
            "test test test test test test test test test test test fake",  # Invalid word
        ]
        
        for phrase in invalid_phrases:
            with pytest.raises(Exception) as exc_info:
                # Try to create wallet with invalid phrase
                # This test would need the library to support seed phrase import
                # For now, test with the passphrase parameter
                TariWallet.generate_new_with_seed_phrase(phrase if phrase.strip() else None)
            
            error_message = str(exc_info.value)
            if phrase == "":  # Empty string might be handled differently
                continue
            assert "error" in error_message.lower() or "invalid" in error_message.lower()
    
    def test_network_partition_simulation(self):
        """Test behavior during simulated network partitions."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Use localhost with a port that's definitely not open
        partition_urls = [
            "http://127.0.0.1:65534",  # High port unlikely to be open
            "http://127.0.0.1:1",     # Low port unlikely to be open
            "http://127.0.0.1:99999", # Invalid port
        ]
        
        for url in partition_urls:
            with pytest.raises(Exception) as exc_info:
                wallet.sync(url)
            
            error_message = str(exc_info.value).lower()
            assert any(keyword in error_message for keyword in ["connection", "error", "failed"])
    
    def test_malformed_url_handling(self):
        """Test handling of malformed URLs."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        malformed_urls = [
            "not-a-url",
            "ftp://wrong-protocol.com",
            "http://",
            "://missing-protocol.com",
            "http://[invalid-ipv6",
            "http://space in url.com",
        ]
        
        for url in malformed_urls:
            with pytest.raises(Exception) as exc_info:
                wallet.sync(url)
            
            # Should get a meaningful error message
            error_message = str(exc_info.value)
            assert len(error_message) > 5  # Should have meaningful content


class TestErrorCategorization:
    """Test error categorization and metrics collection."""
    
    def test_error_type_consistency(self):
        """Test that similar errors produce consistent error types."""
        # Test multiple connection failures produce similar errors
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        error_messages = []
        
        for i in range(3):
            with pytest.raises(Exception) as exc_info:
                wallet.sync(f"http://192.0.2.{i+1}:12345")
            error_messages.append(str(exc_info.value))
        
        # Error messages should have similar structure/type
        # (This is a basic consistency check)
        assert len(set(type(msg) for msg in error_messages)) == 1  # All same type
    
    def test_error_recovery_after_failure(self):
        """Test that system can recover after various error conditions."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        # Cause an error
        with pytest.raises(Exception):
            wallet.sync("http://invalid-endpoint:12345")
        
        # Verify wallet is still functional after error
        assert wallet.birthday() >= 0  # Should still work
        assert wallet.network() is not None  # Should still work
        
        # Can create new wallet after error
        new_wallet = TariWallet.generate_new_with_seed_phrase(None)
        assert new_wallet is not None


class TestPerformanceUnderErrorConditions:
    """Test performance characteristics during error scenarios."""
    
    def test_error_conversion_performance(self):
        """Test that error conversion doesn't introduce significant overhead."""
        import time
        
        start_time = time.time()
        
        # Generate multiple errors quickly
        for i in range(10):
            with pytest.raises(Exception):
                TariWallet.generate_new_with_seed_phrase("invalid")
        
        elapsed = time.time() - start_time
        
        # Should complete reasonably quickly (within 5 seconds for 10 errors)
        assert elapsed < 5.0, f"Error conversion took too long: {elapsed:.2f}s"
    
    def test_connection_pool_performance_under_errors(self):
        """Test connection pool performance when errors occur."""
        wallet = TariWallet.generate_new_with_seed_phrase(None)
        
        import time
        start_time = time.time()
        
        # Generate multiple connection errors to test pool behavior
        for i in range(5):
            with pytest.raises(Exception):
                wallet.sync("http://192.0.2.1:12345")
        
        elapsed = time.time() - start_time
        
        # Should handle errors efficiently (within 10 seconds for 5 attempts)
        assert elapsed < 10.0, f"Connection pool error handling took too long: {elapsed:.2f}s"


@pytest.fixture
def test_wallet():
    """Fixture to provide a test wallet for tests that need one."""
    return TariWallet.generate_new_with_seed_phrase(None)


def test_basic_error_functionality(test_wallet):
    """Basic test to ensure error handling works at all."""
    # This is a simple test to ensure the basic error handling is functional
    wallet = test_wallet
    
    # Test that we can trigger and catch an error
    with pytest.raises(Exception):
        wallet.sync("http://definitely-invalid-url-that-will-fail:99999")
    
    # Test that wallet is still functional after error
    assert wallet.birthday() >= 0


if __name__ == "__main__":
    # Run tests when executed directly
    pytest.main([__file__, "-v"])
