#!/usr/bin/env python3
"""
Comprehensive test suite for stealth address operations.

Tests core TariStealthAddress functionality (create_stealth_address, recover_stealth_key,
scan_for_outputs, generate_shared_secret) with comprehensive error handling and edge case
validation. Uses mock output data with realistic formats but expects limited recovery
due to mock nature.
"""

import pytest
import time
from typing import Dict, List, Tuple

# Custom assertion helpers for stealth address testing
def assert_valid_stealth_address_info(addr_info):
    """Assert that a StealthAddressInfo object has valid structure and hex values."""
    assert hasattr(addr_info, 'view_public_key'), "Missing view_public_key"
    assert hasattr(addr_info, 'spend_public_key'), "Missing spend_public_key"
    assert hasattr(addr_info, 'stealth_spending_key'), "Missing stealth_spending_key"
    assert hasattr(addr_info, 'sender_offset_public_key'), "Missing sender_offset_public_key"
    
    # Validate hex strings (all should be 64 chars = 32 bytes)
    fields = ['view_public_key', 'spend_public_key', 'stealth_spending_key', 'sender_offset_public_key']
    for field in fields:
        value = getattr(addr_info, field)
        assert isinstance(value, str), f"{field} should be string, got {type(value)}"
        assert len(value) == 64, f"{field} should be 64 chars, got {len(value)}"
        
        try:
            int(value, 16)
        except ValueError:
            pytest.fail(f"{field} '{value[:20]}...' is not valid hex")


def assert_valid_scan_result(scan_result):
    """Assert that a StealthScanResult has valid structure."""
    assert hasattr(scan_result, 'addresses'), "Missing addresses"
    assert hasattr(scan_result, 'total_scanned'), "Missing total_scanned"
    assert hasattr(scan_result, 'addresses_found'), "Missing addresses_found"
    
    assert isinstance(scan_result.addresses, list), "addresses should be list"
    assert isinstance(scan_result.total_scanned, int), "total_scanned should be int"
    assert isinstance(scan_result.addresses_found, int), "addresses_found should be int"
    
    assert scan_result.addresses_found == len(scan_result.addresses), "addresses_found should match addresses length"


class TestStealthAddressImports:
    """Test that stealth address classes are available."""
    
    def test_stealth_address_availability(self, wallet_lib_module):
        """Test that TariStealthAddress is available in the module."""
        assert hasattr(wallet_lib_module, 'TariStealthAddress'), "TariStealthAddress not found in wallet_lib"
        TariStealthAddress = wallet_lib_module.TariStealthAddress
        assert callable(TariStealthAddress), "TariStealthAddress should be callable"
    
    def test_stealth_types_availability(self, wallet_lib_module):
        """Test that stealth address data types are available."""
        required_types = ['StealthAddressInfo', 'StealthScanResult']
        
        for type_name in required_types:
            assert hasattr(wallet_lib_module, type_name), f"{type_name} not found in wallet_lib"
            type_class = getattr(wallet_lib_module, type_name)
            assert callable(type_class), f"{type_name} should be callable"


class TestStealthAddressInfo:
    """Test suite for StealthAddressInfo data structure."""
    
    @pytest.fixture
    def StealthAddressInfo(self, wallet_lib_module):
        """Provide StealthAddressInfo class for tests."""
        return wallet_lib_module.StealthAddressInfo
    
    @pytest.fixture
    def sample_stealth_keys(self):
        """Provide sample stealth address keys for testing."""
        return {
            'view_public_key': '0123456789abcdef' * 4,
            'spend_public_key': '1123456789abcdef' * 4,
            'stealth_spending_key': '2123456789abcdef' * 4,
            'sender_offset_public_key': '3123456789abcdef' * 4,
        }
    
    def test_stealth_address_info_creation(self, StealthAddressInfo, sample_stealth_keys):
        """Test creating StealthAddressInfo objects."""
        addr_info = StealthAddressInfo(
            sample_stealth_keys['view_public_key'],
            sample_stealth_keys['spend_public_key'],
            sample_stealth_keys['stealth_spending_key'],
            sample_stealth_keys['sender_offset_public_key']
        )
        
        assert_valid_stealth_address_info(addr_info)
        assert addr_info.view_public_key == sample_stealth_keys['view_public_key']
        assert addr_info.spend_public_key == sample_stealth_keys['spend_public_key']
        assert addr_info.stealth_spending_key == sample_stealth_keys['stealth_spending_key']
        assert addr_info.sender_offset_public_key == sample_stealth_keys['sender_offset_public_key']
    
    def test_stealth_address_info_string_representations(self, StealthAddressInfo, sample_stealth_keys):
        """Test string representations of StealthAddressInfo."""
        addr_info = StealthAddressInfo(**sample_stealth_keys)
        
        # String representation should include key prefixes
        str_repr = str(addr_info)
        assert "StealthAddressInfo" in str_repr
        assert sample_stealth_keys['view_public_key'][:8] in str_repr
        
        # Repr should be same as str
        repr_str = repr(addr_info)
        assert str_repr == repr_str
    
    def test_stealth_address_info_equality_and_hashing(self, StealthAddressInfo, sample_stealth_keys):
        """Test equality and hashing of StealthAddressInfo objects."""
        addr1 = StealthAddressInfo(**sample_stealth_keys)
        addr2 = StealthAddressInfo(**sample_stealth_keys)
        
        # Different keys
        different_keys = sample_stealth_keys.copy()
        different_keys['view_public_key'] = 'fedcba9876543210' * 4
        addr3 = StealthAddressInfo(**different_keys)
        
        # Equality
        assert addr1 == addr2
        assert addr1 != addr3
        
        # Hashing (for dict keys)
        addr_dict = {addr1: "value1", addr3: "value2"}
        assert addr_dict[addr2] == "value1"  # Should find addr1


class TestStealthScanResult:
    """Test suite for StealthScanResult data structure."""
    
    @pytest.fixture
    def StealthScanResult(self, wallet_lib_module):
        """Provide StealthScanResult class for tests."""
        return wallet_lib_module.StealthScanResult
    
    @pytest.fixture
    def StealthAddressInfo(self, wallet_lib_module):
        """Provide StealthAddressInfo class for tests."""
        return wallet_lib_module.StealthAddressInfo
    
    @pytest.fixture
    def sample_addresses(self, StealthAddressInfo):
        """Provide sample stealth addresses for testing."""
        return [
            StealthAddressInfo(
                '0123456789abcdef' * 4,
                '1123456789abcdef' * 4,
                '2123456789abcdef' * 4,
                '3123456789abcdef' * 4
            ),
            StealthAddressInfo(
                'fedcba9876543210' * 4,
                'edcba9876543210f' * 4,
                'dcba9876543210fe' * 4,
                'cba9876543210fed' * 4
            )
        ]
    
    def test_scan_result_creation(self, StealthScanResult, sample_addresses):
        """Test creating StealthScanResult objects."""
        result = StealthScanResult(sample_addresses, 100)
        
        assert_valid_scan_result(result)
        assert result.addresses == sample_addresses
        assert result.total_scanned == 100
        assert result.addresses_found == 2
    
    def test_scan_result_empty(self, StealthScanResult):
        """Test creating empty scan results."""
        result = StealthScanResult([], 50)
        
        assert_valid_scan_result(result)
        assert len(result.addresses) == 0
        assert result.total_scanned == 50
        assert result.addresses_found == 0
        assert not result.is_successful()
    
    def test_scan_result_methods(self, StealthScanResult, sample_addresses):
        """Test StealthScanResult methods."""
        result = StealthScanResult(sample_addresses, 100)
        
        # is_successful
        assert result.is_successful()
        
        # get_addresses
        all_addresses = result.get_addresses()
        assert all_addresses == sample_addresses
        
        # Length
        assert len(result) == 2
    
    def test_scan_result_indexing(self, StealthScanResult, sample_addresses):
        """Test StealthScanResult indexing and iteration."""
        result = StealthScanResult(sample_addresses, 100)
        
        # Indexing
        assert result[0] == sample_addresses[0]
        assert result[1] == sample_addresses[1]
        assert result[-1] == sample_addresses[1]  # Negative indexing
        
        # Out of bounds
        with pytest.raises(IndexError):
            result[2]
        
        # Iteration
        iterated = list(result)
        assert iterated == sample_addresses
    
    def test_scan_result_merge(self, StealthScanResult, StealthAddressInfo):
        """Test merging scan results."""
        # Create two results
        addr1 = StealthAddressInfo('0123456789abcdef' * 4, '1123456789abcdef' * 4,
                                  '2123456789abcdef' * 4, '3123456789abcdef' * 4)
        addr2 = StealthAddressInfo('fedcba9876543210' * 4, 'edcba9876543210f' * 4,
                                  'dcba9876543210fe' * 4, 'cba9876543210fed' * 4)
        
        result1 = StealthScanResult([addr1], 50)
        result2 = StealthScanResult([addr2], 75)
        
        # Merge
        merged = result1.merge(result2)
        
        assert_valid_scan_result(merged)
        assert merged.addresses_found == 2
        assert merged.total_scanned == 125
        assert len(merged.addresses) == 2
        assert addr1 in merged.addresses
        assert addr2 in merged.addresses
    
    def test_scan_result_string_representations(self, StealthScanResult, sample_addresses):
        """Test string representations of StealthScanResult."""
        result = StealthScanResult(sample_addresses, 100)
        
        str_repr = str(result)
        assert "StealthScanResult" in str_repr
        assert "found=2" in str_repr
        assert "scanned=100" in str_repr
        
        # Repr should be same as str
        repr_str = repr(result)
        assert str_repr == repr_str


class TestTariStealthAddress:
    """Test suite for TariStealthAddress core functionality."""
    
    @pytest.fixture
    def TariStealthAddress(self, wallet_lib_module):
        """Provide TariStealthAddress class for tests."""
        return wallet_lib_module.TariStealthAddress
    
    @pytest.fixture
    def stealth_service(self, TariStealthAddress):
        """Provide stealth address service instance."""
        return TariStealthAddress()
    
    @pytest.fixture
    def test_keys(self):
        """Provide test keys for stealth address operations."""
        return {
            'view_key': '0123456789abcdef' * 4,
            'spend_key': '1123456789abcdef' * 4,
            'sender_key': '2123456789abcdef' * 4,
            'private_key': '3123456789abcdef' * 4,
            'public_key': '4123456789abcdef' * 4,
        }
    
    def test_stealth_service_creation(self, TariStealthAddress):
        """Test creating stealth address service."""
        service = TariStealthAddress()
        assert service is not None
    
    def test_stealth_address_generation(self, stealth_service, test_keys):
        """Test stealth address generation."""
        addr_info = stealth_service.create_stealth_address(
            test_keys['view_key'],
            test_keys['spend_key'],
            test_keys['sender_key']
        )
        
        assert_valid_stealth_address_info(addr_info)
        
        # Generated keys should be different from input keys
        assert addr_info.view_public_key != test_keys['view_key']
        assert addr_info.spend_public_key != test_keys['spend_key']
        assert addr_info.stealth_spending_key != test_keys['view_key']
        assert addr_info.sender_offset_public_key != test_keys['sender_key']
    
    def test_stealth_address_generation_determinism(self, stealth_service, test_keys):
        """Test that stealth address generation is deterministic."""
        # Same inputs should produce same outputs
        addr1 = stealth_service.create_stealth_address(
            test_keys['view_key'],
            test_keys['spend_key'],
            test_keys['sender_key']
        )
        
        addr2 = stealth_service.create_stealth_address(
            test_keys['view_key'],
            test_keys['spend_key'],
            test_keys['sender_key']
        )
        
        assert addr1 == addr2
    
    def test_stealth_address_generation_different_inputs(self, stealth_service, test_keys):
        """Test that different inputs produce different stealth addresses."""
        addr1 = stealth_service.create_stealth_address(
            test_keys['view_key'],
            test_keys['spend_key'],
            test_keys['sender_key']
        )
        
        # Different view key
        different_view = 'fedcba9876543210' * 4
        addr2 = stealth_service.create_stealth_address(
            different_view,
            test_keys['spend_key'],
            test_keys['sender_key']
        )
        
        assert addr1 != addr2
        assert addr1.view_public_key != addr2.view_public_key
    
    def test_shared_secret_generation(self, stealth_service, test_keys):
        """Test shared secret generation."""
        shared_secret = stealth_service.generate_shared_secret(
            test_keys['private_key'],
            test_keys['public_key']
        )
        
        assert isinstance(shared_secret, str), "Shared secret should be string"
        assert len(shared_secret) == 64, f"Shared secret should be 64 chars, got {len(shared_secret)}"
        
        # Should be valid hex
        try:
            int(shared_secret, 16)
        except ValueError:
            pytest.fail(f"Shared secret '{shared_secret[:20]}...' is not valid hex")
    
    def test_shared_secret_determinism(self, stealth_service, test_keys):
        """Test that shared secret generation is deterministic."""
        secret1 = stealth_service.generate_shared_secret(
            test_keys['private_key'],
            test_keys['public_key']
        )
        
        secret2 = stealth_service.generate_shared_secret(
            test_keys['private_key'],
            test_keys['public_key']
        )
        
        assert secret1 == secret2
    
    def test_stealth_key_recovery_with_mock_data(self, stealth_service, test_keys):
        """Test stealth key recovery with mock output data."""
        # Mock output data (realistic format but will likely fail recovery)
        mock_outputs = [
            {
                "sender_offset": "deadbeef" * 8,
                "script_key": "cafebabe" * 8
            },
            {
                "sender_offset": "12345678" * 8,
                "script_key": "87654321" * 8
            }
        ]
        
        # Attempt recovery (expecting failure with mock data)
        try:
            recovered = stealth_service.recover_stealth_key(
                test_keys['view_key'],
                test_keys['spend_key'],
                mock_outputs
            )
            
            # If it succeeds, validate the result structure
            assert isinstance(recovered, list), "Recovery result should be list"
            # Each recovered key should be valid hex if present
            for key in recovered:
                if key is not None:
                    assert isinstance(key, str), "Recovered key should be string"
                    assert len(key) == 64, "Recovered key should be 64 chars"
                    
        except Exception as e:
            # Expected to fail with mock data - this is acceptable
            assert "recovery failed" in str(e).lower() or "invalid" in str(e).lower()
    
    def test_output_scanning_with_mock_data(self, stealth_service, test_keys):
        """Test output scanning with mock data."""
        # Mock output data (realistic format)
        mock_outputs = [
            {"sender_offset": "deadbeef" * 8, "script_key": "cafebabe" * 8},
            {"sender_offset": "12345678" * 8, "script_key": "87654321" * 8},
            {"sender_offset": "abcdef12" * 8, "script_key": "34567890" * 8},
        ]
        
        # Scan outputs (expecting empty results with mock data)
        scan_result = stealth_service.scan_for_outputs(
            test_keys['view_key'],
            test_keys['spend_key'],
            mock_outputs
        )
        
        assert_valid_scan_result(scan_result)
        assert scan_result.total_scanned == 3
        # With mock data, we expect no addresses found
        assert scan_result.addresses_found == 0
        assert not scan_result.is_successful()
    
    def test_chunked_processing_validation(self, stealth_service, test_keys):
        """Test that chunked processing works correctly for large datasets."""
        # Create large mock dataset (>1000 items to test chunking)
        large_mock_outputs = []
        for i in range(1500):  # Larger than fixed chunk size of 1000
            large_mock_outputs.append({
                "sender_offset": f"{i:08x}" * 8,
                "script_key": f"{i:08x}" * 8
            })
        
        # Should handle large dataset without memory issues
        scan_result = stealth_service.scan_for_outputs(
            test_keys['view_key'],
            test_keys['spend_key'],
            large_mock_outputs
        )
        
        assert_valid_scan_result(scan_result)
        assert scan_result.total_scanned == 1500
        # With mock data, we expect no addresses found but processing should complete
        assert scan_result.addresses_found == 0


class TestStealthAddressErrorHandling:
    """Test error handling in stealth address operations."""
    
    @pytest.fixture
    def TariStealthAddress(self, wallet_lib_module):
        """Provide TariStealthAddress class for tests."""
        return wallet_lib_module.TariStealthAddress
    
    @pytest.fixture
    def stealth_service(self, TariStealthAddress):
        """Provide stealth address service instance."""
        return TariStealthAddress()
    
    def test_invalid_hex_key_errors(self, stealth_service):
        """Test proper error handling for invalid hex keys."""
        # Invalid hex characters
        with pytest.raises(ValueError):
            stealth_service.create_stealth_address(
                "invalid_hex",
                "1123456789abcdef" * 4,
                "2123456789abcdef" * 4
            )
        
        # Wrong length keys
        with pytest.raises(ValueError):
            stealth_service.create_stealth_address(
                "abc123",  # Too short
                "1123456789abcdef" * 4,
                "2123456789abcdef" * 4
            )
    
    def test_empty_output_list_handling(self, stealth_service):
        """Test handling of empty output lists."""
        test_keys = {
            'view_key': '0123456789abcdef' * 4,
            'spend_key': '1123456789abcdef' * 4,
        }
        
        # Empty output list should return empty result
        scan_result = stealth_service.scan_for_outputs(
            test_keys['view_key'],
            test_keys['spend_key'],
            []
        )
        
        assert_valid_scan_result(scan_result)
        assert scan_result.total_scanned == 0
        assert scan_result.addresses_found == 0
        assert not scan_result.is_successful()
    
    def test_invalid_output_format_errors(self, stealth_service):
        """Test error handling for invalid output formats."""
        test_keys = {
            'view_key': '0123456789abcdef' * 4,
            'spend_key': '1123456789abcdef' * 4,
        }
        
        # Missing required fields
        invalid_outputs = [
            {"sender_offset": "deadbeef" * 8},  # Missing script_key
            {"script_key": "cafebabe" * 8},     # Missing sender_offset
            {},                                 # Missing both
        ]
        
        for invalid_output in invalid_outputs:
            with pytest.raises((KeyError, ValueError)):
                stealth_service.scan_for_outputs(
                    test_keys['view_key'],
                    test_keys['spend_key'],
                    [invalid_output]
                )
    
    def test_shared_secret_error_handling(self, stealth_service):
        """Test error handling in shared secret generation."""
        # Invalid private key
        with pytest.raises(ValueError):
            stealth_service.generate_shared_secret("invalid", "1123456789abcdef" * 4)
        
        # Invalid public key
        with pytest.raises(ValueError):
            stealth_service.generate_shared_secret("0123456789abcdef" * 4, "invalid")
        
        # Wrong length keys
        with pytest.raises(ValueError):
            stealth_service.generate_shared_secret("abc", "def")


class TestStealthAddressPerformance:
    """Performance tests for stealth address operations."""
    
    @pytest.fixture
    def TariStealthAddress(self, wallet_lib_module):
        """Provide TariStealthAddress class for tests."""
        return wallet_lib_module.TariStealthAddress
    
    @pytest.fixture
    def stealth_service(self, TariStealthAddress):
        """Provide stealth address service instance."""
        return TariStealthAddress()
    
    def test_stealth_address_generation_performance(self, stealth_service, performance_threshold_seconds):
        """Test stealth address generation performance."""
        test_keys = {
            'view_key': '0123456789abcdef' * 4,
            'spend_key': '1123456789abcdef' * 4,
            'sender_key': '2123456789abcdef' * 4,
        }
        
        start_time = time.time()
        for _ in range(10):  # Multiple operations
            addr_info = stealth_service.create_stealth_address(**test_keys)
        end_time = time.time()
        
        avg_time = (end_time - start_time) / 10
        threshold = performance_threshold_seconds.get('stealth_address_generation', 0.5)
        
        assert avg_time < threshold, f"Stealth address generation too slow: {avg_time:.3f}s > {threshold}s"
    
    def test_shared_secret_performance(self, stealth_service, performance_threshold_seconds):
        """Test shared secret generation performance."""
        private_key = '0123456789abcdef' * 4
        public_key = 'fedcba9876543210' * 4
        
        start_time = time.time()
        for _ in range(10):
            secret = stealth_service.generate_shared_secret(private_key, public_key)
        end_time = time.time()
        
        avg_time = (end_time - start_time) / 10
        threshold = performance_threshold_seconds.get('shared_secret_generation', 0.1)
        
        assert avg_time < threshold, f"Shared secret generation too slow: {avg_time:.3f}s > {threshold}s"
    
    def test_large_batch_scanning_performance(self, stealth_service, performance_threshold_seconds):
        """Test performance of scanning large output batches."""
        test_keys = {
            'view_key': '0123456789abcdef' * 4,
            'spend_key': '1123456789abcdef' * 4,
        }
        
        # Create large output batch
        large_outputs = []
        for i in range(500):  # Reasonable test size
            large_outputs.append({
                "sender_offset": f"{i:08x}" * 8,
                "script_key": f"{i:08x}" * 8
            })
        
        start_time = time.time()
        scan_result = stealth_service.scan_for_outputs(
            test_keys['view_key'],
            test_keys['spend_key'],
            large_outputs
        )
        end_time = time.time()
        
        total_time = end_time - start_time
        threshold = performance_threshold_seconds.get('large_batch_scanning', 5.0)
        
        assert total_time < threshold, f"Large batch scanning too slow: {total_time:.3f}s > {threshold}s"
        assert scan_result.total_scanned == 500


class TestStealthAddressIntegration:
    """Integration tests for stealth address functionality with other components."""
    
    @pytest.fixture
    def TariStealthAddress(self, wallet_lib_module):
        """Provide TariStealthAddress class for tests."""
        return wallet_lib_module.TariStealthAddress
    
    @pytest.fixture
    def TariKeyManager(self, wallet_lib_module):
        """Provide TariKeyManager class for tests."""
        return wallet_lib_module.TariKeyManager
    
    def test_stealth_address_with_key_manager_integration(self, TariStealthAddress, TariKeyManager, test_wallet):
        """Test stealth address operations with key manager derived keys."""
        # Create key manager from wallet
        km = TariKeyManager.from_wallet(test_wallet)
        keys = km.derive_view_and_spend_keys()
        
        # Use derived keys with stealth address service
        stealth_service = TariStealthAddress()
        sender_key = '2123456789abcdef' * 4  # Mock sender key
        
        addr_info = stealth_service.create_stealth_address(
            keys['view_key'],
            keys['spend_key'],
            sender_key
        )
        
        assert_valid_stealth_address_info(addr_info)
    
    def test_multiple_stealth_services_independence(self, TariStealthAddress):
        """Test that multiple stealth address service instances are independent."""
        service1 = TariStealthAddress()
        service2 = TariStealthAddress()
        
        test_keys = {
            'view_key': '0123456789abcdef' * 4,
            'spend_key': '1123456789abcdef' * 4,
            'sender_key': '2123456789abcdef' * 4,
        }
        
        # Both services should produce same result for same inputs
        addr1 = service1.create_stealth_address(**test_keys)
        addr2 = service2.create_stealth_address(**test_keys)
        
        assert addr1 == addr2  # Should be deterministic
