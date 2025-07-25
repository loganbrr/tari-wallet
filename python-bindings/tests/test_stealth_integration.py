#!/usr/bin/env python3
"""
End-to-end stealth address workflow integration tests.

Tests complete stealth address workflows combining TariKeyManager, TariStealthAddress,
and scanner connectivity for comprehensive functionality validation.
"""

import pytest
import time
from typing import Dict, List, Tuple

# Integration test helpers
def assert_integration_workflow_success(workflow_result):
    """Assert that an integration workflow completed successfully."""
    assert hasattr(workflow_result, 'success'), "Workflow result missing success indicator"
    assert workflow_result.success, f"Integration workflow failed: {getattr(workflow_result, 'error', 'Unknown error')}"


class TestStealthAddressIntegration:
    """End-to-end integration tests for stealth address workflows."""
    
    def test_imports_integration(self, wallet_lib_module):
        """Test that all stealth address components are available together."""
        required_classes = [
            'TariWallet', 'TariKeyManager', 'TariStealthAddress', 
            'KeyDerivationPath', 'StealthAddressInfo', 'StealthScanResult'
        ]
        
        for class_name in required_classes:
            assert hasattr(wallet_lib_module, class_name), f"{class_name} not available for integration"
            class_obj = getattr(wallet_lib_module, class_name)
            assert callable(class_obj), f"{class_name} should be callable"
    
    @pytest.fixture
    def integration_components(self, wallet_lib_module, test_wallet):
        """Provide all components needed for integration testing."""
        return {
            'wallet': test_wallet,
            'key_manager': wallet_lib_module.TariKeyManager.from_wallet(test_wallet),
            'stealth_service': wallet_lib_module.TariStealthAddress(),
            'KeyDerivationPath': wallet_lib_module.KeyDerivationPath,
            'StealthAddressInfo': wallet_lib_module.StealthAddressInfo,
        }
    
    def test_complete_stealth_workflow(self, integration_components):
        """Test complete end-to-end stealth address workflow."""
        wallet = integration_components['wallet']
        key_manager = integration_components['key_manager']
        stealth_service = integration_components['stealth_service']
        
        # Step 1: Derive keys from wallet
        keys = key_manager.derive_view_and_spend_keys()
        assert 'view_key' in keys
        assert 'spend_key' in keys
        assert len(keys['view_key']) == 64  # 32 bytes hex
        assert len(keys['spend_key']) == 64  # 32 bytes hex
        
        # Step 2: Generate shared secret
        sender_private_key = "deadbeef" * 8  # Mock sender key
        sender_public_key = "cafebabe" * 8   # Mock public key
        shared_secret = stealth_service.generate_shared_secret(sender_private_key, sender_public_key)
        assert len(shared_secret) == 64
        
        # Step 3: Create stealth address
        stealth_addr = stealth_service.create_stealth_address(
            keys['view_key'],
            keys['spend_key'],
            sender_private_key
        )
        
        # Validate stealth address structure
        assert hasattr(stealth_addr, 'view_public_key')
        assert hasattr(stealth_addr, 'spend_public_key')
        assert hasattr(stealth_addr, 'stealth_spending_key')
        assert hasattr(stealth_addr, 'sender_offset_public_key')
        
        # Step 4: Test output scanning (mock data)
        mock_outputs = [
            {"sender_offset": "deadbeef" * 8, "script_key": "cafebabe" * 8},
            {"sender_offset": "12345678" * 8, "script_key": "87654321" * 8}
        ]
        
        scan_result = stealth_service.scan_for_outputs(
            keys['view_key'],
            keys['spend_key'],
            mock_outputs
        )
        
        # Validate scan result
        assert hasattr(scan_result, 'total_scanned')
        assert hasattr(scan_result, 'addresses_found')
        assert scan_result.total_scanned == 2
        # With mock data, we expect no real addresses found
        assert scan_result.addresses_found == 0
    
    def test_key_derivation_integration(self, integration_components):
        """Test key derivation integration with different paths."""
        key_manager = integration_components['key_manager']
        KeyDerivationPath = integration_components['KeyDerivationPath']
        
        # Test different derivation paths
        test_paths = [
            "m/44'/0'/0'",
            "m/44'/1'/0'", 
            "m/0/0/0",
            "m/2147483647"  # Large number
        ]
        
        derived_keys = {}
        for path_str in test_paths:
            # Test string-based derivation
            path = KeyDerivationPath.from_string(path_str)
            derived_key = key_manager.derive_key_from_path(path)
            derived_keys[path_str] = derived_key
            
            # Validate derived key
            assert len(derived_key) == 64
            assert derived_key not in derived_keys.values() or list(derived_keys.values()).count(derived_key) == 1
        
        # Ensure different paths produce different keys
        unique_keys = set(derived_keys.values())
        assert len(unique_keys) == len(test_paths), "Different paths should produce different keys"
    
    def test_multiple_wallet_stealth_independence(self, wallet_lib_module, multiple_test_wallets):
        """Test that different wallets produce independent stealth addresses."""
        if len(multiple_test_wallets) < 2:
            pytest.skip("Need at least 2 wallets for independence testing")
        
        stealth_addresses = []
        sender_key = "deadbeef" * 8  # Same sender for all
        
        for wallet in multiple_test_wallets[:2]:  # Test first 2 wallets
            # Create key manager for this wallet
            key_manager = wallet_lib_module.TariKeyManager.from_wallet(wallet)
            keys = key_manager.derive_view_and_spend_keys()
            
            # Create stealth address
            stealth_service = wallet_lib_module.TariStealthAddress()
            stealth_addr = stealth_service.create_stealth_address(
                keys['view_key'],
                keys['spend_key'],
                sender_key
            )
            
            stealth_addresses.append(stealth_addr)
        
        # Verify independence - different wallets should produce different stealth addresses
        addr1, addr2 = stealth_addresses[0], stealth_addresses[1]
        assert addr1.view_public_key != addr2.view_public_key
        assert addr1.spend_public_key != addr2.spend_public_key
        assert addr1.stealth_spending_key != addr2.stealth_spending_key
        # sender_offset_public_key might be same since same sender_key used
    
    def test_deterministic_stealth_operations(self, integration_components):
        """Test that stealth operations are deterministic."""
        key_manager = integration_components['key_manager']
        stealth_service = integration_components['stealth_service']
        
        # Derive keys twice - should be same
        keys1 = key_manager.derive_view_and_spend_keys()
        keys2 = key_manager.derive_view_and_spend_keys()
        assert keys1 == keys2
        
        # Create stealth address twice with same inputs - should be same
        sender_key = "deadbeef" * 8
        stealth_addr1 = stealth_service.create_stealth_address(
            keys1['view_key'], keys1['spend_key'], sender_key
        )
        stealth_addr2 = stealth_service.create_stealth_address(
            keys2['view_key'], keys2['spend_key'], sender_key
        )
        
        assert stealth_addr1 == stealth_addr2
    
    def test_large_dataset_integration(self, integration_components):
        """Test integration with large datasets to validate chunking."""
        stealth_service = integration_components['stealth_service']
        key_manager = integration_components['key_manager']
        
        keys = key_manager.derive_view_and_spend_keys()
        
        # Create large dataset (>1000 to test chunking)
        large_outputs = []
        for i in range(1500):
            large_outputs.append({
                "sender_offset": f"{i:08x}" * 8,
                "script_key": f"{(i+1):08x}" * 8
            })
        
        # Should handle large dataset without issues
        start_time = time.time()
        scan_result = stealth_service.scan_for_outputs(
            keys['view_key'],
            keys['spend_key'],
            large_outputs
        )
        processing_time = time.time() - start_time
        
        # Validate processing completed
        assert scan_result.total_scanned == 1500
        assert scan_result.addresses_found == 0  # Mock data
        
        # Should complete in reasonable time (chunking should help)
        assert processing_time < 10.0, f"Large dataset processing too slow: {processing_time:.2f}s"
    
    def test_error_recovery_integration(self, integration_components):
        """Test error recovery in integrated workflows."""
        key_manager = integration_components['key_manager']
        stealth_service = integration_components['stealth_service']
        
        keys = key_manager.derive_view_and_spend_keys()
        
        # Test with invalid output format - should handle gracefully
        invalid_outputs = [
            {"invalid_field": "value"},  # Missing required fields
            {"sender_offset": "invalid_hex"},  # Invalid hex
        ]
        
        # Should fail gracefully with proper error messages
        for invalid_output in invalid_outputs:
            with pytest.raises((KeyError, ValueError)) as exc_info:
                stealth_service.scan_for_outputs(
                    keys['view_key'],
                    keys['spend_key'],
                    [invalid_output]
                )
            
            # Error should be informative
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in ["invalid", "missing", "key", "format"])
    
    def test_memory_efficiency_integration(self, integration_components):
        """Test memory efficiency of integrated operations."""
        stealth_service = integration_components['stealth_service']
        key_manager = integration_components['key_manager']
        
        keys = key_manager.derive_view_and_spend_keys()
        
        # Process multiple medium-sized batches to test memory reuse
        batch_size = 500
        total_processed = 0
        
        for batch_num in range(5):  # 5 batches of 500 = 2500 total
            batch_outputs = []
            for i in range(batch_size):
                idx = batch_num * batch_size + i
                batch_outputs.append({
                    "sender_offset": f"{idx:08x}" * 8,
                    "script_key": f"{(idx+1):08x}" * 8
                })
            
            scan_result = stealth_service.scan_for_outputs(
                keys['view_key'],
                keys['spend_key'],
                batch_outputs
            )
            
            total_processed += scan_result.total_scanned
        
        assert total_processed == 2500
    
    def test_concurrent_operations_integration(self, integration_components):
        """Test that concurrent stealth operations work correctly."""
        import threading
        
        stealth_service = integration_components['stealth_service']
        key_manager = integration_components['key_manager']
        
        keys = key_manager.derive_view_and_spend_keys()
        results = []
        errors = []
        
        def worker_function(worker_id):
            try:
                # Each worker generates shared secret
                private_key = f"{worker_id:08x}" * 8
                public_key = f"{worker_id+1:08x}" * 8
                
                shared_secret = stealth_service.generate_shared_secret(private_key, public_key)
                
                # Create stealth address
                stealth_addr = stealth_service.create_stealth_address(
                    keys['view_key'],
                    keys['spend_key'],
                    private_key
                )
                
                results.append({
                    'worker_id': worker_id,
                    'shared_secret': shared_secret,
                    'stealth_addr': stealth_addr
                })
                
            except Exception as e:
                errors.append(f"Worker {worker_id}: {e}")
        
        # Start multiple worker threads
        threads = []
        for i in range(3):  # 3 concurrent workers
            thread = threading.Thread(target=worker_function, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all to complete
        for thread in threads:
            thread.join()
        
        # Validate results
        assert len(errors) == 0, f"Concurrent errors: {errors}"
        assert len(results) == 3
        
        # Results should be different (different worker inputs)
        secrets = [r['shared_secret'] for r in results]
        assert len(set(secrets)) == 3, "Concurrent operations should produce different results"


class TestStealthAddressPerformanceIntegration:
    """Performance tests for integrated stealth address workflows."""
    
    @pytest.fixture
    def performance_components(self, wallet_lib_module, test_wallet):
        """Provide components for performance testing."""
        return {
            'wallet': test_wallet,
            'key_manager': wallet_lib_module.TariKeyManager.from_wallet(test_wallet),
            'stealth_service': wallet_lib_module.TariStealthAddress(),
        }
    
    def test_end_to_end_workflow_performance(self, performance_components, performance_threshold_seconds):
        """Test performance of complete stealth address workflows."""
        key_manager = performance_components['key_manager']
        stealth_service = performance_components['stealth_service']
        
        # Measure complete workflow time
        start_time = time.time()
        
        # Complete workflow
        keys = key_manager.derive_view_and_spend_keys()
        shared_secret = stealth_service.generate_shared_secret("deadbeef" * 8, "cafebabe" * 8)
        stealth_addr = stealth_service.create_stealth_address(
            keys['view_key'], keys['spend_key'], "deadbeef" * 8
        )
        
        # Small scan operation
        mock_outputs = [{"sender_offset": "deadbeef" * 8, "script_key": "cafebabe" * 8}] * 100
        scan_result = stealth_service.scan_for_outputs(
            keys['view_key'], keys['spend_key'], mock_outputs
        )
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should complete quickly
        threshold = performance_threshold_seconds.get('stealth_workflow', 2.0)
        assert total_time < threshold, f"Stealth workflow too slow: {total_time:.3f}s > {threshold}s"
    
    def test_batch_processing_performance(self, performance_components, performance_threshold_seconds):
        """Test performance of batch processing operations."""
        stealth_service = performance_components['stealth_service']
        key_manager = performance_components['key_manager']
        
        keys = key_manager.derive_view_and_spend_keys()
        
        # Test various batch sizes
        batch_sizes = [100, 500, 1000, 2000]
        
        for batch_size in batch_sizes:
            outputs = [
                {"sender_offset": f"{i:08x}" * 8, "script_key": f"{(i+1):08x}" * 8}
                for i in range(batch_size)
            ]
            
            start_time = time.time()
            scan_result = stealth_service.scan_for_outputs(
                keys['view_key'], keys['spend_key'], outputs
            )
            end_time = time.time()
            
            processing_time = end_time - start_time
            throughput = batch_size / processing_time
            
            # Validate results
            assert scan_result.total_scanned == batch_size
            
            # Performance should scale reasonably
            # Larger batches should not be proportionally slower due to chunking
            if batch_size >= 1000:
                min_throughput = 500  # At least 500 items/second
                assert throughput >= min_throughput, f"Batch {batch_size} too slow: {throughput:.1f} items/s"


# Integration test markers
pytestmark = pytest.mark.integration
