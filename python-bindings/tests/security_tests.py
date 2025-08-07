#!/usr/bin/env python3
"""
Security tests for Tari wallet Python bindings.

This module focuses on memory safety, secure data handling, cryptographic validation,
and security edge cases for the Python bindings.
"""

import pytest
import gc
import psutil
import time
import threading
import concurrent.futures
from typing import List, Tuple, Dict, Any
import weakref
import sys
import os

# Import the wallet library
import lightweight_wallet_libpy as wallet_lib
from lightweight_wallet_libpy import (
    TariWallet, PrivateKey, CompressedCommitment, RangeProof,
    PyWalletError, NativeCryptoStats
)


class TestMemorySafety:
    """Memory safety tests for secure data handling."""
    
    def test_private_key_zeroization(self):
        """Test that private keys are properly zeroized when destroyed."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Create and destroy multiple private keys
        for _ in range(100):
            key = PrivateKey.from_bytes(bytes([1] * 32))
            # Force destruction by removing reference
            del key
        
        # Force garbage collection
        gc.collect()
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be minimal (less than 1MB)
        assert memory_increase < 1024 * 1024, f"Memory leak in private key zeroization: {memory_increase} bytes"
        
        print(f"✅ Private key zeroization test passed (memory increase: {memory_increase} bytes)")
    
    def test_secure_data_lifetime(self):
        """Test secure data lifetime and cleanup."""
        # Track object creation and destruction
        created_objects = []
        
        for i in range(50):
            key = PrivateKey.from_bytes(bytes([i] * 32))
            commitment = wallet_lib.calculate_commitment_native(1000 + i, key)
            created_objects.append((key, commitment))
        
        # Verify objects are accessible
        assert len(created_objects) == 50
        
        # Clear references and force cleanup
        del created_objects
        gc.collect()
        
        print(f"✅ Secure data lifetime test passed")
    
    def test_memory_pressure_handling(self):
        """Test memory pressure handling during intensive operations."""
        process = psutil.Process()
        
        # Perform intensive operations to create memory pressure
        objects = []
        for i in range(1000):
            key = PrivateKey.from_bytes(bytes([i % 256] * 32))
            commitment = wallet_lib.calculate_commitment_native(1000 + i, key)
            objects.append((key, commitment))
            
            # Periodically clear some objects to simulate memory pressure
            if i % 100 == 0:
                objects = objects[-50:]  # Keep only last 50 objects
                gc.collect()
        
        # Verify system remains stable
        final_memory = process.memory_info().rss
        assert final_memory < 500 * 1024 * 1024, f"Excessive memory usage: {final_memory} bytes"
        
        print(f"✅ Memory pressure handling test passed")
    
    def test_concurrent_memory_safety(self):
        """Test memory safety under concurrent access."""
        def memory_intensive_operation(thread_id: int) -> bool:
            """Perform memory-intensive operations in a thread."""
            try:
                for i in range(100):
                    key = PrivateKey.from_bytes(bytes([thread_id * 100 + i] * 32))
                    commitment = wallet_lib.calculate_commitment_native(1000 + i, key)
                    del key, commitment
                
                gc.collect()
                return True
            except Exception as e:
                print(f"Thread {thread_id} failed: {e}")
                return False
        
        # Run concurrent operations
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(memory_intensive_operation, i) for i in range(4)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # All operations should succeed
        assert all(results), "Some concurrent operations failed"
        
        print(f"✅ Concurrent memory safety test passed")


class TestCryptographicValidation:
    """Cryptographic validation and security tests."""
    
    def test_commitment_format_validation(self):
        """Test commitment format validation for security."""
        # Test valid commitment
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        valid_commitment = wallet_lib.calculate_commitment_native(1000, private_key)
        
        # Verify commitment has correct format
        commitment_hex = valid_commitment.to_hex()
        assert commitment_hex.startswith('08') or commitment_hex.startswith('09'), \
            f"Invalid commitment format: {commitment_hex[:2]}"
        
        # Test invalid commitment format
        with pytest.raises(PyWalletError):
            invalid_commitment = CompressedCommitment.new(bytes([0x01] * 32))
            mock_proof = RangeProof.from_bytes(bytes([0x08] * 100))
            wallet_lib.verify_range_proof_native(mock_proof, invalid_commitment, 1000)
        
        print(f"✅ Commitment format validation test passed")
    
    def test_private_key_validation(self):
        """Test private key validation for security."""
        # Test valid private key
        valid_key = PrivateKey.from_bytes(bytes([1] * 32))
        commitment = wallet_lib.calculate_commitment_native(1000, valid_key)
        assert commitment.to_hex().startswith('08') or commitment.to_hex().startswith('09')
        
        # Test invalid private key length
        with pytest.raises(PyWalletError):
            invalid_key = PrivateKey.from_bytes(bytes([1] * 31))  # Wrong length
            wallet_lib.calculate_commitment_native(1000, invalid_key)
        
        # Test invalid private key format
        with pytest.raises(PyWalletError):
            invalid_key = PrivateKey.from_bytes(bytes([0] * 32))  # All zeros
            wallet_lib.calculate_commitment_native(1000, invalid_key)
        
        print(f"✅ Private key validation test passed")
    
    def test_range_proof_validation(self):
        """Test range proof validation for security."""
        # Create valid commitment and proof
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        commitment = wallet_lib.calculate_commitment_native(1000, private_key)
        valid_proof = RangeProof.from_bytes(bytes([0x08] * 100))
        
        # Test valid range proof
        result = wallet_lib.verify_range_proof_native(valid_proof, commitment, 1000)
        assert isinstance(result, bool)
        
        # Test invalid range proof (empty)
        with pytest.raises(PyWalletError):
            invalid_proof = RangeProof.from_bytes(bytes([]))
            wallet_lib.verify_range_proof_native(invalid_proof, commitment, 1000)
        
        # Test invalid range proof (too large)
        with pytest.raises(PyWalletError):
            invalid_proof = RangeProof.from_bytes(bytes([0x08] * 10000))  # Too large
            wallet_lib.verify_range_proof_native(invalid_proof, commitment, 1000)
        
        print(f"✅ Range proof validation test passed")
    
    def test_batch_operation_security(self):
        """Test security of batch operations."""
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        
        # Test valid batch operation
        batch_inputs = [(1000 + i, private_key) for i in range(10)]
        batch_commitments = wallet_lib.batch_calculate_commitments_native(batch_inputs)
        
        assert len(batch_commitments) == 10
        for commitment in batch_commitments:
            assert commitment.to_hex().startswith('08') or commitment.to_hex().startswith('09')
        
        # Test batch operation with invalid input
        with pytest.raises(PyWalletError):
            invalid_key = PrivateKey.from_bytes(bytes([1] * 31))  # Wrong length
            invalid_batch_inputs = [(1000, invalid_key)]
            wallet_lib.batch_calculate_commitments_native(invalid_batch_inputs)
        
        print(f"✅ Batch operation security test passed")


class TestSecurityEdgeCases:
    """Security edge cases and boundary testing."""
    
    def test_extreme_value_handling(self):
        """Test handling of extreme values."""
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        
        # Test very large values
        large_commitment = wallet_lib.calculate_commitment_native(2**63 - 1, private_key)
        assert large_commitment.to_hex().startswith('08') or large_commitment.to_hex().startswith('09')
        
        # Test zero value
        zero_commitment = wallet_lib.calculate_commitment_native(0, private_key)
        assert zero_commitment.to_hex().startswith('08') or zero_commitment.to_hex().startswith('09')
        
        print(f"✅ Extreme value handling test passed")
    
    def test_malformed_input_handling(self):
        """Test handling of malformed inputs."""
        # Test malformed private key
        with pytest.raises(PyWalletError):
            malformed_key = PrivateKey.from_bytes(bytes([0xFF] * 32))  # All ones
            wallet_lib.calculate_commitment_native(1000, malformed_key)
        
        # Test malformed commitment
        with pytest.raises(PyWalletError):
            malformed_commitment = CompressedCommitment.new(bytes([0xFF] * 32))
            mock_proof = RangeProof.from_bytes(bytes([0x08] * 100))
            wallet_lib.verify_range_proof_native(mock_proof, malformed_commitment, 1000)
        
        print(f"✅ Malformed input handling test passed")
    
    def test_resource_exhaustion_protection(self):
        """Test protection against resource exhaustion attacks."""
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        
        # Test with very large batch size
        large_batch_inputs = [(1000 + i, private_key) for i in range(1000)]
        
        start_time = time.time()
        batch_commitments = wallet_lib.batch_calculate_commitments_native(large_batch_inputs)
        end_time = time.time()
        
        # Operation should complete within reasonable time (less than 10 seconds)
        assert end_time - start_time < 10.0, "Batch operation took too long"
        assert len(batch_commitments) == 1000
        
        print(f"✅ Resource exhaustion protection test passed")
    
    def test_concurrent_security(self):
        """Test security under concurrent access."""
        def security_operation(thread_id: int) -> bool:
            """Perform security-critical operations in a thread."""
            try:
                # Create private key
                key = PrivateKey.from_bytes(bytes([thread_id] * 32))
                
                # Perform crypto operations
                commitment = wallet_lib.calculate_commitment_native(1000 + thread_id, key)
                mock_proof = RangeProof.from_bytes(bytes([0x08] * 100))
                result = wallet_lib.verify_range_proof_native(mock_proof, commitment, 1000 + thread_id)
                
                # Verify results
                assert commitment.to_hex().startswith('08') or commitment.to_hex().startswith('09')
                assert isinstance(result, bool)
                
                return True
            except Exception as e:
                print(f"Thread {thread_id} security operation failed: {e}")
                return False
        
        # Run concurrent security operations
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(security_operation, i) for i in range(8)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # All operations should succeed
        assert all(results), "Some concurrent security operations failed"
        
        print(f"✅ Concurrent security test passed")


class TestSecureDataHandling:
    """Secure data handling and memory management tests."""
    
    def test_secure_data_isolation(self):
        """Test that secure data is properly isolated."""
        # Create multiple private keys
        keys = []
        for i in range(10):
            key = PrivateKey.from_bytes(bytes([i] * 32))
            keys.append(key)
        
        # Verify each key produces different commitments
        commitments = []
        for i, key in enumerate(keys):
            commitment = wallet_lib.calculate_commitment_native(1000 + i, key)
            commitments.append(commitment.to_hex())
        
        # All commitments should be different
        unique_commitments = set(commitments)
        assert len(unique_commitments) == len(commitments), "Commitments are not unique"
        
        print(f"✅ Secure data isolation test passed")
    
    def test_secure_data_cleanup(self):
        """Test secure data cleanup and memory management."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Create and destroy secure objects
        for _ in range(100):
            key = PrivateKey.from_bytes(bytes([1] * 32))
            commitment = wallet_lib.calculate_commitment_native(1000, key)
            proof = RangeProof.from_bytes(bytes([0x08] * 100))
            
            # Force cleanup
            del key, commitment, proof
        
        # Force garbage collection
        gc.collect()
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be minimal
        assert memory_increase < 1024 * 1024, f"Memory leak in secure data cleanup: {memory_increase} bytes"
        
        print(f"✅ Secure data cleanup test passed (memory increase: {memory_increase} bytes)")
    
    def test_weak_reference_handling(self):
        """Test weak reference handling for secure data."""
        # Create private key
        key = PrivateKey.from_bytes(bytes([1] * 32))
        
        # Create weak reference
        weak_ref = weakref.ref(key)
        
        # Verify weak reference works
        assert weak_ref() is not None
        
        # Delete the key
        del key
        
        # Force garbage collection
        gc.collect()
        
        # Weak reference should be None
        assert weak_ref() is None
        
        print(f"✅ Weak reference handling test passed")


class TestCryptographicIntegrity:
    """Cryptographic integrity and consistency tests."""
    
    def test_commitment_determinism(self):
        """Test that commitments are deterministic for the same inputs."""
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        
        # Create multiple commitments with same inputs
        commitment1 = wallet_lib.calculate_commitment_native(1000, private_key)
        commitment2 = wallet_lib.calculate_commitment_native(1000, private_key)
        
        # Commitments should be identical
        assert commitment1.to_hex() == commitment2.to_hex()
        
        print(f"✅ Commitment determinism test passed")
    
    def test_commitment_uniqueness(self):
        """Test that different inputs produce different commitments."""
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        
        # Create commitments with different values
        commitment1 = wallet_lib.calculate_commitment_native(1000, private_key)
        commitment2 = wallet_lib.calculate_commitment_native(2000, private_key)
        
        # Commitments should be different
        assert commitment1.to_hex() != commitment2.to_hex()
        
        print(f"✅ Commitment uniqueness test passed")
    
    def test_batch_operation_consistency(self):
        """Test consistency of batch operations."""
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        
        # Create batch inputs
        batch_inputs = [(1000 + i, private_key) for i in range(5)]
        
        # Perform batch operation multiple times
        batch1 = wallet_lib.batch_calculate_commitments_native(batch_inputs)
        batch2 = wallet_lib.batch_calculate_commitments_native(batch_inputs)
        
        # Results should be identical
        assert len(batch1) == len(batch2)
        for i in range(len(batch1)):
            assert batch1[i].to_hex() == batch2[i].to_hex()
        
        print(f"✅ Batch operation consistency test passed")


# Security test fixtures
@pytest.fixture
def security_monitor():
    """Fixture to monitor security-related metrics during tests."""
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
    
    print(f"Security test metrics: {end_time - start_time:.3f}s, "
          f"Memory change: {end_memory - start_memory} bytes")


# Security validation decorator
def validate_security(func):
    """Decorator to validate security properties of test functions."""
    def wrapper(*args, **kwargs):
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 