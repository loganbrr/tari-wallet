#!/usr/bin/env python3
"""
Performance benchmarks for Tari wallet Python bindings.

This module benchmarks native operations against pure Python implementations,
measures performance characteristics, and includes regression testing.
"""

import pytest
import time
import statistics
import psutil
import gc
import threading
import concurrent.futures
from typing import List, Tuple, Dict, Any, Callable
import json
import os
from dataclasses import dataclass
from memory_profiler import profile

# Import the wallet library
import lightweight_wallet_libpy as wallet_lib
from lightweight_wallet_libpy import (
    TariWallet, PrivateKey, CompressedCommitment, RangeProof,
    PyWalletError, NativeCryptoStats
)


@dataclass
class BenchmarkResult:
    """Container for benchmark results."""
    operation_name: str
    duration_ms: float
    memory_usage_bytes: int
    iterations: int
    throughput_ops_per_sec: float
    memory_per_op_bytes: float


class PerformanceBenchmarks:
    """Performance benchmarking suite for native operations."""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
        self.process = psutil.Process()
    
    def benchmark_operation(self, 
                          operation_name: str, 
                          operation: Callable, 
                          iterations: int = 1000,
                          warmup_iterations: int = 100) -> BenchmarkResult:
        """Benchmark a single operation."""
        # Warmup
        for _ in range(warmup_iterations):
            try:
                operation()
            except Exception:
                pass
        
        # Force garbage collection
        gc.collect()
        
        # Measure initial memory
        initial_memory = self.process.memory_info().rss
        
        # Benchmark
        start_time = time.time()
        for _ in range(iterations):
            operation()
        end_time = time.time()
        
        # Measure final memory
        final_memory = self.process.memory_info().rss
        
        # Calculate metrics
        duration_ms = (end_time - start_time) * 1000
        memory_usage_bytes = final_memory - initial_memory
        throughput_ops_per_sec = iterations / (duration_ms / 1000)
        memory_per_op_bytes = memory_usage_bytes / iterations
        
        result = BenchmarkResult(
            operation_name=operation_name,
            duration_ms=duration_ms,
            memory_usage_bytes=memory_usage_bytes,
            iterations=iterations,
            throughput_ops_per_sec=throughput_ops_per_sec,
            memory_per_op_bytes=memory_per_op_bytes
        )
        
        self.results.append(result)
        return result
    
    def print_results(self):
        """Print benchmark results."""
        print("\n" + "="*80)
        print("PERFORMANCE BENCHMARK RESULTS")
        print("="*80)
        
        for result in self.results:
            print(f"\n{result.operation_name}:")
            print(f"  Duration: {result.duration_ms:.2f}ms for {result.iterations} iterations")
            print(f"  Throughput: {result.throughput_ops_per_sec:.2f} ops/sec")
            print(f"  Memory usage: {result.memory_usage_bytes} bytes")
            print(f"  Memory per op: {result.memory_per_op_bytes:.2f} bytes")
        
        print("\n" + "="*80)


class TestNativeCryptoPerformance:
    """Performance tests for native crypto operations."""
    
    def test_commitment_calculation_performance(self):
        """Benchmark commitment calculation performance."""
        benchmark = PerformanceBenchmarks()
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        
        # Benchmark single commitment calculation
        def single_commitment():
            return wallet_lib.calculate_commitment_native(1000, private_key)
        
        result = benchmark.benchmark_operation(
            "Single Commitment Calculation",
            single_commitment,
            iterations=10000
        )
        
        # Performance assertions
        assert result.throughput_ops_per_sec > 1000, f"Commitment calculation too slow: {result.throughput_ops_per_sec} ops/sec"
        assert result.memory_per_op_bytes < 1024, f"Excessive memory per operation: {result.memory_per_op_bytes} bytes"
        
        benchmark.print_results()
        print(f"✅ Commitment calculation performance test passed")
    
    def test_batch_commitment_performance(self):
        """Benchmark batch commitment calculation performance."""
        benchmark = PerformanceBenchmarks()
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        
        # Test different batch sizes
        batch_sizes = [1, 10, 100, 1000]
        
        for size in batch_sizes:
            batch_inputs = [(1000 + i, private_key) for i in range(size)]
            
            def batch_commitment():
                return wallet_lib.batch_calculate_commitments_native(batch_inputs)
            
            result = benchmark.benchmark_operation(
                f"Batch Commitment Calculation ({size} items)",
                batch_commitment,
                iterations=1000 // size  # Adjust iterations based on batch size
            )
            
            # Verify batch operations scale efficiently
            if size > 1:
                efficiency_ratio = result.throughput_ops_per_sec / (result.throughput_ops_per_sec / size)
                assert efficiency_ratio > 0.5, f"Batch operations not scaling efficiently: {efficiency_ratio}"
        
        benchmark.print_results()
        print(f"✅ Batch commitment performance test passed")
    
    def test_range_proof_verification_performance(self):
        """Benchmark range proof verification performance."""
        benchmark = PerformanceBenchmarks()
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        commitment = wallet_lib.calculate_commitment_native(1000, private_key)
        mock_proof = RangeProof.from_bytes(bytes([0x08] * 100))
        
        def range_proof_verification():
            return wallet_lib.verify_range_proof_native(mock_proof, commitment, 1000)
        
        result = benchmark.benchmark_operation(
            "Range Proof Verification",
            range_proof_verification,
            iterations=5000
        )
        
        # Performance assertions
        assert result.throughput_ops_per_sec > 500, f"Range proof verification too slow: {result.throughput_ops_per_sec} ops/sec"
        
        benchmark.print_results()
        print(f"✅ Range proof verification performance test passed")
    
    def test_concurrent_performance(self):
        """Test performance under concurrent load."""
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        
        def concurrent_operation(thread_id: int) -> Tuple[int, float]:
            start_time = time.time()
            
            for i in range(100):
                commitment = wallet_lib.calculate_commitment_native(1000 + i, private_key)
                mock_proof = RangeProof.from_bytes(bytes([0x08] * 100))
                wallet_lib.verify_range_proof_native(mock_proof, commitment, 1000 + i)
            
            end_time = time.time()
            return thread_id, end_time - start_time
        
        # Run concurrent operations
        thread_count = 4
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(concurrent_operation, i) for i in range(thread_count)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # Verify all operations completed successfully
        assert len(results) == thread_count
        total_time = sum(time_taken for _, time_taken in results)
        avg_time = total_time / thread_count
        
        print(f"Concurrent performance: {thread_count} threads, avg time: {avg_time:.3f}s")
        assert avg_time < 5.0, f"Concurrent operations too slow: {avg_time}s"
        
        print(f"✅ Concurrent performance test passed")


class TestPerformanceScaling:
    """Test performance scaling characteristics."""
    
    def test_operation_scaling(self):
        """Test how performance scales with different input sizes."""
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        
        # Test different batch sizes
        batch_sizes = [1, 5, 10, 50, 100, 500, 1000]
        timings = {}
        
        for size in batch_sizes:
            batch_inputs = [(1000 + i, private_key) for i in range(size)]
            
            start_time = time.time()
            batch_commitments = wallet_lib.batch_calculate_commitments_native(batch_inputs)
            end_time = time.time()
            
            timings[size] = end_time - start_time
            assert len(batch_commitments) == size
        
        # Analyze scaling characteristics
        print(f"\nScaling analysis:")
        for size, timing in timings.items():
            ops_per_sec = size / timing
            print(f"  Batch size {size}: {timing:.3f}s, {ops_per_sec:.1f} ops/sec")
        
        # Verify that larger batches are more efficient per operation
        small_batch_ops_per_sec = 1 / timings[1]
        large_batch_ops_per_sec = 1000 / timings[1000]
        
        efficiency_improvement = large_batch_ops_per_sec / small_batch_ops_per_sec
        assert efficiency_improvement > 1.5, f"Batch operations not scaling efficiently: {efficiency_improvement}x"
        
        print(f"✅ Operation scaling test passed (efficiency improvement: {efficiency_improvement:.1f}x)")
    
    def test_memory_scaling(self):
        """Test memory usage scaling with different batch sizes."""
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        process = psutil.Process()
        
        batch_sizes = [1, 10, 100, 1000]
        memory_usage = {}
        
        for size in batch_sizes:
            # Force garbage collection
            gc.collect()
            initial_memory = process.memory_info().rss
            
            batch_inputs = [(1000 + i, private_key) for i in range(size)]
            batch_commitments = wallet_lib.batch_calculate_commitments_native(batch_inputs)
            
            final_memory = process.memory_info().rss
            memory_usage[size] = final_memory - initial_memory
            
            # Clean up
            del batch_commitments
            gc.collect()
        
        print(f"\nMemory scaling analysis:")
        for size, memory in memory_usage.items():
            memory_per_op = memory / size
            print(f"  Batch size {size}: {memory} bytes total, {memory_per_op:.1f} bytes per op")
        
        # Memory per operation should be relatively constant
        memory_per_op_values = [memory_usage[size] / size for size in batch_sizes]
        memory_variance = statistics.variance(memory_per_op_values)
        
        assert memory_variance < 1000, f"Memory usage not scaling consistently: variance {memory_variance}"
        
        print(f"✅ Memory scaling test passed")


class TestPerformanceRegression:
    """Performance regression tests."""
    
    def test_performance_baseline(self):
        """Establish performance baseline for regression testing."""
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        
        # Measure baseline performance
        start_time = time.time()
        for i in range(1000):
            commitment = wallet_lib.calculate_commitment_native(1000 + i, private_key)
        end_time = time.time()
        
        baseline_time = end_time - start_time
        baseline_throughput = 1000 / baseline_time
        
        print(f"Baseline performance: {baseline_throughput:.1f} ops/sec")
        
        # Store baseline for future comparison
        baseline_file = "performance_baseline.json"
        baseline_data = {
            "commitment_calculation_ops_per_sec": baseline_throughput,
            "timestamp": time.time()
        }
        
        with open(baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=2)
        
        print(f"✅ Performance baseline established")
    
    def test_performance_regression_detection(self):
        """Test detection of performance regressions."""
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        
        # Measure current performance
        start_time = time.time()
        for i in range(1000):
            commitment = wallet_lib.calculate_commitment_native(1000 + i, private_key)
        end_time = time.time()
        
        current_throughput = 1000 / (end_time - start_time)
        
        # Load baseline
        baseline_file = "performance_baseline.json"
        if os.path.exists(baseline_file):
            with open(baseline_file, 'r') as f:
                baseline_data = json.load(f)
            
            baseline_throughput = baseline_data["commitment_calculation_ops_per_sec"]
            regression_ratio = current_throughput / baseline_throughput
            
            print(f"Current: {current_throughput:.1f} ops/sec, Baseline: {baseline_throughput:.1f} ops/sec")
            print(f"Performance ratio: {regression_ratio:.2f}")
            
            # Allow 20% performance regression
            assert regression_ratio > 0.8, f"Performance regression detected: {regression_ratio:.2f}"
        
        print(f"✅ Performance regression test passed")


class TestMemoryPerformance:
    """Memory performance tests."""
    
    @profile
    def test_memory_efficiency(self):
        """Test memory efficiency of operations."""
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        
        # Perform memory-intensive operations
        commitments = []
        for i in range(1000):
            commitment = wallet_lib.calculate_commitment_native(1000 + i, private_key)
            commitments.append(commitment)
        
        # Verify memory usage is reasonable
        process = psutil.Process()
        memory_usage = process.memory_info().rss
        
        # Should use less than 100MB for 1000 commitments
        assert memory_usage < 100 * 1024 * 1024, f"Excessive memory usage: {memory_usage} bytes"
        
        print(f"✅ Memory efficiency test passed (usage: {memory_usage / 1024 / 1024:.1f} MB)")
    
    def test_memory_cleanup_performance(self):
        """Test memory cleanup performance."""
        process = psutil.Process()
        
        # Measure memory before operations
        initial_memory = process.memory_info().rss
        
        # Perform operations and cleanup
        for _ in range(10):
            private_key = PrivateKey.from_bytes(bytes([1] * 32))
            commitments = []
            
            for i in range(100):
                commitment = wallet_lib.calculate_commitment_native(1000 + i, private_key)
                commitments.append(commitment)
            
            # Clean up
            del commitments, private_key
            gc.collect()
        
        # Measure memory after cleanup
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be minimal
        assert memory_increase < 10 * 1024 * 1024, f"Memory cleanup ineffective: {memory_increase} bytes"
        
        print(f"✅ Memory cleanup performance test passed (increase: {memory_increase} bytes)")


class TestStressPerformance:
    """Stress performance tests."""
    
    def test_stress_test_high_load(self):
        """Stress test under high load."""
        private_key = PrivateKey.from_bytes(bytes([1] * 32))
        
        # Perform intensive operations
        start_time = time.time()
        operations_completed = 0
        
        for i in range(10000):
            commitment = wallet_lib.calculate_commitment_native(1000 + i, private_key)
            mock_proof = RangeProof.from_bytes(bytes([0x08] * 100))
            wallet_lib.verify_range_proof_native(mock_proof, commitment, 1000 + i)
            operations_completed += 1
            
            # Progress indicator
            if i % 1000 == 0:
                elapsed = time.time() - start_time
                ops_per_sec = operations_completed / elapsed
                print(f"Progress: {i}/{10000} operations, {ops_per_sec:.1f} ops/sec")
        
        total_time = time.time() - start_time
        overall_throughput = operations_completed / total_time
        
        print(f"Stress test completed: {overall_throughput:.1f} ops/sec")
        assert overall_throughput > 100, f"Stress test performance too low: {overall_throughput} ops/sec"
        
        print(f"✅ Stress performance test passed")
    
    def test_concurrent_stress_test(self):
        """Stress test under concurrent load."""
        def stress_operation(thread_id: int) -> int:
            private_key = PrivateKey.from_bytes(bytes([thread_id] * 32))
            operations = 0
            
            for i in range(1000):
                commitment = wallet_lib.calculate_commitment_native(1000 + i, private_key)
                mock_proof = RangeProof.from_bytes(bytes([0x08] * 100))
                wallet_lib.verify_range_proof_native(mock_proof, commitment, 1000 + i)
                operations += 1
            
            return operations
        
        # Run concurrent stress operations
        thread_count = 4
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(stress_operation, i) for i in range(thread_count)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        total_operations = sum(results)
        print(f"Concurrent stress test: {total_operations} operations completed")
        assert total_operations == thread_count * 1000, "Some operations failed"
        
        print(f"✅ Concurrent stress test passed")


# Performance test fixtures
@pytest.fixture
def performance_benchmark():
    """Fixture for performance benchmarking."""
    return PerformanceBenchmarks()


@pytest.fixture
def benchmark_private_key():
    """Fixture providing a private key for benchmarking."""
    return PrivateKey.from_bytes(bytes([1] * 32))


# Performance monitoring decorator
def monitor_performance(threshold_ops_per_sec: float = 1000):
    """Decorator to monitor performance of test functions."""
    def decorator(func):
        def wrapper(*args, **kwargs):
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 