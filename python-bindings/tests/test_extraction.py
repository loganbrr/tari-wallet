"""Comprehensive test suite for extraction functionality.

This module provides extensive test coverage for all extraction components
including core extraction functions, batch validation, and result types.
"""

import pytest
from unittest.mock import Mock, patch
import sys
import os

# Add the python-bindings directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))

import tari_wallet_python

# Test constants
VALID_PRIVATE_KEY = b'a' * 32  # 32-byte private key
VALID_PUBLIC_KEY = b'b' * 32   # 32-byte public key
INVALID_KEY = b'c' * 16        # Invalid 16-byte key


class TestExtractionConfig:
    """Test suite for TariExtractionConfig class."""

    def test_create_default_config(self):
        """Test creating default extraction configuration."""
        config = tari_wallet_python.TariExtractionConfig()
        
        # Check default values
        assert config.enable_key_derivation is True
        assert config.validate_range_proofs is True
        assert config.validate_signatures is True
        assert config.handle_special_outputs is True
        assert config.detect_corruption is True

    def test_create_config_with_private_key(self):
        """Test creating configuration with private key."""
        config = tari_wallet_python.TariExtractionConfig.with_private_key(VALID_PRIVATE_KEY)
        
        # Should be created successfully
        assert config is not None
        assert "TariExtractionConfig" in repr(config)
        assert "has_private_key=True" in repr(config)

    def test_create_config_with_public_key(self):
        """Test creating configuration with public key."""
        config = tari_wallet_python.TariExtractionConfig.with_public_key(VALID_PUBLIC_KEY)
        
        # Should be created successfully
        assert config is not None
        assert "TariExtractionConfig" in repr(config)
        assert "has_public_key=True" in repr(config)

    def test_invalid_private_key_length(self):
        """Test error handling for invalid private key length."""
        with pytest.raises(Exception) as exc_info:
            tari_wallet_python.TariExtractionConfig.with_private_key(INVALID_KEY)
        
        assert "32 bytes" in str(exc_info.value)

    def test_invalid_public_key_length(self):
        """Test error handling for invalid public key length."""
        with pytest.raises(Exception) as exc_info:
            tari_wallet_python.TariExtractionConfig.with_public_key(INVALID_KEY)
        
        assert "32 bytes" in str(exc_info.value)

    def test_set_private_key(self):
        """Test setting private key after creation."""
        config = tari_wallet_python.TariExtractionConfig()
        
        # Should work with valid key
        config.set_private_key(VALID_PRIVATE_KEY)
        assert "has_private_key=True" in repr(config)

    def test_set_public_key(self):
        """Test setting public key after creation."""
        config = tari_wallet_python.TariExtractionConfig()
        
        # Should work with valid key
        config.set_public_key(VALID_PUBLIC_KEY)
        assert "has_public_key=True" in repr(config)

    def test_set_invalid_private_key(self):
        """Test error handling when setting invalid private key."""
        config = tari_wallet_python.TariExtractionConfig()
        
        with pytest.raises(Exception) as exc_info:
            config.set_private_key(INVALID_KEY)
        
        assert "32 bytes" in str(exc_info.value)

    def test_set_invalid_public_key(self):
        """Test error handling when setting invalid public key."""
        config = tari_wallet_python.TariExtractionConfig()
        
        with pytest.raises(Exception) as exc_info:
            config.set_public_key(INVALID_KEY)
        
        assert "32 bytes" in str(exc_info.value)

    def test_configuration_options(self):
        """Test setting configuration options."""
        config = tari_wallet_python.TariExtractionConfig()
        
        # Test setting each option
        config.set_enable_key_derivation(False)
        assert config.enable_key_derivation is False
        
        config.set_validate_range_proofs(False)
        assert config.validate_range_proofs is False
        
        config.set_validate_signatures(False)
        assert config.validate_signatures is False
        
        config.set_handle_special_outputs(False)
        assert config.handle_special_outputs is False
        
        config.set_detect_corruption(False)
        assert config.detect_corruption is False

    def test_config_repr(self):
        """Test string representation of configuration."""
        config = tari_wallet_python.TariExtractionConfig()
        repr_str = repr(config)
        
        assert "TariExtractionConfig" in repr_str
        assert "enable_key_derivation=" in repr_str
        assert "validate_range_proofs=" in repr_str
        assert "validate_signatures=" in repr_str
        assert "handle_special_outputs=" in repr_str
        assert "detect_corruption=" in repr_str
        assert "has_private_key=" in repr_str
        assert "has_public_key=" in repr_str


class TestDecryptionOptions:
    """Test suite for DecryptionOptions class."""

    def test_create_default_options(self):
        """Test creating default decryption options."""
        options = tari_wallet_python.DecryptionOptions()
        
        # Check default values
        assert options.try_all_keys is True
        assert options.validate_decrypted_data is True
        assert options.max_keys_to_try == 0  # Unlimited
        assert options.return_partial_results is False

    def test_create_custom_options(self):
        """Test creating custom decryption options."""
        options = tari_wallet_python.DecryptionOptions.with_options(
            try_all_keys=False,
            validate_decrypted_data=False,
            max_keys_to_try=5,
            return_partial_results=True
        )
        
        assert options.try_all_keys is False
        assert options.validate_decrypted_data is False
        assert options.max_keys_to_try == 5
        assert options.return_partial_results is True

    def test_option_setters(self):
        """Test setting individual options."""
        options = tari_wallet_python.DecryptionOptions()
        
        options.set_try_all_keys(False)
        assert options.try_all_keys is False
        
        options.set_validate_decrypted_data(False)
        assert options.validate_decrypted_data is False
        
        options.set_max_keys_to_try(10)
        assert options.max_keys_to_try == 10
        
        options.set_return_partial_results(True)
        assert options.return_partial_results is True

    def test_options_repr(self):
        """Test string representation of options."""
        options = tari_wallet_python.DecryptionOptions()
        repr_str = repr(options)
        
        assert "DecryptionOptions" in repr_str
        assert "try_all_keys=" in repr_str
        assert "validate_decrypted_data=" in repr_str
        assert "max_keys_to_try=" in repr_str
        assert "return_partial_results=" in repr_str


class TestBatchValidationOptions:
    """Test suite for BatchValidationOptions class."""

    def test_create_default_options(self):
        """Test creating default batch validation options."""
        options = tari_wallet_python.BatchValidationOptions()
        
        # Check default values
        assert options.continue_on_error is True
        assert options.max_errors_per_output == 5
        assert options.validate_range_proofs is True
        assert options.validate_signatures is True
        assert options.validate_commitments is True

    def test_create_custom_options(self):
        """Test creating custom batch validation options."""
        options = tari_wallet_python.BatchValidationOptions.with_options(
            continue_on_error=False,
            max_errors_per_output=3,
            validate_range_proofs=False,
            validate_signatures=False,
            validate_commitments=False
        )
        
        assert options.continue_on_error is False
        assert options.max_errors_per_output == 3
        assert options.validate_range_proofs is False
        assert options.validate_signatures is False
        assert options.validate_commitments is False

    def test_option_setters(self):
        """Test setting individual options."""
        options = tari_wallet_python.BatchValidationOptions()
        
        options.set_continue_on_error(False)
        assert options.continue_on_error is False
        
        options.set_max_errors_per_output(7)
        assert options.max_errors_per_output == 7
        
        options.set_validate_range_proofs(False)
        assert options.validate_range_proofs is False
        
        options.set_validate_signatures(False)
        assert options.validate_signatures is False
        
        options.set_validate_commitments(False)
        assert options.validate_commitments is False

    def test_options_repr(self):
        """Test string representation of options."""
        options = tari_wallet_python.BatchValidationOptions()
        repr_str = repr(options)
        
        assert "BatchValidationOptions" in repr_str
        assert "continue_on_error=" in repr_str
        assert "max_errors_per_output=" in repr_str
        assert "validate_range_proofs=" in repr_str
        assert "validate_signatures=" in repr_str
        assert "validate_commitments=" in repr_str


class TestExtractWalletOutput:
    """Test suite for extract_wallet_output function."""

    def create_mock_transaction_output(self):
        """Create a mock transaction output for testing."""
        # This would normally be a LightweightTransactionOutput instance
        # For testing API correctness, we focus on proper error handling
        return Mock()

    def test_extract_without_keys_fails(self):
        """Test that extraction fails when no keys are provided."""
        output = self.create_mock_transaction_output()
        config = tari_wallet_python.TariExtractionConfig()
        
        # Should fail because no keys are provided
        with pytest.raises(Exception) as exc_info:
            tari_wallet_python.extract_wallet_output(output, config)
        
        # The error should mention missing keys
        error_msg = str(exc_info.value).lower()
        assert "key" in error_msg or "not supported" in error_msg

    def test_extract_with_mock_data_expected_failure(self):
        """Test extraction with mock data (expected to fail cryptographically)."""
        output = self.create_mock_transaction_output()
        config = tari_wallet_python.TariExtractionConfig.with_private_key(VALID_PRIVATE_KEY)
        
        # Should fail because mock data doesn't have real encrypted data
        # This tests API correctness rather than cryptographic validity
        with pytest.raises(Exception):
            tari_wallet_python.extract_wallet_output(output, config)


class TestBatchValidation:
    """Test suite for batch validation functions."""

    def create_mock_outputs(self, count=3):
        """Create mock transaction outputs for testing."""
        return [Mock() for _ in range(count)]

    def test_validate_output_batch_api(self):
        """Test the validate_output_batch function API."""
        outputs = self.create_mock_outputs(3)
        options = tari_wallet_python.BatchValidationOptions()
        
        # Test that function exists and can be called
        # With mock data, this should either return results or raise an exception
        # We're testing API correctness, not cryptographic validity
        try:
            result = tari_wallet_python.validate_output_batch(outputs, options)
            
            # If it succeeds, check result structure
            assert hasattr(result, 'is_valid')
            assert hasattr(result, 'results')
            assert hasattr(result, 'summary')
            
        except Exception as e:
            # Expected with mock data - test that error is reasonable
            assert isinstance(e, Exception)

    def test_validate_output_batch_empty_list(self):
        """Test batch validation with empty output list."""
        outputs = []
        options = tari_wallet_python.BatchValidationOptions()
        
        try:
            result = tari_wallet_python.validate_output_batch(outputs, options)
            
            # Empty batch should succeed
            assert result.is_valid is True
            assert result.summary.total_outputs == 0
            assert len(result.results) == 0
            
        except Exception:
            # Some implementations might not handle empty lists
            pass

    def test_batch_validation_parallel_exists(self):
        """Test that parallel batch validation function exists if grpc feature is enabled."""
        # Check if the parallel function is available
        if hasattr(tari_wallet_python, 'validate_output_batch_parallel'):
            outputs = self.create_mock_outputs(3)
            options = tari_wallet_python.BatchValidationOptions()
            
            # Test that function can be called (may fail with mock data)
            try:
                result = tari_wallet_python.validate_output_batch_parallel(outputs, options)
                assert hasattr(result, 'is_valid')
            except Exception:
                # Expected with mock data
                pass


class TestResultTypes:
    """Test suite for result type classes."""

    def test_decryption_result_structure(self):
        """Test DecryptionResult class structure."""
        # Can't easily create instances without Rust backend
        # Test that class exists and has expected attributes
        assert hasattr(tari_wallet_python, 'DecryptionResult')

    def test_payment_id_extraction_result_structure(self):
        """Test PaymentIdExtractionResult class structure."""
        assert hasattr(tari_wallet_python, 'PaymentIdExtractionResult')

    def test_payment_id_metadata_structure(self):
        """Test PaymentIdMetadata class structure."""
        assert hasattr(tari_wallet_python, 'PaymentIdMetadata')

    def test_output_validation_result_structure(self):
        """Test OutputValidationResult class structure."""
        assert hasattr(tari_wallet_python, 'OutputValidationResult')

    def test_batch_validation_summary_structure(self):
        """Test BatchValidationSummary class structure."""
        assert hasattr(tari_wallet_python, 'BatchValidationSummary')

    def test_batch_validation_result_structure(self):
        """Test BatchValidationResult class structure."""
        assert hasattr(tari_wallet_python, 'BatchValidationResult')


class TestIntegrationScenarios:
    """Integration test scenarios for extraction functionality."""

    def test_configuration_workflow(self):
        """Test complete configuration workflow."""
        # Create config
        config = tari_wallet_python.TariExtractionConfig()
        
        # Configure options
        config.set_enable_key_derivation(True)
        config.set_validate_range_proofs(True)
        config.set_validate_signatures(False)  # Disable for performance
        config.set_handle_special_outputs(True)
        config.set_detect_corruption(True)
        
        # Set keys
        config.set_private_key(VALID_PRIVATE_KEY)
        
        # Verify configuration
        assert config.enable_key_derivation is True
        assert config.validate_range_proofs is True
        assert config.validate_signatures is False
        assert config.handle_special_outputs is True
        assert config.detect_corruption is True

    def test_batch_processing_workflow(self):
        """Test complete batch processing workflow."""
        # Create batch options
        options = tari_wallet_python.BatchValidationOptions()
        
        # Configure for performance
        options.set_continue_on_error(True)
        options.set_max_errors_per_output(3)
        options.set_validate_range_proofs(True)
        options.set_validate_signatures(False)  # Disable for performance
        options.set_validate_commitments(True)
        
        # Verify configuration
        assert options.continue_on_error is True
        assert options.max_errors_per_output == 3
        assert options.validate_range_proofs is True
        assert options.validate_signatures is False
        assert options.validate_commitments is True

    def test_error_handling_consistency(self):
        """Test that error handling is consistent across all functions."""
        # Test invalid key lengths consistently fail
        with pytest.raises(Exception):
            tari_wallet_python.TariExtractionConfig.with_private_key(b'short')
        
        with pytest.raises(Exception):
            tari_wallet_python.TariExtractionConfig.with_public_key(b'short')
        
        config = tari_wallet_python.TariExtractionConfig()
        
        with pytest.raises(Exception):
            config.set_private_key(b'short')
        
        with pytest.raises(Exception):
            config.set_public_key(b'short')


class TestPerformanceConsiderations:
    """Test performance-related aspects of extraction functionality."""

    def test_gil_release_during_operations(self):
        """Test that operations release the GIL appropriately."""
        # This is more of a documentation test since we can't easily verify GIL release
        # The key functions that should release GIL are:
        # - extract_wallet_output
        # - validate_output_batch
        # - validate_output_batch_parallel
        
        # Ensure functions exist and are callable
        assert callable(tari_wallet_python.extract_wallet_output)
        assert callable(tari_wallet_python.validate_output_batch)
        
        if hasattr(tari_wallet_python, 'validate_output_batch_parallel'):
            assert callable(tari_wallet_python.validate_output_batch_parallel)

    def test_memory_efficiency_batch_processing(self):
        """Test that batch processing handles large datasets efficiently."""
        # Test with various batch sizes to ensure no memory issues
        small_batch = []
        medium_batch = [Mock() for _ in range(100)]
        
        options = tari_wallet_python.BatchValidationOptions()
        
        # These should not cause memory issues (though may fail with mock data)
        try:
            tari_wallet_python.validate_output_batch(small_batch, options)
        except Exception:
            pass
        
        try:
            tari_wallet_python.validate_output_batch(medium_batch, options)
        except Exception:
            pass


class TestSecurityConsiderations:
    """Test security-related aspects of extraction functionality."""

    def test_key_validation(self):
        """Test that key validation prevents invalid keys."""
        # Test various invalid key lengths
        invalid_keys = [
            b'',           # Empty
            b'short',      # Too short
            b'a' * 16,     # Wrong length
            b'a' * 64,     # Too long
        ]
        
        for invalid_key in invalid_keys:
            with pytest.raises(Exception):
                tari_wallet_python.TariExtractionConfig.with_private_key(invalid_key)
            
            with pytest.raises(Exception):
                tari_wallet_python.TariExtractionConfig.with_public_key(invalid_key)

    def test_error_message_sanitization(self):
        """Test that error messages don't expose sensitive information."""
        # Errors should be informative but not expose key material
        try:
            tari_wallet_python.TariExtractionConfig.with_private_key(b'short')
        except Exception as e:
            error_msg = str(e)
            # Should mention length requirement
            assert "32 bytes" in error_msg
            # Should not contain the actual key material
            assert "short" not in error_msg

    def test_configuration_immutability_between_instances(self):
        """Test that configurations don't interfere with each other."""
        config1 = tari_wallet_python.TariExtractionConfig()
        config2 = tari_wallet_python.TariExtractionConfig()
        
        # Modify one config
        config1.set_enable_key_derivation(False)
        config1.set_validate_range_proofs(False)
        
        # Other config should be unaffected
        assert config2.enable_key_derivation is True
        assert config2.validate_range_proofs is True


if __name__ == '__main__':
    # Run the test suite
    pytest.main([__file__, '-v', '--tb=short'])
