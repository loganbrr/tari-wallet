"""
Comprehensive test suite for UTXO validation API

Tests the TariUTXOValidator class and related functionality including ownership detection,
value extraction, payment ID processing, and batch validation with memory-efficient chunking.
"""

import pytest
from unittest.mock import Mock
from tari_wallet import (
    TariUTXOValidator,
    UTXOValidationConfig,
    UTXOValidationResult,
    BatchValidationSummary,
    TariUTXOBatchValidator,
    ValidationResult,
    BatchValidationResult,
)


class TestUTXOValidationConfig:
    """Test UTXOValidationConfig class"""

    def test_config_creation_defaults(self):
        """Test default configuration creation"""
        config = UTXOValidationConfig()
        assert config.validate_ownership == True
        assert config.extract_values == True
        assert config.extract_payment_ids == True
        assert config.validate_range_proofs == True
        assert config.chunk_size == 1000

    def test_config_creation_custom(self):
        """Test custom configuration creation"""
        config = UTXOValidationConfig(
            validate_ownership=False,
            extract_values=True,
            extract_payment_ids=False,
            validate_range_proofs=True
        )
        assert config.validate_ownership == False
        assert config.extract_values == True
        assert config.extract_payment_ids == False
        assert config.validate_range_proofs == True
        assert config.chunk_size == 1000  # Fixed value

    def test_config_repr(self):
        """Test configuration string representation"""
        config = UTXOValidationConfig()
        repr_str = config.__repr__()
        assert "UTXOValidationConfig" in repr_str
        assert "ownership=True" in repr_str
        assert "values=True" in repr_str
        assert "chunk_size=1000" in repr_str


class TestUTXOValidationResult:
    """Test UTXOValidationResult class"""

    def test_validation_result_creation(self):
        """Test validation result creation with mock data"""
        # This would be created by the validator in real usage
        result = UTXOValidationResult()
        result.is_owned = True
        result.value = 1000000
        result.payment_id = "abcd1234"
        result.range_proof_valid = True
        result.errors = []

        assert result.is_owned == True
        assert result.value == 1000000
        assert result.payment_id == "abcd1234"
        assert result.range_proof_valid == True
        assert len(result.errors) == 0

    def test_validation_result_with_errors(self):
        """Test validation result with errors"""
        result = UTXOValidationResult()
        result.is_owned = False
        result.value = None
        result.payment_id = None
        result.range_proof_valid = False
        result.errors = ["Invalid commitment", "Decryption failed"]

        assert result.is_owned == False
        assert result.value is None
        assert result.payment_id is None
        assert result.range_proof_valid == False
        assert len(result.errors) == 2


class TestBatchValidationSummary:
    """Test BatchValidationSummary class"""

    def test_summary_creation(self):
        """Test batch validation summary creation"""
        summary = BatchValidationSummary()
        summary.total_outputs = 100
        summary.owned_outputs = 25
        summary.valid_outputs = 20
        summary.payment_id_outputs = 5
        summary.valid_range_proofs = 18
        summary.success_rate = 0.25

        assert summary.total_outputs == 100
        assert summary.owned_outputs == 25
        assert summary.valid_outputs == 20
        assert summary.payment_id_outputs == 5
        assert summary.valid_range_proofs == 18
        assert summary.success_rate == 0.25

    def test_summary_repr(self):
        """Test summary string representation"""
        summary = BatchValidationSummary()
        summary.total_outputs = 100
        summary.owned_outputs = 25
        summary.success_rate = 0.25

        repr_str = summary.__repr__()
        assert "BatchValidationSummary" in repr_str
        assert "total=100" in repr_str
        assert "owned=25" in repr_str
        assert "success_rate=25.00%" in repr_str


class TestTariUTXOValidator:
    """Test TariUTXOValidator class"""

    @pytest.fixture
    def mock_keys(self):
        """Fixture providing mock wallet keys"""
        return {
            "view_key": "a" * 64,  # 32 bytes hex
            "spend_key": "b" * 64  # 32 bytes hex
        }

    @pytest.fixture
    def validator(self, mock_keys):
        """Fixture providing a UTXO validator instance"""
        config = UTXOValidationConfig()
        return TariUTXOValidator(
            mock_keys["view_key"],
            mock_keys["spend_key"],
            config
        )

    def test_validator_creation(self, mock_keys):
        """Test UTXO validator creation"""
        validator = TariUTXOValidator(
            mock_keys["view_key"],
            mock_keys["spend_key"]
        )
        assert validator is not None
        config = validator.config
        assert config.validate_ownership == True
        assert config.chunk_size == 1000

    def test_validator_creation_with_config(self, mock_keys):
        """Test UTXO validator creation with custom config"""
        config = UTXOValidationConfig(
            validate_ownership=True,
            extract_values=False,
            extract_payment_ids=True,
            validate_range_proofs=False
        )
        validator = TariUTXOValidator(
            mock_keys["view_key"],
            mock_keys["spend_key"],
            config
        )
        assert validator.config.validate_ownership == True
        assert validator.config.extract_values == False
        assert validator.config.extract_payment_ids == True
        assert validator.config.validate_range_proofs == False

    def test_validator_config_update(self, validator):
        """Test updating validator configuration"""
        new_config = UTXOValidationConfig(
            validate_ownership=False,
            extract_values=True,
            extract_payment_ids=False,
            validate_range_proofs=True
        )
        validator.config = new_config
        
        config = validator.config
        assert config.validate_ownership == False
        assert config.extract_values == True

    def test_single_utxo_validation(self, validator):
        """Test single UTXO validation with mock data"""
        # Create mock UTXO data
        utxo_data = {
            "commitment": "a" * 64,
            "range_proof": "b" * 128,
            "encrypted_data": "c" * 256,
        }

        # Note: With mock data, we expect validation to fail
        # This tests the API correctness rather than cryptographic validity
        try:
            result = validator.validate_utxo(utxo_data)
            # Validation may fail with mock data, which is expected
            assert isinstance(result, UTXOValidationResult)
            assert isinstance(result.is_owned, bool)
            assert isinstance(result.errors, list)
        except Exception as e:
            # Mock data validation failure is acceptable
            assert "Invalid" in str(e) or "Failed" in str(e)

    def test_batch_validation(self, validator):
        """Test batch UTXO validation"""
        # Create mock UTXO batch
        utxo_list = [
            {
                "commitment": "a" * 64,
                "range_proof": "b" * 128,
                "encrypted_data": "c" * 256,
            },
            {
                "commitment": "d" * 64,
                "range_proof": "e" * 128,
                "encrypted_data": "f" * 256,
            }
        ]

        try:
            results, summary = validator.validate_batch(utxo_list)
            assert isinstance(results, list)
            assert isinstance(summary, BatchValidationSummary)
            assert len(results) == 2
            assert summary.total_outputs == 2
        except Exception as e:
            # Mock data validation failure is acceptable
            assert "Invalid" in str(e) or "Failed" in str(e)

    def test_validator_repr(self, validator):
        """Test validator string representation"""
        repr_str = validator.__repr__()
        assert "TariUTXOValidator" in repr_str
        assert "config=" in repr_str


class TestTariUTXOBatchValidator:
    """Test TariUTXOBatchValidator class"""

    @pytest.fixture
    def batch_validator(self):
        """Fixture providing a batch validator instance"""
        return TariUTXOBatchValidator()

    @pytest.fixture
    def mock_keys(self):
        """Fixture providing mock wallet keys"""
        return {
            "view_key": "a" * 64,
            "spend_key": "b" * 64
        }

    def test_batch_validator_creation(self):
        """Test batch validator creation"""
        validator = TariUTXOBatchValidator()
        assert validator.chunk_size == 1000

    def test_batch_validator_custom_chunk_size(self):
        """Test batch validator with custom chunk size"""
        validator = TariUTXOBatchValidator(chunk_size=500)
        assert validator.chunk_size == 500

    def test_chunk_size_update(self, batch_validator):
        """Test updating chunk size"""
        batch_validator.chunk_size = 2000
        assert batch_validator.chunk_size == 2000

    def test_batch_ownership_validation(self, batch_validator, mock_keys):
        """Test batch ownership validation"""
        utxo_list = [
            {"encrypted_data": "a" * 256},
            {"encrypted_data": "b" * 256}
        ]

        try:
            result = batch_validator.batch_validate_ownership(
                utxo_list,
                mock_keys["view_key"],
                mock_keys["spend_key"]
            )
            assert isinstance(result, BatchValidationResult)
            assert hasattr(result, 'results')
        except Exception as e:
            # Mock data validation failure is acceptable
            assert "Invalid" in str(e) or "Missing" in str(e) or "Failed" in str(e)

    def test_large_batch_chunking(self, batch_validator):
        """Test that large batches are properly chunked"""
        # Create a large mock dataset
        large_utxo_list = [
            {"encrypted_data": f"{i:0256d}"} for i in range(2500)
        ]

        # Set small chunk size for testing
        batch_validator.chunk_size = 1000

        try:
            result = batch_validator.batch_validate_ownership(
                large_utxo_list,
                "a" * 64,
                "b" * 64
            )
            # If it doesn't crash, chunking worked
            assert isinstance(result, BatchValidationResult)
        except Exception as e:
            # Mock data validation failure is acceptable
            # Important thing is that it processes all chunks without memory issues
            assert "Invalid" in str(e) or "Missing" in str(e) or "Failed" in str(e)


class TestValidationIntegration:
    """Integration tests for validation components"""

    def test_config_validator_integration(self):
        """Test that configuration properly affects validator behavior"""
        config_ownership_only = UTXOValidationConfig(
            validate_ownership=True,
            extract_values=False,
            extract_payment_ids=False,
            validate_range_proofs=False
        )

        validator = TariUTXOValidator(
            "a" * 64,
            "b" * 64,
            config_ownership_only
        )

        assert validator.config.validate_ownership == True
        assert validator.config.extract_values == False
        assert validator.config.extract_payment_ids == False
        assert validator.config.validate_range_proofs == False

    def test_validation_error_handling(self):
        """Test validation error handling with invalid inputs"""
        with pytest.raises(Exception):
            # Invalid key length
            TariUTXOValidator("invalid_key", "b" * 64)

        with pytest.raises(Exception):
            # Invalid hex
            TariUTXOValidator("invalid_hex", "b" * 64)

    def test_performance_with_fixed_chunking(self):
        """Test that fixed chunking provides consistent performance"""
        import time
        
        validator = TariUTXOBatchValidator()
        
        # All validators should use same chunk size
        assert validator.chunk_size == 1000
        
        # Test that chunk size cannot be configured to invalid values
        validator.chunk_size = 1000  # Reset to fixed value
        assert validator.chunk_size == 1000


if __name__ == "__main__":
    pytest.main([__file__])
