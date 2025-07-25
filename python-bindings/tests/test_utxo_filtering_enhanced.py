"""
Enhanced UTXO filtering capabilities test suite

Tests the enhanced UTXOFilter with validation integration, script pattern support,
and maturity-based filtering capabilities.
"""

import pytest
from unittest.mock import Mock
from tari_wallet import (
    UTXOFilter,
    PyScriptPattern,
    TariUTXOValidator,
    TariUTXOManager,
    UTXOValidationConfig,
)


class TestPyScriptPattern:
    """Test PyScriptPattern enumeration"""

    def test_script_pattern_standard(self):
        """Test standard script pattern"""
        pattern = PyScriptPattern.Standard
        str_repr = pattern.__str__()
        assert str_repr == "Standard"
        
        repr_str = pattern.__repr__()
        assert "ScriptPattern::Standard" in repr_str

    def test_script_pattern_simple_one_sided(self):
        """Test simple one-sided script pattern"""
        pattern = PyScriptPattern.SimpleOneSided
        pattern.key_hex = "abcd1234efgh5678"
        
        str_repr = pattern.__str__()
        assert "SimpleOneSided" in str_repr
        assert "abcd1234" in str_repr  # Shows first 8 chars

    def test_script_pattern_stealth_one_sided(self):
        """Test stealth one-sided script pattern"""
        pattern = PyScriptPattern.StealthOneSided
        pattern.nonce_hex = "nonce123456789ab"
        pattern.key_hex = "key123456789abcd"
        
        str_repr = pattern.__str__()
        assert "StealthOneSided" in str_repr
        assert "nonce123" in str_repr
        assert "key12345" in str_repr

    def test_script_pattern_equality(self):
        """Test script pattern equality comparison"""
        pattern1 = PyScriptPattern.Standard
        pattern2 = PyScriptPattern.Standard
        pattern3 = PyScriptPattern.Unknown
        
        assert pattern1 == pattern2
        assert pattern1 != pattern3


class TestEnhancedUTXOFilter:
    """Test enhanced UTXOFilter with validation integration"""

    @pytest.fixture
    def base_filter(self):
        """Fixture providing a basic UTXO filter"""
        return UTXOFilter()

    @pytest.fixture
    def mock_validator(self):
        """Fixture providing a mock UTXO validator"""
        config = UTXOValidationConfig()
        return TariUTXOValidator("a" * 64, "b" * 64, config)

    def test_filter_creation_defaults(self, base_filter):
        """Test filter creation with defaults"""
        assert base_filter.wallet_id is None
        assert base_filter.min_value is None
        assert base_filter.max_value is None
        assert base_filter.status is None
        assert base_filter.mature_only == False
        assert base_filter.spendable_at_height is None
        assert base_filter.limit is None
        assert base_filter.offset is None
        # Enhanced fields
        assert base_filter.ownership_validation == False
        assert base_filter.script_pattern is None
        assert base_filter.maturity_at_height is None
        assert base_filter.validate_before_filter == False

    def test_filter_basic_methods(self, base_filter):
        """Test basic filter methods work correctly"""
        filter_with_wallet = base_filter.with_wallet_id(123)
        assert filter_with_wallet.wallet_id == 123

        filter_with_range = base_filter.with_value_range(1000, 5000)
        assert filter_with_range.min_value == 1000
        assert filter_with_range.max_value == 5000

        filter_with_status = base_filter.with_status(1)
        assert filter_with_status.status == 1

        filter_spendable = base_filter.spendable_at(12345)
        assert filter_spendable.spendable_at_height == 12345

        filter_limited = base_filter.with_limit(100)
        assert filter_limited.limit == 100

        filter_offset = base_filter.with_offset(50)
        assert filter_offset.offset == 50

    def test_enhanced_filter_methods(self, base_filter):
        """Test enhanced filter methods"""
        # Test ownership validation
        filter_ownership = base_filter.by_ownership(True)
        assert filter_ownership.ownership_validation == True

        # Test maturity filtering
        filter_maturity = base_filter.by_maturity_at_height(54321)
        assert filter_maturity.maturity_at_height == 54321

        # Test script pattern filtering
        pattern = PyScriptPattern.Standard
        filter_pattern = base_filter.by_script_pattern(pattern)
        assert filter_pattern.script_pattern == pattern

        # Test validation before filter
        filter_validation = base_filter.validate_before_filter(True)
        assert filter_validation.validate_before_filter == True

    def test_filter_validator_integration(self, base_filter, mock_validator):
        """Test filter integration with validator"""
        filter_with_validator = base_filter.set_validator(mock_validator)
        assert filter_with_validator.validator is not None

    def test_filter_method_chaining(self, base_filter):
        """Test that filter methods can be chained"""
        chained_filter = (base_filter
                         .with_wallet_id(123)
                         .with_value_range(1000, 5000)
                         .by_ownership(True)
                         .by_maturity_at_height(12345)
                         .validate_before_filter(True))

        assert chained_filter.wallet_id == 123
        assert chained_filter.min_value == 1000
        assert chained_filter.max_value == 5000
        assert chained_filter.ownership_validation == True
        assert chained_filter.maturity_at_height == 12345
        assert chained_filter.validate_before_filter == True

    def test_filter_script_pattern_integration(self, base_filter):
        """Test script pattern filtering integration"""
        # Test with different script patterns
        patterns = [
            PyScriptPattern.Standard,
            PyScriptPattern.UnrecognizedOneSided,
            PyScriptPattern.UnrecognizedStealth,
            PyScriptPattern.Unknown
        ]

        for pattern in patterns:
            filtered = base_filter.by_script_pattern(pattern)
            assert filtered.script_pattern == pattern

    def test_filter_string_representation(self, base_filter):
        """Test enhanced filter string representation"""
        complex_filter = (base_filter
                         .with_wallet_id(123)
                         .with_value_range(1000, 5000)
                         .with_status(0)
                         .by_ownership(True)
                         .validate_before_filter(True))

        str_repr = complex_filter.__str__()
        assert "UTXOFilter" in str_repr
        assert "wallet_id=123" in str_repr
        assert "value_range=1000-5000" in str_repr
        assert "ownership=True" in str_repr
        assert "validation=True" in str_repr

    def test_filter_with_script_pattern_string(self, base_filter):
        """Test filter string representation with script pattern"""
        pattern = PyScriptPattern.Standard
        filtered = base_filter.by_script_pattern(pattern)
        
        str_repr = filtered.__str__()
        assert "script_pattern='Standard'" in str_repr

    def test_filter_edge_cases(self, base_filter):
        """Test filter edge cases and error conditions"""
        # Test with None script pattern
        filter_none_pattern = base_filter.by_script_pattern(None)
        # Should handle None gracefully (though may not be typical usage)

        # Test multiple validator assignments
        validator1 = TariUTXOValidator("a" * 64, "b" * 64)
        validator2 = TariUTXOValidator("c" * 64, "d" * 64)
        
        filter1 = base_filter.set_validator(validator1)
        filter2 = filter1.set_validator(validator2)
        
        # Latest validator should be set
        assert filter2.validator is not None


class TestUTXOFilterIntegration:
    """Integration tests for enhanced UTXO filtering"""

    @pytest.fixture
    def utxo_manager(self):
        """Fixture providing a UTXO manager for integration tests"""
        return TariUTXOManager()

    def test_filter_utxo_manager_integration(self, utxo_manager):
        """Test filter integration with UTXO manager"""
        # Create enhanced filter
        enhanced_filter = (UTXOFilter()
                          .with_wallet_id(1)
                          .by_ownership(True)
                          .by_maturity_at_height(12345))

        # Integration test - verify filter can be used with UTXO manager
        # Note: Without actual storage, this tests API compatibility
        assert enhanced_filter.wallet_id == 1
        assert enhanced_filter.ownership_validation == True
        assert enhanced_filter.maturity_at_height == 12345

    def test_validation_workflow_integration(self):
        """Test complete validation workflow integration"""
        # Create validator
        validator = TariUTXOValidator("a" * 64, "b" * 64)
        
        # Create filter with validation
        filter_with_validation = (UTXOFilter()
                                 .with_wallet_id(1)
                                 .by_ownership(True)
                                 .validate_before_filter(True)
                                 .set_validator(validator))

        assert filter_with_validation.validate_before_filter == True
        assert filter_with_validation.validator is not None
        assert filter_with_validation.ownership_validation == True

    def test_script_pattern_filtering_workflow(self):
        """Test script pattern filtering workflow"""
        # Test filtering by different script patterns
        filters = []
        
        # Standard outputs filter
        standard_filter = (UTXOFilter()
                          .by_script_pattern(PyScriptPattern.Standard)
                          .with_wallet_id(1))
        filters.append(standard_filter)
        
        # One-sided outputs filter
        onesided_filter = (UTXOFilter()
                          .by_script_pattern(PyScriptPattern.UnrecognizedOneSided)
                          .with_wallet_id(1))
        filters.append(onesided_filter)
        
        # Stealth outputs filter  
        stealth_filter = (UTXOFilter()
                         .by_script_pattern(PyScriptPattern.UnrecognizedStealth)
                         .with_wallet_id(1))
        filters.append(stealth_filter)

        # Verify all filters have correct patterns
        assert filters[0].script_pattern == PyScriptPattern.Standard
        assert filters[1].script_pattern == PyScriptPattern.UnrecognizedOneSided
        assert filters[2].script_pattern == PyScriptPattern.UnrecognizedStealth

    def test_maturity_based_filtering(self):
        """Test maturity-based filtering scenarios"""
        current_height = 100000
        
        # Filter for outputs mature at current height
        mature_filter = (UTXOFilter()
                        .by_maturity_at_height(current_height)
                        .with_wallet_id(1))
        
        # Filter for outputs requiring future maturity
        future_filter = (UTXOFilter()
                        .by_maturity_at_height(current_height + 1000)
                        .with_wallet_id(1))

        assert mature_filter.maturity_at_height == current_height
        assert future_filter.maturity_at_height == current_height + 1000

    def test_complex_filtering_combinations(self):
        """Test complex combinations of filtering criteria"""
        # Complex filter combining multiple criteria
        complex_filter = (UTXOFilter()
                         .with_wallet_id(1)
                         .with_value_range(1000000, 10000000)  # 1-10 Tari
                         .with_status(0)  # Unspent
                         .by_ownership(True)
                         .by_maturity_at_height(100000)
                         .by_script_pattern(PyScriptPattern.Standard)
                         .validate_before_filter(True)
                         .with_limit(50)
                         .with_offset(0))

        # Verify all criteria are set
        assert complex_filter.wallet_id == 1
        assert complex_filter.min_value == 1000000
        assert complex_filter.max_value == 10000000
        assert complex_filter.status == 0
        assert complex_filter.ownership_validation == True
        assert complex_filter.maturity_at_height == 100000
        assert complex_filter.script_pattern == PyScriptPattern.Standard
        assert complex_filter.validate_before_filter == True
        assert complex_filter.limit == 50
        assert complex_filter.offset == 0

    def test_performance_with_large_filters(self):
        """Test performance characteristics with complex filters"""
        import time
        
        start_time = time.time()
        
        # Create many complex filters to test performance
        filters = []
        for i in range(1000):
            complex_filter = (UTXOFilter()
                             .with_wallet_id(i)
                             .by_ownership(True)
                             .by_maturity_at_height(i * 1000)
                             .validate_before_filter(True))
            filters.append(complex_filter)
        
        end_time = time.time()
        
        # Filter creation should be fast (< 1 second for 1000 filters)
        assert end_time - start_time < 1.0
        assert len(filters) == 1000
        
        # Verify filters are correctly configured
        assert filters[500].wallet_id == 500
        assert filters[500].maturity_at_height == 500000


if __name__ == "__main__":
    pytest.main([__file__])
