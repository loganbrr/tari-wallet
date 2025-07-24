#!/usr/bin/env python3
"""Integration tests specifically for TariUTXOManager functionality."""

import pytest
import os
import tempfile

# Import the Python module built by maturin
try:
    from lightweight_wallet_libpy import TariWalletStorage, TariUTXOManager, UTXOFilter
except ImportError:
    pytest.skip("lightweight_wallet_libpy not available - run 'maturin develop' first", allow_module_level=True)


@pytest.fixture
def temp_db_path():
    """Create a temporary database file path."""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def initialized_storage_with_data(temp_db_path):
    """Create storage with sample wallet and UTXO data."""
    storage = TariWalletStorage(temp_db_path)
    storage.initialize()
    
    # Create sample wallet
    wallet_data = {
        'name': 'test_wallet',
        'seed_phrase': 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
        'view_key_hex': '0123456789abcdef' * 4,  # 32 bytes (64 hex chars)
        'spend_key_hex': 'fedcba9876543210' * 4,  # 32 bytes (64 hex chars)
        'birthday_block': 0,
        'latest_scanned_block': 0,
    }
    wallet_id = storage.save_wallet(wallet_data)
    
    # Create sample UTXOs
    utxos = [
        {
            'wallet_id': wallet_id,
            'commitment_hex': 'aabbccdd' * 8,  # 32 bytes (64 hex chars)
            'hash_hex': 'ddccbbaa' * 8,  # 32 bytes (64 hex chars)
            'value': 1000000,
            'spending_key_hex': '0123456789abcdef' * 4,  # 32 bytes (64 hex chars)
            'script_private_key_hex': 'fedcba9876543210' * 4,  # 32 bytes (64 hex chars)
            'script_hex': 'abcdef12' * 8,  # 32 bytes (64 hex chars)
            'input_data_hex': '12345678' * 8,  # 32 bytes (64 hex chars)
            'covenant_hex': '87654321' * 8,  # 32 bytes (64 hex chars)
            'output_type': 0,
            'features_json': '{}',
            'maturity': 100,
            'script_lock_height': 0,
            'sender_offset_public_key_hex': 'abcdef00' * 4,  # 32 bytes (64 hex chars)
            'metadata_signature_ephemeral_commitment_hex': 'deadbeef' * 8,  # 32 bytes (64 hex chars)
            'metadata_signature_ephemeral_pubkey_hex': 'cafebabe' * 8,  # 32 bytes (64 hex chars)
            'metadata_signature_u_a_hex': '12345678' * 8,  # 32 bytes (64 hex chars)
            'metadata_signature_u_x_hex': '87654321' * 8,  # 32 bytes (64 hex chars)
            'metadata_signature_u_y_hex': 'abcdef12' * 8,  # 32 bytes (64 hex chars)
            'encrypted_data_hex': 'feedface' * 8,  # 32 bytes (64 hex chars)
            'minimum_value_promise': 1000000,
            'rangeproof_hex': None,
            'status': 0,  # Unspent
            'mined_height': 12345,
            'spent_in_tx_id': None,
        },
        {
            'wallet_id': wallet_id,
            'commitment_hex': 'eeffaabb' * 8,  # 32 bytes (64 hex chars)
            'hash_hex': 'bbaaffee' * 8,  # 32 bytes (64 hex chars)
            'value': 2000000,
            'spending_key_hex': '0123456789abcdef' * 4,  # 32 bytes (64 hex chars)
            'script_private_key_hex': 'fedcba9876543210' * 4,  # 32 bytes (64 hex chars)
            'script_hex': 'abcdef12' * 8,  # 32 bytes (64 hex chars)
            'input_data_hex': '12345678' * 8,  # 32 bytes (64 hex chars)
            'covenant_hex': '87654321' * 8,  # 32 bytes (64 hex chars)
            'output_type': 0,
            'features_json': '{}',
            'maturity': 200,  # Higher maturity
            'script_lock_height': 0,
            'sender_offset_public_key_hex': 'abcdef00' * 4,  # 32 bytes (64 hex chars)
            'metadata_signature_ephemeral_commitment_hex': 'deadbeef' * 8,  # 32 bytes (64 hex chars)
            'metadata_signature_ephemeral_pubkey_hex': 'cafebabe' * 8,  # 32 bytes (64 hex chars)
            'metadata_signature_u_a_hex': '12345678' * 8,  # 32 bytes (64 hex chars)
            'metadata_signature_u_x_hex': '87654321' * 8,  # 32 bytes (64 hex chars)
            'metadata_signature_u_y_hex': 'abcdef12' * 8,  # 32 bytes (64 hex chars)
            'encrypted_data_hex': 'feedface' * 8,  # 32 bytes (64 hex chars)
            'minimum_value_promise': 2000000,
            'rangeproof_hex': None,
            'status': 0,  # Unspent
            'mined_height': 12346,
            'spent_in_tx_id': None,
        },
        {
            'wallet_id': wallet_id,
            'commitment_hex': '11223344' * 8,  # 32 bytes (64 hex chars)
            'hash_hex': '44332211' * 8,  # 32 bytes (64 hex chars)
            'value': 500000,
            'spending_key_hex': '0123456789abcdef' * 4,  # 32 bytes (64 hex chars)
            'script_private_key_hex': 'fedcba9876543210' * 4,  # 32 bytes (64 hex chars)
            'script_hex': 'abcdef12' * 8,  # 32 bytes (64 hex chars)
            'input_data_hex': '12345678' * 8,  # 32 bytes (64 hex chars)
            'covenant_hex': '87654321' * 8,  # 32 bytes (64 hex chars)
            'output_type': 0,
            'features_json': '{}',
            'maturity': 50,
            'script_lock_height': 0,
            'sender_offset_public_key_hex': 'abcdef00' * 4,  # 32 bytes (64 hex chars)
            'metadata_signature_ephemeral_commitment_hex': 'deadbeef' * 8,  # 32 bytes (64 hex chars)
            'metadata_signature_ephemeral_pubkey_hex': 'cafebabe' * 8,  # 32 bytes (64 hex chars)
            'metadata_signature_u_a_hex': '12345678' * 8,  # 32 bytes (64 hex chars)
            'metadata_signature_u_x_hex': '87654321' * 8,  # 32 bytes (64 hex chars)
            'metadata_signature_u_y_hex': 'abcdef12' * 8,  # 32 bytes (64 hex chars)
            'encrypted_data_hex': 'feedface' * 8,  # 32 bytes (64 hex chars)
            'minimum_value_promise': 500000,
            'rangeproof_hex': None,
            'status': 1,  # Spent
            'mined_height': 12340,
            'spent_in_tx_id': 99999,
        }
    ]
    
    for utxo in utxos:
        storage.save_output(utxo)
    
    return storage, wallet_id


class TestUTXOFiltering:
    """Test UTXO filtering functionality."""

    def test_filter_by_wallet(self, initialized_storage_with_data):
        """Test filtering UTXOs by wallet ID."""
        storage, wallet_id = initialized_storage_with_data
        
        utxo_manager = TariUTXOManager()
        utxo_manager.set_storage(storage)
        
        # Filter by wallet ID
        filter_obj = UTXOFilter()
        filter_obj.wallet_id = wallet_id
        
        result = utxo_manager.get_utxos(filter_obj)
        assert len(result.utxos) == 3  # All UTXOs belong to this wallet
        assert result.total_value == 3500000  # 1M + 2M + 500K

    def test_filter_by_value_range(self, initialized_storage_with_data):
        """Test filtering UTXOs by value range."""
        storage, wallet_id = initialized_storage_with_data
        
        utxo_manager = TariUTXOManager()
        utxo_manager.set_storage(storage)
        
        # Filter by value range (only UTXOs >= 1M)
        filter_obj = UTXOFilter()
        filter_obj.wallet_id = wallet_id
        filter_obj.min_value = 1000000
        
        result = utxo_manager.get_utxos(filter_obj)
        assert len(result.utxos) == 2  # 1M and 2M UTXOs
        assert result.total_value == 3000000

    def test_filter_by_status(self, initialized_storage_with_data):
        """Test filtering UTXOs by status."""
        storage, wallet_id = initialized_storage_with_data
        
        utxo_manager = TariUTXOManager()
        utxo_manager.set_storage(storage)
        
        # Filter by unspent status
        filter_obj = UTXOFilter()
        filter_obj.wallet_id = wallet_id
        filter_obj.status = 0  # Unspent
        
        result = utxo_manager.get_utxos(filter_obj)
        assert len(result.utxos) == 2  # Only unspent UTXOs
        assert result.total_value == 3000000  # 1M + 2M

    def test_spendable_utxos(self, initialized_storage_with_data):
        """Test getting spendable UTXOs with maturity consideration."""
        storage, wallet_id = initialized_storage_with_data
        
        utxo_manager = TariUTXOManager()
        utxo_manager.set_storage(storage)
        
        # Test with block height that makes first UTXO spendable (maturity 100)
        result = utxo_manager.get_spendable_utxos(wallet_id, 12445)  # 12345 + 100
        assert len(result.utxos) == 1  # Only first UTXO is mature enough
        assert result.utxos[0].value == 1000000
        assert result.spendable_count == 1

        # Test with higher block height that makes both UTXOs spendable
        result = utxo_manager.get_spendable_utxos(wallet_id, 12546)  # 12346 + 200
        assert len(result.utxos) == 2  # Both unspent UTXOs are mature
        assert result.spendable_count == 2
        assert result.total_value == 3000000

    def test_spendable_balance(self, initialized_storage_with_data):
        """Test calculating spendable balance."""
        storage, wallet_id = initialized_storage_with_data
        
        utxo_manager = TariUTXOManager()
        utxo_manager.set_storage(storage)
        
        # Test balance with first UTXO spendable
        balance = utxo_manager.get_spendable_balance(wallet_id, 12445)
        assert balance == 1000000

        # Test balance with both UTXOs spendable
        balance = utxo_manager.get_spendable_balance(wallet_id, 12546)
        assert balance == 3000000


class TestUTXOSummaryInformation:
    """Test UTXO summary and statistics."""

    def test_utxo_list_summary(self, initialized_storage_with_data):
        """Test UTXOList summary information."""
        storage, wallet_id = initialized_storage_with_data
        
        utxo_manager = TariUTXOManager()
        utxo_manager.set_storage(storage)
        
        filter_obj = UTXOFilter()
        filter_obj.wallet_id = wallet_id
        
        result = utxo_manager.get_utxos(filter_obj)
        
        # Verify summary information
        assert result.total_value == 3500000
        assert len(result.utxos) == 3
        
        # Check individual UTXO information
        values = [utxo.value for utxo in result.utxos]
        assert 1000000 in values
        assert 2000000 in values
        assert 500000 in values

    def test_unspent_utxos_only(self, initialized_storage_with_data):
        """Test getting only unspent UTXOs."""
        storage, wallet_id = initialized_storage_with_data
        
        utxo_manager = TariUTXOManager()
        utxo_manager.set_storage(storage)
        
        # Get unspent UTXOs
        result = utxo_manager.get_unspent_utxos(wallet_id)
        
        # Should only return unspent UTXOs
        assert len(result.utxos) == 2
        assert result.total_value == 3000000  # Excludes the spent 500K UTXO
        
        # Verify all returned UTXOs are unspent
        for utxo in result.utxos:
            assert utxo.status == 0  # Unspent
            assert utxo.spent_in_tx_id is None


class TestUTXOManagerEdgeCases:
    """Test edge cases and error conditions."""

    def test_no_storage_set(self):
        """Test operations without setting storage."""
        utxo_manager = TariUTXOManager()
        
        # Should raise error when no storage is set
        with pytest.raises(Exception):  # RuntimeError from Python
            filter_obj = UTXOFilter()
            utxo_manager.get_utxos(filter_obj)

    def test_empty_results(self, initialized_storage_with_data):
        """Test operations that return empty results."""
        storage, wallet_id = initialized_storage_with_data
        
        utxo_manager = TariUTXOManager()
        utxo_manager.set_storage(storage)
        
        # Filter for non-existent wallet
        filter_obj = UTXOFilter()
        filter_obj.wallet_id = 99999  # Non-existent wallet
        
        result = utxo_manager.get_utxos(filter_obj)
        assert len(result.utxos) == 0
        assert result.total_value == 0

        # Test spendable balance for non-existent wallet
        balance = utxo_manager.get_spendable_balance(99999, 50000)
        assert balance == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
