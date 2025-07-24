#!/usr/bin/env python3
"""Integration tests for TariWalletStorage and TariUTXOManager interaction."""

import pytest
import os
import tempfile
from typing import Dict, Any

# Import the Python module built by maturin
try:
    from lightweight_wallet_libpy import TariWalletStorage, TariUTXOManager, UTXOFilter
except ImportError:
    pytest.skip("lightweight_wallet_libpy not available - run 'maturin develop' first", allow_module_level=True)


@pytest.fixture
def temp_db_path():
    """Create a temporary database file path."""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)  # Close the file descriptor, we just need the path
    yield path
    # Cleanup after test
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def storage(temp_db_path):
    """Create and initialize a TariWalletStorage instance."""
    storage = TariWalletStorage(temp_db_path)
    storage.initialize()
    return storage


@pytest.fixture
def utxo_manager():
    """Create a TariUTXOManager instance."""
    return TariUTXOManager()


@pytest.fixture
def sample_wallet_data():
    """Sample wallet data for testing."""
    return {
        'name': 'test_wallet',
        'seed_phrase': 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
        'view_key_hex': '0123456789abcdef' * 4,  # 32 bytes (64 hex chars)
        'spend_key_hex': 'fedcba9876543210' * 4,  # 32 bytes (64 hex chars)
        'birthday_block': 0,
        'latest_scanned_block': 0,
    }


@pytest.fixture
def sample_transaction_data():
    """Sample transaction data for testing."""
    return {
        'block_height': 12345,
        'output_index': 0,
        'input_index': None, 
        'commitment_hex': 'aabbccdd' * 8,  # 32 bytes (64 hex chars)
        'output_hash_hex': 'ddccbbaa' * 8,  # 32 bytes (64 hex chars)
        'value': 1000000,
        'payment_id': {'type': 'Empty', 'value': None},
        'transaction_status': 'minedconfirmed',
        'transaction_direction': 'inbound',
        'is_mature': True,
        'is_spent': False,
        'spent_in_block': None,
        'spent_in_input': None,
        'mined_timestamp': 1234567890,
    }


@pytest.fixture
def sample_output_data():
    """Sample UTXO output data for testing."""
    return {
        'wallet_id': 1,
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
        'status': 0,  # OutputStatus::Unspent
        'mined_height': 12345,
        'spent_in_tx_id': None,
    }


class TestStorageIntegration:
    """Test storage functionality."""

    def test_wallet_lifecycle(self, storage, sample_wallet_data):
        """Test basic wallet operations."""
        # Save wallet
        wallet_id = storage.save_wallet(sample_wallet_data)
        assert isinstance(wallet_id, int)
        assert wallet_id > 0

        # Get wallet by ID
        wallet = storage.get_wallet_by_id(wallet_id)
        assert wallet is not None
        assert wallet['name'] == sample_wallet_data['name']
        assert wallet['seed_phrase'] == sample_wallet_data['seed_phrase']

        # Get wallet by name
        wallet_by_name = storage.get_wallet_by_name(sample_wallet_data['name'])
        assert wallet_by_name is not None
        assert wallet_by_name['id'] == wallet_id

        # List wallets
        wallets = storage.list_wallets()
        assert len(wallets) == 1
        assert wallets[0]['id'] == wallet_id

        # Check name exists
        assert storage.wallet_name_exists(sample_wallet_data['name'])
        assert not storage.wallet_name_exists('nonexistent_wallet')

        # Delete wallet
        deleted = storage.delete_wallet(wallet_id)
        assert deleted

        # Verify deletion
        assert storage.get_wallet_by_id(wallet_id) is None
        assert not storage.wallet_name_exists(sample_wallet_data['name'])

    def test_transaction_persistence(self, storage, sample_wallet_data, sample_transaction_data):
        """Test transaction storage operations."""
        # Create wallet first
        wallet_id = storage.save_wallet(sample_wallet_data)
        
        # Save transaction
        storage.save_transaction(wallet_id, sample_transaction_data)

        # Get transactions
        transactions = storage.get_transactions(wallet_id, {})
        assert len(transactions) == 1
        
        tx = transactions[0]
        assert tx['block_height'] == sample_transaction_data['block_height']
        assert tx['value'] == sample_transaction_data['value']
        assert tx['commitment_hex'] == sample_transaction_data['commitment_hex']

        # Mark transaction as spent
        storage.mark_transaction_spent(
            sample_transaction_data['commitment_hex'], 
            54321,  # spent_in_block
            0       # spent_in_input
        )

        # Verify transaction is marked as spent
        updated_transactions = storage.get_transactions(wallet_id, {})
        assert len(updated_transactions) == 1
        assert updated_transactions[0]['is_spent'] == True
        assert updated_transactions[0]['spent_in_block'] == 54321

    def test_utxo_persistence(self, storage, sample_wallet_data, sample_output_data):
        """Test UTXO storage operations."""
        # Create wallet first
        wallet_id = storage.save_wallet(sample_wallet_data)
        sample_output_data['wallet_id'] = wallet_id

        # Save output
        output_id = storage.save_output(sample_output_data)
        assert isinstance(output_id, int)
        assert output_id > 0

        # Get outputs
        outputs = storage.get_outputs({})
        assert len(outputs) == 1
        
        output = outputs[0]
        assert output['wallet_id'] == wallet_id
        assert output['value'] == sample_output_data['value']
        assert output['commitment_hex'] == sample_output_data['commitment_hex']

        # Get spendable balance
        balance = storage.get_spendable_balance(wallet_id, 50000)  # High block height
        assert balance == sample_output_data['value']

        # Mark output as spent
        storage.mark_output_spent(output_id, 99999)

        # Verify output is marked as spent
        updated_outputs = storage.get_outputs({})
        assert len(updated_outputs) == 1
        assert updated_outputs[0]['spent_in_tx_id'] == 99999


class TestUTXOManagerIntegration:
    """Test UTXO manager integration with storage."""

    def test_set_storage_integration(self, storage, utxo_manager):
        """Test setting storage backend on UTXO manager."""
        # This should work without error
        utxo_manager.set_storage(storage)
        
        # Verify we can perform operations (should not raise errors)
        filter_obj = UTXOFilter()
        result = utxo_manager.get_utxos(filter_obj)
        assert result is not None
        assert hasattr(result, 'utxos')
        assert hasattr(result, 'total_value')

    def test_utxo_operations_with_storage(self, storage, utxo_manager, sample_wallet_data, sample_output_data):
        """Test UTXO operations through the manager with storage backend."""
        # Set up storage with wallet and UTXO
        wallet_id = storage.save_wallet(sample_wallet_data)
        sample_output_data['wallet_id'] = wallet_id
        output_id = storage.save_output(sample_output_data)

        # Set storage on UTXO manager
        utxo_manager.set_storage(storage)

        # Get UTXOs through manager
        filter_obj = UTXOFilter()
        filter_obj.wallet_id = wallet_id
        
        result = utxo_manager.get_utxos(filter_obj)
        assert result is not None
        assert len(result.utxos) == 1
        assert result.total_value == sample_output_data['value']
        assert result.utxos[0].wallet_id == wallet_id
        assert result.utxos[0].value == sample_output_data['value']

        # Get spendable UTXOs
        spendable_result = utxo_manager.get_spendable_utxos(wallet_id, 50000)
        assert spendable_result is not None
        assert len(spendable_result.utxos) == 1
        assert spendable_result.spendable_count == 1

        # Get spendable balance
        balance = utxo_manager.get_spendable_balance(wallet_id, 50000)
        assert balance == sample_output_data['value']

    def test_storage_sharing(self, storage, sample_wallet_data, sample_output_data):
        """Test that storage is properly shared between wallet storage and UTXO manager."""
        # Set up data through storage
        wallet_id = storage.save_wallet(sample_wallet_data)
        sample_output_data['wallet_id'] = wallet_id
        output_id = storage.save_output(sample_output_data)

        # Create UTXO manager and set storage
        utxo_manager = TariUTXOManager()
        utxo_manager.set_storage(storage)

        # Verify UTXO manager can see data created through storage
        filter_obj = UTXOFilter()
        filter_obj.wallet_id = wallet_id
        
        result = utxo_manager.get_utxos(filter_obj)
        assert len(result.utxos) == 1
        assert result.utxos[0].value == sample_output_data['value']

        # Create another UTXO manager with the same storage
        utxo_manager2 = TariUTXOManager()
        utxo_manager2.set_storage(storage)

        # Both managers should see the same data
        result2 = utxo_manager2.get_utxos(filter_obj)
        assert len(result2.utxos) == 1
        assert result2.utxos[0].value == sample_output_data['value']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
