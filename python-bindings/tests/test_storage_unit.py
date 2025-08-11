#!/usr/bin/env python3
import pytest

from lightweight_wallet_libpy import (
    TariWalletStorage,
    OutputStatus,
    OutputFilter,
)


def test_storage_initialize_and_close(tmp_path):
    db_path = tmp_path / "unit.db"
    st = TariWalletStorage(str(db_path))
    st.initialize()
    assert "TariWalletStorage(" in str(st)
    st.close()


def test_output_filter_builders():
    f = OutputFilter()
    f = f.wallet_id(1)
    f = f.status(OutputStatus.unspent())
    f = f.value_range(10, 100)
    f = f.spendable_at(50)
    f = f.limit(10)
    f = f.offset(20)
    # just ensure builder returns an object and repr works
    assert "OutputFilter" in repr(f)


# Extended tests

def _mk_wallet(storage: TariWalletStorage, name: str) -> int:
    wallet = {
        'name': name,
        'seed_phrase': 'abandon ' * 11 + 'about',
        'view_key_hex': '01' * 32,
        'spend_key_hex': '02' * 32,
        'birthday_block': 0,
        'latest_scanned_block': 0,
    }
    return storage.save_wallet(wallet)


def _mk_output(wallet_id: int, value: int, status: int, maturity: int):
    return {
        'wallet_id': wallet_id,
        'commitment_hex': 'aa' * 32,
        'hash_hex': 'bb' * 32,
        'value': value,
        'spending_key_hex': '01' * 32,
        'script_private_key_hex': '02' * 32,
        'script_hex': '00' * 32,
        'input_data_hex': '00' * 32,
        'covenant_hex': '00' * 32,
        'output_type': 0,
        'features_json': '{}',
        'maturity': maturity,
        'script_lock_height': 0,
        'sender_offset_public_key_hex': '03' * 32,
        'metadata_signature_ephemeral_commitment_hex': '04' * 32,
        'metadata_signature_ephemeral_pubkey_hex': '05' * 32,
        'metadata_signature_u_a_hex': '06' * 32,
        'metadata_signature_u_x_hex': '07' * 32,
        'metadata_signature_u_y_hex': '08' * 32,
        'encrypted_data_hex': '09' * 32,
        'minimum_value_promise': value,
        'rangeproof_hex': None,
        'status': status,
        'mined_height': 0,
        'spent_in_tx_id': None,
    }


def test_output_filtering_and_balance(tmp_path):
    db_path = tmp_path / "filters.db"
    st = TariWalletStorage(str(db_path))
    st.initialize()

    wid = _mk_wallet(st, "w")

    # Insert outputs: some spendable, some not
    out1 = _mk_output(wid, 100, 0, maturity=0)   # Unspent
    out2 = _mk_output(wid, 200, 0, maturity=50)  # Unspent, matures at 50
    out3 = _mk_output(wid, 300, 1, maturity=0)   # Spent
    # Ensure unique commitments for uniqueness constraint
    out2['commitment_hex'] = 'ab' * 32
    out3['commitment_hex'] = 'ac' * 32
    st.save_output(out1)
    st.save_output(out2)
    st.save_output(out3)

    # All outputs for wallet
    outputs = st.get_outputs({'wallet_id': wid})
    assert len(outputs) == 3

    # Unspent only
    outputs_unspent = st.get_outputs({'wallet_id': wid, 'status': 0})
    assert {o['value'] for o in outputs_unspent} == {100, 200}

    # Value range filter
    outputs_range = st.get_outputs({'wallet_id': wid, 'min_value': 150, 'max_value': 250})
    assert len(outputs_range) == 1 and outputs_range[0]['value'] == 200

    # Pagination
    outputs_page = st.get_outputs({'wallet_id': wid, 'limit': 1, 'offset': 1})
    assert len(outputs_page) == 1

    # Spendable balance at height 0: only maturity <= 0 and unspent
    bal0 = st.get_spendable_balance(wid, 0)
    assert bal0 == 100

    # Spendable balance at height 100: both unspent become spendable
    bal100 = st.get_spendable_balance(wid, 100)
    assert bal100 == 100 + 200
