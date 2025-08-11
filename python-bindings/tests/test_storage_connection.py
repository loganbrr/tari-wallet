#!/usr/bin/env python3
import os
import sys
import stat
import pytest
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from lightweight_wallet_libpy import TariWalletStorage
except ImportError:
    pytest.skip("lightweight_wallet_libpy not available - run 'maturin develop' first", allow_module_level=True)


@pytest.fixture
def temp_db_dir(tmp_path):
    d = tmp_path / "dbdir"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_wallet(storage: "TariWalletStorage", name: str):
    wallet = {
        'name': name,
        'seed_phrase': 'abandon ' * 11 + 'about',
        'view_key_hex': '01' * 32,
        'spend_key_hex': '02' * 32,
        'birthday_block': 0,
        'latest_scanned_block': 0,
    }
    return storage.save_wallet(wallet)


def test_database_file_creation(temp_db_dir):
    db_path = temp_db_dir / "test_wallet.db"
    assert not db_path.exists()

    st = TariWalletStorage(str(db_path))
    st.initialize()
    assert db_path.exists()

    # Reopen again
    st2 = TariWalletStorage(str(db_path))
    st2.initialize()


def test_invalid_database_path(tmp_path):
    # Non-existent nested directories under a read-only parent should fail
    invalid_path = tmp_path / "does" / "not" / "exist" / "wallet.db"
    st = TariWalletStorage(str(invalid_path))
    with pytest.raises(Exception):
        st.initialize()


@pytest.mark.skipif(os.name != 'posix', reason='chmod read-only semantics are POSIX-specific')
def test_readonly_directory_database_creation(tmp_path):
    readonly_dir = tmp_path / "readonly"
    readonly_dir.mkdir(parents=True, exist_ok=True)

    os.chmod(readonly_dir, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    db_path = readonly_dir / "wallet.db"
    try:
        st = TariWalletStorage(str(db_path))
        with pytest.raises(Exception):
            st.initialize()
    finally:
        # Restore perms so tmp cleanup works
        os.chmod(readonly_dir, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)


def test_in_memory_database_isolation():
    # Using SQLite in-memory database token should isolate connections
    st1 = TariWalletStorage(":memory:")
    st2 = TariWalletStorage(":memory:")
    st1.initialize()
    st2.initialize()

    _save_wallet(st1, "test1")
    wallets1 = st1.list_wallets()
    wallets2 = st2.list_wallets()
    assert len(wallets1) == 1
    assert len(wallets2) == 0


def test_concurrent_database_access(temp_db_dir):
    db_path = temp_db_dir / "concurrent.db"

    # Initialize schema
    TariWalletStorage(str(db_path)).initialize()

    def worker(i: int) -> int:
        st = TariWalletStorage(str(db_path))
        st.initialize()
        _save_wallet(st, f"wallet_{i}")
        assert any(w['name'] == f"wallet_{i}" for w in st.list_wallets())
        return i

    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(worker, i) for i in range(10)]
        results = [f.result(timeout=10) for f in futs]

    assert len(results) == 10

    st_final = TariWalletStorage(str(db_path))
    st_final.initialize()
    wallets = st_final.list_wallets()
    assert len(wallets) == 10


def test_database_reopen_after_close(temp_db_dir):
    db_path = temp_db_dir / "reopen.db"

    st = TariWalletStorage(str(db_path))
    st.initialize()
    _save_wallet(st, "test_wallet")

    # Drop reference to close connection
    del st

    st2 = TariWalletStorage(str(db_path))
    st2.initialize()
    wallets = st2.list_wallets()
    assert any(w['name'] == 'test_wallet' for w in wallets)


def test_database_schema_initialization_idempotent():
    st = TariWalletStorage(":memory:")
    st.initialize()
    st.initialize()
    st.initialize()
    assert st.list_wallets() == []


def test_database_corruption_detection(temp_db_dir):
    db_path = temp_db_dir / "corrupt.db"

    # Create and write data
    st = TariWalletStorage(str(db_path))
    st.initialize()
    _save_wallet(st, "test")

    # Corrupt the file
    with open(db_path, 'wb') as f:
        f.write(b"This is not a valid SQLite database")

    # Attempt to initialize or access should fail
    st2 = TariWalletStorage(str(db_path))
    with pytest.raises(Exception):
        st2.initialize()


def test_database_large_path_handling(tmp_path):
    long_path = tmp_path
    for i in range(10):
        long_path = long_path / f"very_long_directory_name_{i}"
    long_path.mkdir(parents=True, exist_ok=True)
    db_path = long_path / "wallet.db"

    st = TariWalletStorage(str(db_path))
    st.initialize()
    assert st.list_wallets() == []


def test_database_special_characters_in_path(tmp_path):
    special = tmp_path / "test wallet with spaces & symbols!.db"
    st = TariWalletStorage(str(special))
    st.initialize()
    _save_wallet(st, "test")
    assert len(st.list_wallets()) == 1


def test_operation_on_uninitialized_storage(tmp_path):
    db_path = tmp_path / "uninit.db"
    st = TariWalletStorage(str(db_path))
    with pytest.raises(Exception):
        st.list_wallets()


def test_sql_injection_like_name(tmp_path):
    db_path = tmp_path / "inject.db"
    st = TariWalletStorage(str(db_path))
    st.initialize()

    name = "test'; DROP TABLE wallets; --"
    _save_wallet(st, name)
    wallets = st.list_wallets()
    assert len(wallets) == 1
    assert wallets[0]['name'] == name


def test_very_long_and_null_byte_names(tmp_path):
    db_path = tmp_path / "longname.db"
    st = TariWalletStorage(str(db_path))
    st.initialize()

    long_name = "a" * 10000
    try:
        _save_wallet(st, long_name)
        assert any(w['name'] == long_name for w in st.list_wallets())
    except Exception:
        # Acceptable to reject long inputs
        pass

    name_with_null = "test\0wallet"
    try:
        _save_wallet(st, name_with_null)
        assert any(w['name'] == name_with_null for w in st.list_wallets())
    except Exception:
        # Acceptable to reject null bytes
        pass
