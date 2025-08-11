#!/usr/bin/env python3
import pytest

from lightweight_wallet_libpy import (
    TariWallet,
    TariAddressFeatures,
    Network,
)


def test_wallet_creation_and_seed_phrase_roundtrip():
    w = TariWallet.generate_new_with_seed_phrase(None)
    seed = w.seed_phrase()
    assert isinstance(seed, str) and len(seed.split()) in (12, 24)
    assert TariWallet.validate_seed_phrase(seed)

    w2 = TariWallet.from_seed_phrase(seed, None)
    assert isinstance(w2.seed_phrase(), str)


def test_wallet_metadata_and_properties():
    w = TariWallet.generate_new_with_seed_phrase(None)
    w.set_label("Core Wallet")
    w.set_network(Network.mainnet())
    w.set_birthday(12345)

    props = w.properties()
    assert props["network"] == "mainnet"
    assert props["birthday"] == 12345
    assert props["current_key_index"] == w.view_key_index()


def test_wallet_sign_and_verify_message_empty_message_allowed():
    w = TariWallet.generate_new_with_seed_phrase(None)

    msg = ""
    sig = w.sign_message(msg)
    assert sig.signature and sig.nonce and sig.public_key

    ok = TariWallet.verify_message_signature(msg, sig.signature, sig.nonce, sig.public_key)
    assert ok is True


def test_wallet_sign_and_verify_message_negative_case():
    w = TariWallet.generate_new_with_seed_phrase(None)

    msg = "hello tari"
    sig = w.sign_message(msg)

    # Tweak the signature to make it invalid
    bad_sig = sig.signature[:-2] + ("00" if sig.signature[-2:] != "00" else "ff")
    ok = TariWallet.verify_message_signature(msg, bad_sig, sig.nonce, sig.public_key)
    assert ok is False
