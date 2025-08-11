#!/usr/bin/env python3
import pytest

from lightweight_wallet_libpy import (
    ExecutionStack,
    TransactionInput,
    TransactionKernel,
    Block,
    BlockSummary,
    TransactionOutput,
    OutputFeatures,
    OutputType,
    Script,
    CompressedPublicKey,
    Signature,
    Covenant,
    EncryptedData,
    MicroMinotari,
    CompressedCommitment,
)


def make_output(value: int) -> TransactionOutput:
    features = OutputFeatures.payment(0)
    commitment = CompressedCommitment.from_bytes(bytes([1] * 32))
    proof = None
    script = Script.empty()
    sender_pk = CompressedPublicKey.from_bytes(bytes([2] * 32))
    metadata_sig = Signature.from_bytes(bytes([3] * 64))
    covenant = Covenant.empty()
    enc = EncryptedData.empty()
    mvp = MicroMinotari(value)
    return TransactionOutput.new_current_version(
        features,
        commitment,
        proof,
        script,
        sender_pk,
        metadata_sig,
        covenant,
        enc,
        mvp,
    )


def test_execution_stack_basic():
    st = ExecutionStack()
    assert st.len() == 0
    st.push(b"abc")
    st.push(b"def")
    assert st.len() == 2
    assert not st.is_empty()
    items = st.items()
    assert items[0] == b"abc"
    assert items[1] == b"def"


def test_transaction_input_roundtrip():
    sender_pk = CompressedPublicKey.from_bytes(bytes([9] * 32))
    stack = ExecutionStack()
    stack.push(b"arg1")
    stack.push(b"arg2")
    cov = Covenant.from_bytes(b"")

    ti = TransactionInput(
        1,
        0,
        "11" * 32,
        "22" * 32,
        sender_pk,
        cov,
        stack,
        "3f" * 128,
        0,
        "44" * 32,
        10,
        MicroMinotari(1234),
    )
    assert ti.version == 1
    assert ti.features == 0
    assert ti.maturity() == 10
    assert ti.value().inner() == 1234
    ti.validate_lengths()


def test_transaction_kernel_hex_roundtrip():
    excess = CompressedPublicKey.from_bytes(bytes([7] * 32))
    k = TransactionKernel(
        1,
        0,
        MicroMinotari(999),
        0,
        excess,
        "aa" * 64,
        0,
        None,
    )
    hx = k.to_hex()
    k2 = TransactionKernel.from_hex(hx)
    assert isinstance(hx, str)
    assert "aa" in hx or len(hx) > 0
    assert k2.to_hex() == hx


def test_block_and_summary():
    outs = [make_output(1000), make_output(2000)]
    sender_pk = CompressedPublicKey.from_bytes(bytes([9] * 32))
    stack = ExecutionStack()
    cov = Covenant.from_bytes(b"")
    ti = TransactionInput(
        1, 0, "11" * 32, "22" * 32, sender_pk, cov, stack, "3f" * 128, 0, "44" * 32, 0, MicroMinotari(0)
    )

    blk = Block(123, "ab" * 32, 999999, outs, [ti])
    assert blk.output_count() == 2
    assert blk.input_count() == 1
    summary = blk.summary()
    assert isinstance(summary, BlockSummary)
    assert summary.height() == 123
    assert summary.input_count() == 1
    assert summary.output_count() == 2
    assert len(summary.hash_hex()) == 64


def test_transaction_input_invalid_lengths():
    sender_pk = CompressedPublicKey.from_bytes(bytes([9] * 32))
    stack = ExecutionStack()
    cov = Covenant.from_bytes(b"")

    # commitment hex wrong length
    with pytest.raises(ValueError):
        TransactionInput(1, 0, "11" * 31, "22" * 32, sender_pk, cov, stack, "33" * 32, 0, "44" * 32, 0, MicroMinotari(0))

    # output_hash hex wrong length
    with pytest.raises(ValueError):
        TransactionInput(1, 0, "11" * 32, "22" * 31, sender_pk, cov, stack, "33" * 32, 0, "44" * 32, 0, MicroMinotari(0))

    # script_sig hex wrong length
    with pytest.raises(ValueError):
        TransactionInput(1, 0, "11" * 32, "22" * 32, sender_pk, cov, stack, "33" * 31, 0, "44" * 32, 0, MicroMinotari(0))

    # metadata_sig hex wrong length
    with pytest.raises(ValueError):
        TransactionInput(1, 0, "11" * 32, "22" * 32, sender_pk, cov, stack, "33" * 32, 0, "44" * 31, 0, MicroMinotari(0))


def test_execution_stack_roundtrip_order():
    st = ExecutionStack()
    data = [b"one", b"two", b"three"]
    for d in data:
        st.push(d)
    assert st.items() == data


def test_transaction_output_roundtrip():
    out = make_output(12345)
    hx = out.to_hex()
    out2 = TransactionOutput.from_hex(hx)
    assert out2.to_hex() == hx
