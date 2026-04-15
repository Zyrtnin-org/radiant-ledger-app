#!/usr/bin/env python3
"""
Radiant (RXD) signature preimage oracle.

Port of radiantjs/lib/transaction/sighash.js:91-128 (GetHashOutputHashes)
and 171-237 (sighashPreimageForForkId) to Python.

Purpose: compute the expected sighash for a Radiant transaction input,
so we can verify our Ledger Radiant app produces signatures that match.

Authoritative sources (all verified in Phase 1.5.0 against the live repos):
    https://github.com/RadiantBlockchain/radiantjs/blob/master/lib/transaction/sighash.js
    https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/interpreter.cpp
    https://github.com/RadiantBlockchain/radiant-node/blob/master/src/primitives/transaction.h

Preimage structure (Radiant, SIGHASH_ALL|FORKID only — v1 scope):

    version                           int32  LE   (4 bytes)
    hashPrevouts                      sha256d    (32 bytes)
    hashSequence                      sha256d    (32 bytes)
    prev_tx_id (reversed)             bytes      (32 bytes)
    prev_output_index                 uint32 LE  (4 bytes)
    scriptCode length                 varint
    scriptCode                        bytes
    input_satoshis                    uint64 LE  (8 bytes)
    input_sequence                    uint32 LE  (4 bytes)
    hashOutputHashes                  sha256d    (32 bytes) ← Radiant's addition
    hashOutputs                       sha256d    (32 bytes)
    nLockTime                         uint32 LE  (4 bytes)
    sighashType                       uint32 LE  (4 bytes)

hashOutputHashes is sha256d of concatenated per-output summaries. Per-output:

    nValue                            uint64 LE  (8 bytes)
    sha256d(scriptPubKey)             bytes      (32 bytes)
    totalRefs                         uint32 LE  (4 bytes)  ← for v1 P2PKH always 0
    refsHash                          bytes      (32 bytes) ← for v1 P2PKH always 0x00...00

Version handling: no branching on tx version 1 vs 2 (per Phase 1.5.0 Check 2).
tx.version is emitted directly.
"""

import hashlib
import struct
from typing import NamedTuple

ZERO_32 = bytes(32)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    """Double-SHA256. Bitcoin family convention (CHashWriter in C++; Hash.sha256sha256 in JS)."""
    return sha256(sha256(data))


def u32_le(n: int) -> bytes:
    return struct.pack("<I", n & 0xFFFFFFFF)


def i32_le(n: int) -> bytes:
    return struct.pack("<i", n)


def u64_le(n: int) -> bytes:
    return struct.pack("<Q", n)


def varint_encode(n: int) -> bytes:
    """Bitcoin-style varint encoding."""
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


class Output(NamedTuple):
    value: int  # satoshis
    script_pubkey: bytes


class Input(NamedTuple):
    prev_txid: bytes  # 32 bytes, internal byte order (NOT reversed)
    prev_vout: int
    script_sig: bytes  # ignored for preimage; scriptCode is passed separately per-input
    sequence: int


class Transaction(NamedTuple):
    version: int
    inputs: list
    outputs: list
    locktime: int


# ----- Helper hashers ----- #

def get_prevout_hash(tx: Transaction) -> bytes:
    """Double-SHA256 of all inputs' (prev_txid_reversed || vout_LE)."""
    w = b""
    for inp in tx.inputs:
        # radiantjs writeReverse(prevTxId): the JS library stores txids in display order,
        # serializes reversed. Callers should pass prev_txid in INTERNAL byte order
        # (natural hash output from sha256d). Reversal happens here.
        w += inp.prev_txid[::-1]
        w += u32_le(inp.prev_vout)
    return sha256d(w)


def get_sequence_hash(tx: Transaction) -> bytes:
    w = b"".join(u32_le(inp.sequence) for inp in tx.inputs)
    return sha256d(w)


def get_outputs_hash(tx: Transaction, single_index: int | None = None) -> bytes:
    """Double-SHA256 of serialized outputs (value || varint(script_len) || script)."""
    if single_index is not None:
        outs = [tx.outputs[single_index]]
    else:
        outs = tx.outputs
    w = b""
    for out in outs:
        w += u64_le(out.value)
        w += varint_encode(len(out.script_pubkey))
        w += out.script_pubkey
    return sha256d(w)


def per_output_summary(out: Output) -> bytes:
    """76-byte per-output summary for hashOutputHashes. v1: totalRefs=0, refsHash=zeros.

    For a future v2 that handles push-refs, extend this to scan the script
    for OP_PUSHINPUTREF family opcodes, deduplicate, sort, concat, sha256d.
    """
    # Phase 1.5.0 Check 3 verified this exact order:
    # 8B nValue | 32B sha256d(scriptPubKey) | 4B totalRefs LE | 32B refsHash
    script_hash = sha256d(out.script_pubkey)
    total_refs = 0  # v1 scope: plain P2PKH only; caller ensures canonical P2PKH
    refs_hash = ZERO_32
    return u64_le(out.value) + script_hash + u32_le(total_refs) + refs_hash


def get_hash_output_hashes(tx: Transaction, single_index: int | None = None) -> bytes:
    """Per-output summaries concatenated, then sha256d."""
    if single_index is not None:
        outs = [tx.outputs[single_index]]
    else:
        outs = tx.outputs
    w = b"".join(per_output_summary(out) for out in outs)
    return sha256d(w)


# ----- Main entry point ----- #

def compute_radiant_sighash(
    tx: Transaction,
    input_index: int,
    prev_output_script: bytes,
    prev_output_value: int,
    sighash_type: int = 0x41,  # SIGHASH_ALL | SIGHASH_FORKID
) -> bytes:
    """Returns the 32-byte sighash for signing input_index of tx.

    sighash_type = 0x41 is the only value supported in v1 (matches device gate).
    Radiant's SINGLE/NONE/ANYONECANPAY variants have different preimage rules;
    we reject them here to mirror the device's strict policy and prevent
    accidentally computing a hash the device can't produce.
    """
    if sighash_type != 0x41:
        raise ValueError(f"v1 scope supports only sighash_type=0x41, got 0x{sighash_type:02x}")
    if input_index < 0 or input_index >= len(tx.inputs):
        raise ValueError(f"input_index {input_index} out of range (tx has {len(tx.inputs)} inputs)")
    if prev_output_value < 0:
        raise ValueError("prev_output_value must be non-negative")

    inp = tx.inputs[input_index]
    hash_prevouts = get_prevout_hash(tx)
    hash_sequence = get_sequence_hash(tx)
    hash_outputs = get_outputs_hash(tx)
    hash_output_hashes = get_hash_output_hashes(tx)

    preimage = (
        i32_le(tx.version)
        + hash_prevouts
        + hash_sequence
        + inp.prev_txid[::-1]  # prev_tx_id reversed (display-order serialization)
        + u32_le(inp.prev_vout)
        + varint_encode(len(prev_output_script))
        + prev_output_script
        + u64_le(prev_output_value)
        + u32_le(inp.sequence)
        + hash_output_hashes  # <-- Radiant's addition
        + hash_outputs
        + u32_le(tx.locktime)
        + u32_le(sighash_type)
    )

    return sha256d(preimage)


# ----- Tx parsing helpers (for test-vector loading) ----- #

def parse_varint(buf: bytes, offset: int) -> tuple[int, int]:
    """Return (value, new_offset)."""
    first = buf[offset]
    if first < 0xFD:
        return first, offset + 1
    if first == 0xFD:
        return struct.unpack_from("<H", buf, offset + 1)[0], offset + 3
    if first == 0xFE:
        return struct.unpack_from("<I", buf, offset + 1)[0], offset + 5
    return struct.unpack_from("<Q", buf, offset + 1)[0], offset + 9


def parse_transaction(raw: bytes) -> Transaction:
    """Parse a raw tx (Bitcoin-family wire format) into a Transaction.

    Radiant's on-wire tx format is byte-identical to BCH (verified in
    Phase 0 research). Version | vin | vout | locktime.
    """
    pos = 0
    version = struct.unpack_from("<i", raw, pos)[0]; pos += 4
    vin_count, pos = parse_varint(raw, pos)
    inputs = []
    for _ in range(vin_count):
        prev_txid = raw[pos:pos + 32][::-1]; pos += 32  # reverse to internal byte order
        prev_vout = struct.unpack_from("<I", raw, pos)[0]; pos += 4
        script_len, pos = parse_varint(raw, pos)
        script_sig = raw[pos:pos + script_len]; pos += script_len
        sequence = struct.unpack_from("<I", raw, pos)[0]; pos += 4
        inputs.append(Input(prev_txid, prev_vout, script_sig, sequence))
    vout_count, pos = parse_varint(raw, pos)
    outputs = []
    for _ in range(vout_count):
        value = struct.unpack_from("<Q", raw, pos)[0]; pos += 8
        script_len, pos = parse_varint(raw, pos)
        script_pubkey = raw[pos:pos + script_len]; pos += script_len
        outputs.append(Output(value, script_pubkey))
    locktime = struct.unpack_from("<I", raw, pos)[0]; pos += 4
    assert pos == len(raw), f"tx parsing left {len(raw) - pos} trailing bytes"
    return Transaction(version, inputs, outputs, locktime)


# ----- Doctests ----- #

def _selftest():
    """Basic sanity: encoding helpers round-trip."""
    assert u32_le(0) == b"\x00\x00\x00\x00"
    assert u32_le(1) == b"\x01\x00\x00\x00"
    assert u64_le(0) == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert u64_le(100_000_000) == b"\x00\xe1\xf5\x05\x00\x00\x00\x00"  # 1 RXD in sats
    assert varint_encode(0) == b"\x00"
    assert varint_encode(252) == b"\xfc"
    assert varint_encode(253) == b"\xfd\xfd\x00"
    assert varint_encode(65535) == b"\xfd\xff\xff"
    assert varint_encode(65536) == b"\xfe\x00\x00\x01\x00"
    assert sha256(b"") == bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert sha256d(b"") == bytes.fromhex("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
    print("[_selftest] encoding + hash helpers OK")


if __name__ == "__main__":
    _selftest()
    print("\nradiant_preimage_oracle.py: module loaded. Run tests via scripts/oracle_self_validate.py")
