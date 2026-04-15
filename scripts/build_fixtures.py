#!/usr/bin/env python3
"""
Phase 1.5.2 — Golden fixture generator.

For each target mainnet RXD tx:
  1. Fetch tx hex + parse
  2. Fetch each input's prev-output data (scriptPubKey, amount)
  3. For each input, compute oracle's expected sighash
  4. Extract the published signature + pubkey from scriptSig
  5. Verify locally via ecdsa — if it passes, the fixture is known-good
  6. Record everything in scripts/fixtures/preimage-vectors.json

The fixture JSON is the input to Phase 1.5.4's compare harness. It
represents "the answer the device must produce" for each tx shape.

Running this script requires:
  - Trusted oracle (Phase 1.5.1 validated it)
  - Network access to a Radiant block explorer

Output: scripts/fixtures/preimage-vectors.json
"""

import json
import sys
import urllib.request
from pathlib import Path

import ecdsa
from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der

sys.path.insert(0, str(Path(__file__).parent))
from radiant_preimage_oracle import (
    Input,
    Output,
    Transaction,
    compute_radiant_sighash,
    parse_transaction,
)


def fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "radiant-ledger-oracle/0.1"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


# 4 target shapes, 4 mainnet txs:
VECTORS = [
    {
        "name": "sweep_1in_1out",
        "shape": "1-in / 1-out (sweep, no change)",
        "txid": "48bcbdef7ef09ec964420fa690de031f579193b5cc696fc13ecfafc8f10f2279",
    },
    {
        "name": "standard_1in_2out",
        "shape": "1-in / 2-out (with change) — our funding tx",
        "txid": "3521c21125f9bdf0039bec54946ca7c911f4d38c23aef1786a85e9d98f6a8556",
    },
    {
        "name": "multi_3in_2out",
        "shape": "3-in / 2-out (multi-input)",
        "txid": "266fdbec0e0a6229568ef5365de642cef58ec28771e95a4bbf1ef64f0225e1a6",
    },
    {
        "name": "consolidation_11in_1out",
        "shape": "11-in / 1-out (consolidation — per-output-hasher lifecycle stress)",
        "txid": "b4debc1567bfbdee6793577f093fbd0fb013988fd6b041e28c91ac2b3213bba0",
    },
]


def extract_sig_pubkey(script_sig: bytes) -> tuple[bytes, bytes, int] | None:
    """P2PKH scriptSig: <sig_len> <sig+hashtype> <pubkey_len> <pubkey>.
    Returns (sig_der, pubkey, hashtype_byte) or None if parse fails."""
    try:
        pos = 0
        sig_len = script_sig[pos]; pos += 1
        sig_with_ht = script_sig[pos:pos + sig_len]; pos += sig_len
        pk_len = script_sig[pos]; pos += 1
        pk = script_sig[pos:pos + pk_len]
        return sig_with_ht[:-1], pk, sig_with_ht[-1]
    except (IndexError, ValueError):
        return None


def build_vector(spec: dict) -> dict:
    """Build one complete fixture for a target tx."""
    print(f"\n== Building fixture: {spec['name']} ({spec['shape']}) ==")
    print(f"   txid: {spec['txid']}")

    tx_data = fetch(f"https://radiantexplorer.com/api/tx/{spec['txid']}")
    tx_hex = tx_data["hex"]
    tx_bytes = bytes.fromhex(tx_hex)
    signed_tx = parse_transaction(tx_bytes)

    # Build the "unsigned" variant (scriptSigs cleared) used for sighash
    unsigned_inputs = [
        Input(prev_txid=inp.prev_txid, prev_vout=inp.prev_vout, script_sig=b"", sequence=inp.sequence)
        for inp in signed_tx.inputs
    ]
    unsigned_tx = Transaction(
        version=signed_tx.version,
        inputs=unsigned_inputs,
        outputs=signed_tx.outputs,
        locktime=signed_tx.locktime,
    )

    # Compute the unsigned tx hex (outputs + inputs with empty scriptSigs)
    from radiant_preimage_oracle import i32_le, u32_le, u64_le, varint_encode
    unsigned_hex = bytes(i32_le(unsigned_tx.version))
    unsigned_hex += varint_encode(len(unsigned_tx.inputs))
    for inp in unsigned_tx.inputs:
        unsigned_hex += inp.prev_txid[::-1]
        unsigned_hex += u32_le(inp.prev_vout)
        unsigned_hex += b"\x00"  # empty scriptSig
        unsigned_hex += u32_le(inp.sequence)
    unsigned_hex += varint_encode(len(unsigned_tx.outputs))
    for out in unsigned_tx.outputs:
        unsigned_hex += u64_le(out.value)
        unsigned_hex += varint_encode(len(out.script_pubkey))
        unsigned_hex += out.script_pubkey
    unsigned_hex += u32_le(unsigned_tx.locktime)

    # Build per-input data
    inputs_data = []
    for i, inp in enumerate(signed_tx.inputs):
        vin_meta = tx_data["vin"][i]
        prev_txid = vin_meta["txid"]
        prev_vout = vin_meta["vout"]
        prev_value_rxd = float(vin_meta["value"])
        prev_value_sats = int(round(prev_value_rxd * 100_000_000))

        prev_tx = fetch(f"https://radiantexplorer.com/api/tx/{prev_txid}")
        prev_spk_hex = prev_tx["vout"][prev_vout]["scriptPubKey"]["hex"]
        prev_spk = bytes.fromhex(prev_spk_hex)

        # Oracle-computed sighash
        expected_sighash = compute_radiant_sighash(
            unsigned_tx, input_index=i,
            prev_output_script=prev_spk, prev_output_value=prev_value_sats,
        )

        # Extract published signature for verification check
        extracted = extract_sig_pubkey(inp.script_sig)
        if extracted is None:
            raise RuntimeError(f"input {i}: could not parse scriptSig")
        sig_der, pubkey, ht = extracted
        if ht != 0x41:
            raise RuntimeError(f"input {i}: unexpected hashtype 0x{ht:02x}")

        # Verify published sig against oracle sighash
        try:
            vk = VerifyingKey.from_string(pubkey, curve=SECP256k1)
            vk.verify_digest(sig_der, expected_sighash, sigdecode=sigdecode_der)
            print(f"   input {i}: oracle sighash {expected_sighash.hex()[:16]}… ✓ verifies published sig")
        except ecdsa.BadSignatureError:
            raise RuntimeError(f"input {i}: published signature does NOT verify against oracle sighash — fixture is invalid")

        inputs_data.append({
            "input_index": i,
            "prev_txid": prev_txid,
            "prev_vout": prev_vout,
            "prev_scriptpubkey_hex": prev_spk_hex,
            "prev_value_sats": prev_value_sats,
            "sequence": inp.sequence,
            "expected_sighash_hex": expected_sighash.hex(),
            "published_signature_der_hex": sig_der.hex(),
            "published_pubkey_hex": pubkey.hex(),
        })

    vector = {
        "name": spec["name"],
        "shape": spec["shape"],
        "txid": spec["txid"],
        "signed_tx_hex": tx_hex,
        "unsigned_tx_hex": unsigned_hex.hex(),
        "version": signed_tx.version,
        "locktime": signed_tx.locktime,
        "num_inputs": len(signed_tx.inputs),
        "num_outputs": len(signed_tx.outputs),
        "outputs": [
            {
                "value_sats": out.value,
                "script_hex": out.script_pubkey.hex(),
            }
            for out in signed_tx.outputs
        ],
        "inputs": inputs_data,
        "sighash_type": "0x41 (SIGHASH_ALL | SIGHASH_FORKID)",
    }
    print(f"   ✓ fixture built with {len(inputs_data)} input(s) all verified")
    return vector


def main():
    fixtures_dir = Path(__file__).parent / "fixtures"
    fixtures_dir.mkdir(exist_ok=True)

    vectors = []
    for spec in VECTORS:
        try:
            vectors.append(build_vector(spec))
        except Exception as e:
            print(f"   ✗ {spec['name']} FAILED: {e}", file=sys.stderr)
            raise

    output = {
        "phase": "1.5.2",
        "description": "Golden test vectors for Radiant Ledger app. Each fixture is a real confirmed mainnet RXD transaction whose published signatures have been verified against the oracle's computed sighash. The device must produce sighashes that match expected_sighash_hex for each input.",
        "generated_via": "scripts/build_fixtures.py",
        "oracle_source": "scripts/radiant_preimage_oracle.py (port of radiantjs sighash.js)",
        "num_vectors": len(vectors),
        "vectors": vectors,
    }

    out_path = fixtures_dir / "preimage-vectors.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n✓ Wrote {len(vectors)} fixtures to {out_path}")
    print(f"  Total size: {out_path.stat().st_size} bytes")


if __name__ == "__main__":
    main()
