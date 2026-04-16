#!/usr/bin/env python3
"""Scan recent Radiant mainnet blocks for a Glyph FT-shaped output.

An FT output is any scriptPubKey whose first byte is OP_PUSHINPUTREF (0xd0) —
the non-singleton ref-push opcode. Compare against NFT outputs, which use
OP_PUSHINPUTREFSINGLETON (0xd8).

Goal: find ONE real FT UTXO on mainnet, dump its raw scriptPubKey bytes, and
do a best-effort parse so we can nail down the exact wrapper shape before
teaching Electron-Wallet's script classifier about FTs.

Uses ssh to the VPS radiant-mainnet container — no wallet access, read-only RPC.

Usage:
  python3 find_ft_utxo.py                  # scan last 50 blocks
  python3 find_ft_utxo.py --back 200       # scan further back
  python3 find_ft_utxo.py --tx <txid>      # inspect a specific tx instead
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

VPS_HOST = os.environ.get("VPS", "user@your-vps-ip")
RADIANT_CLI = "docker exec radiant-mainnet radiant-cli -datadir=/home/radiant/.radiant"


def rpc(*args):
    """Call radiant-cli on the VPS via ssh, return stdout as string."""
    cli_cmd = RADIANT_CLI + " " + " ".join(str(a) for a in args)
    out = subprocess.check_output(
        ["ssh", VPS_HOST, cli_cmd], timeout=120, stderr=subprocess.PIPE
    )
    return out.decode().strip()


def rpc_json(*args):
    return json.loads(rpc(*args))


def pkh_to_addr(pkh_hex):
    """Encode a 20-byte pubkey hash as a Radiant/Bitcoin P2PKH address."""
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    payload = bytes([0x00]) + bytes.fromhex(pkh_hex)
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + chk
    n = int.from_bytes(data, "big")
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = alpha[r] + s
    lead = 0
    for b in data:
        if b == 0:
            lead += 1
        else:
            break
    return "1" * lead + s


def classify_shape(spk_hex):
    """Categorize where d0/d8 appear relative to the P2PKH tail, if any."""
    if "d0" not in spk_hex and "d8" not in spk_hex:
        return "no-glyph-opcode"
    # Try to locate standard P2PKH pattern 76a914 <40hex> 88ac
    import re

    p2pkh = re.search(r"76a914[0-9a-f]{40}88ac", spk_hex)
    leads_d8 = spk_hex.startswith("d8")
    leads_d0 = spk_hex.startswith("d0")
    has_d0 = "d0" in spk_hex
    has_d8 = "d8" in spk_hex
    if leads_d8 and p2pkh and p2pkh.start() == 2 + 72 + 2:
        return "nft-prefix (d8 ref OP_DROP P2PKH) — classic 63B singleton wrapper"
    if leads_d0 and p2pkh and p2pkh.start() == 2 + 72 + 2:
        return "ft-prefix (d0 ref OP_DROP P2PKH) — FT analog of NFT wrapper"
    if p2pkh and has_d0 and spk_hex.index("d0") > p2pkh.end():
        return "p2pkh-then-glyph-suffix (P2PKH tail followed by d0/refs)"
    if p2pkh and (has_d0 or has_d8) and spk_hex.index("d0" if has_d0 else "d8") < p2pkh.start():
        return "glyph-prefix-nonstandard (glyph opcodes before P2PKH but not classic wrapper)"
    if not p2pkh and (has_d0 or has_d8):
        return "glyph-only (no P2PKH tail — custom/commit script)"
    return "other"


def parse_ft_script(spk_hex):
    """Structural decode with shape classification."""
    info = {"total_bytes": len(spk_hex) // 2, "shape": classify_shape(spk_hex)}
    import re

    m = re.search(r"76a914([0-9a-f]{40})88ac", spk_hex)
    if m:
        info["p2pkh_hash160"] = m.group(1)
        info["p2pkh_address"] = pkh_to_addr(m.group(1))
        info["p2pkh_offset_bytes"] = m.start() // 2
    # collect all d0 / d8 opcode positions and the 36 bytes that follow each
    for opcode, name in (("d0", "OP_PUSHINPUTREF"), ("d8", "OP_PUSHINPUTREFSINGLETON")):
        positions = []
        i = 0
        while True:
            j = spk_hex.find(opcode, i)
            if j == -1 or j % 2 != 0:
                if j == -1:
                    break
                i = j + 1
                continue
            if j + 2 + 72 <= len(spk_hex):
                positions.append({"byte_offset": j // 2, "ref_hex": spk_hex[j + 2 : j + 2 + 72]})
            i = j + 2
        if positions:
            info[f"{name}_occurrences"] = positions
    return info


def report_output(height, txid, vout_n, value, spk_hex):
    info = parse_ft_script(spk_hex) or {}
    print(f"Block:    {height}")
    print(f"TXID:     {txid}")
    print(f"Vout:     {vout_n}")
    print(f"Value:    {value} RXD")
    print(f"Script  ({info.get('total_bytes', '?')} bytes):")
    print(f"  {spk_hex}")
    print("Structure:")
    for k, v in info.items():
        print(f"  {k}: {v}")


def scan_tx(txid):
    tx = rpc_json("getrawtransaction", txid, 1)
    height = tx.get("blockheight", "mempool?")
    found = False
    for vout in tx["vout"]:
        spk = vout["scriptPubKey"]["hex"]
        if "d0" in spk or "d8" in spk:
            report_output(height, txid, vout["n"], vout["value"], spk)
            print()
            found = True
    if not found:
        print(f"No glyph-opcode outputs in {txid}")


def ft_template_bytes(spk_hex):
    """For a 75-byte p2pkh-then-glyph-suffix output, strip the pkh and ref and
    return the fixed-template bytes (everything structural, no per-UTXO data).
    Returns (prefix_before_pkh, pkh_hex, between_pkh_and_ref, ref_hex, suffix_after_ref)."""
    # shape: 76a914 <40> 88ac bd d0 <72> <tail>
    return (
        spk_hex[0:6],              # 76a914
        spk_hex[6:46],             # 20B pkh
        spk_hex[46:54],             # 88ac bd d0
        spk_hex[54:126],           # 36B ref
        spk_hex[126:],             # tail opcodes
    )


def scan_recent(back):
    """Scan N blocks back, count outputs by shape, group FT-holder UTXOs by ref."""
    tip = int(rpc("getblockcount"))
    print(f"Tip block: {tip}. Scanning {back} blocks backward...", file=sys.stderr)
    shape_counts = {}
    shape_examples = {}
    ft_ref_counts = {}               # ref_hex -> count
    ft_ref_example = {}              # ref_hex -> (h, txid, n, val, spk)
    ft_prefix_variants = {}          # `76a914` prefix variants seen
    ft_middle_variants = {}          # `88ac bd d0` middle variants seen
    ft_suffix_variants = {}          # post-ref tail variants seen
    ft_length_variants = {}          # total byte lengths seen for FT-shaped
    scanned = 0
    for h in range(tip, tip - back, -1):
        bhash = rpc("getblockhash", h)
        try:
            blk = rpc_json("getblock", bhash, 2)
        except Exception as e:
            print(f"  block {h} skip ({e})", file=sys.stderr)
            continue
        scanned += 1
        for tx in blk["tx"]:
            for vout in tx["vout"]:
                spk = vout["scriptPubKey"]["hex"]
                if "d0" not in spk and "d8" not in spk:
                    continue
                shape = classify_shape(spk)
                shape_counts[shape] = shape_counts.get(shape, 0) + 1
                if shape not in shape_examples:
                    shape_examples[shape] = (h, tx["txid"], vout["n"], vout["value"], spk)
                if shape.startswith("p2pkh-then-glyph-suffix"):
                    ft_length_variants[len(spk) // 2] = ft_length_variants.get(len(spk) // 2, 0) + 1
                    if len(spk) == 150:  # 75 bytes
                        pre, pkh, mid, ref, tail = ft_template_bytes(spk)
                        ft_prefix_variants[pre] = ft_prefix_variants.get(pre, 0) + 1
                        ft_middle_variants[mid] = ft_middle_variants.get(mid, 0) + 1
                        ft_suffix_variants[tail] = ft_suffix_variants.get(tail, 0) + 1
                        ft_ref_counts[ref] = ft_ref_counts.get(ref, 0) + 1
                        if ref not in ft_ref_example:
                            ft_ref_example[ref] = (h, tx["txid"], vout["n"], vout["value"], spk)
        if scanned % 20 == 0:
            print(f"  scanned {scanned}/{back}  shapes: {dict(shape_counts)}  ft_refs: {len(ft_ref_counts)}",
                  file=sys.stderr)
    print(f"\n=== Summary over {scanned} blocks (tip {tip} back to {tip - back + 1}) ===")
    for shape, count in sorted(shape_counts.items(), key=lambda x: -x[1]):
        print(f"  {count:5d}  {shape}")
    print("\n=== FT-holder template invariance (75-byte p2pkh-then-glyph-suffix) ===")
    print(f"Length distribution (bytes): {ft_length_variants}")
    print(f"Unique prefix variants (expect 1, '76a914'): {len(ft_prefix_variants)}")
    for v, c in sorted(ft_prefix_variants.items(), key=lambda x: -x[1])[:5]:
        print(f"    {c:5d}  {v}")
    print(f"Unique middle variants (expect 1, '88acbdd0'): {len(ft_middle_variants)}")
    for v, c in sorted(ft_middle_variants.items(), key=lambda x: -x[1])[:5]:
        print(f"    {c:5d}  {v}")
    print(f"Unique suffix variants (expect small, fixed tail opcodes): {len(ft_suffix_variants)}")
    for v, c in sorted(ft_suffix_variants.items(), key=lambda x: -x[1])[:5]:
        print(f"    {c:5d}  {v}")
    print(f"\nUnique refs (FT tokens) seen: {len(ft_ref_counts)}")
    for ref, count in sorted(ft_ref_counts.items(), key=lambda x: -x[1])[:10]:
        h, txid, n, val, spk = ft_ref_example[ref]
        print(f"  {count:5d}  ref {ref}")
        print(f"         example: block {h} tx {txid} vout {n}")
    print("\n=== One example per shape ===")
    for shape, (h, txid, n, val, spk) in shape_examples.items():
        print(f"\n--- shape: {shape} ---")
        report_output(h, txid, n, val, spk)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--back", type=int, default=50, help="blocks back from tip to scan")
    ap.add_argument("--tx", help="inspect a specific txid instead of scanning")
    args = ap.parse_args()
    if args.tx:
        scan_tx(args.tx)
    else:
        scan_recent(args.back)


if __name__ == "__main__":
    main()
