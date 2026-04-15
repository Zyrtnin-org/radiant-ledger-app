---
title: Radiant signature preimage missing hashOutputHashes field causes "Invalid status 6702" on broadcast
date: 2026-04-15
problem_type: integration-issue
component: ledger-app-radiant-signing-path
symptoms:
  - "Electron Radiant wallet error: Invalid status 6702"
  - "Node rejection: script execution error"
  - "Transaction signs on Ledger device but fails broadcast"
  - "Signature valid under BCH sighash rules but invalid under Radiant consensus"
tags:
  - ledger-hardware-wallet
  - radiant-rxd
  - sighash-preimage
  - hashOutputHashes
  - bitcoin-cash-fork
  - slip44-512
  - p2pkh-signing
  - consensus-rejection
severity: critical
time_to_fix: 2-3 days
---

# Radiant signature preimage missing `hashOutputHashes` field

**Quick answer**: If you fork LedgerHQ/app-bitcoin's `bitcoin_cash` variant for Radiant (RXD), signatures will look valid to the device but mainnet will reject them. Radiant's signature preimage contains an 11th field (`hashOutputHashes`, 32 bytes) between `nSequence` and `hashOutputs` that BCH's BIP143 preimage doesn't produce. You must compute and insert it on-device. This field is present in **every** Radiant transaction, even plain P2PKH.

## Problem

### Symptoms

- Host-side wallet (e.g. Electron Radiant with patched plugin) reports `Exception : Invalid status 6702` during signing, or a similar transport-level error.
- Device successfully signs (no on-device rejection), but broadcast fails with `script execution error` from the Radiant node.
- `blockchain.transaction.broadcast` over Electrum returns the same rejection.

### When it hits you

You forked LedgerHQ/app-bitcoin, added a `radiant` Makefile variant with `COIN_KIND_RADIANT` + `COIN_FORKID=0` + `BIP44_COIN_TYPE=512`, reused the `bitcoin_cash` signing path (because the SIGHASH type byte is the same `0x41`, same fork-id value), and tried to sign a plain P2PKH spend. Address derivation works. Path-lock works. The device happily signs. Mainnet rejects.

## Root cause

Radiant inherited BCH's `SIGHASH_ALL|FORKID = 0x41` wire format but added an extra 32-byte field to the preimage. The canonical source is [`radiant-node/src/script/interpreter.cpp:2636-2650`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/interpreter.cpp#L2636):

```
BCH (BIP143):    nVersion | hashPrevouts | hashSequence | prevout | scriptCode |
                 amount | nSequence | hashOutputs | nLockTime | sigHashType

Radiant:         nVersion | hashPrevouts | hashSequence | prevout | scriptCode |
                 amount | nSequence | hashOutputHashes | hashOutputs | nLockTime | sigHashType
                                     ^^^^^^^^^^^^^^^^ new 32-byte field
```

`hashOutputHashes = sha256d(concat(per_output_summary))` where each summary is **76 bytes**:

| Field | Width | Notes |
|---|---|---|
| `nValue` | u64 LE (8 B) | Amount in satoshis |
| `sha256d(scriptPubKey)` | 32 B | Double-SHA256 of the locking script |
| `totalRefs` | u32 LE (4 B) | `0` for plain P2PKH (NOT a varint) |
| `refsHash` | 32 B | Zero bytes for no-ref outputs; otherwise sha256d of sorted push-refs |

For Glyph-bearing outputs (`OP_PUSHINPUTREF*` opcodes), `totalRefs` and `refsHash` carry real values. For plain P2PKH (v1 scope), both are zero — but the **summary is still emitted** for every output.

Misleading clue trail:
- Same SIGHASH byte as BCH (`0x41`)
- Same `COIN_FORKID=0`
- Same wire tx format
- ECDSA verification path identical
- ⇒ easy to assume byte-identical sighash; it isn't

## Investigation arc (what was tried, what didn't work, what did)

- **First assumption (WRONG)**: Radiant sighash ≡ BCH byte-for-byte because both use SIGHASH byte `0x41` and fork-id=0. Initial Phase 1 C diff (~58 lines) shipped assuming a stock BCH preimage would validate.
- **Hardware test**: Device signed a 1-in/2-out P2PKH spend; broadcast rejected. Iterating on Electron Radiant eventually surfaced `0x6702` at the transport layer.
- **Diagnosis path**: Read `radiant-node/src/script/interpreter.cpp:2636-2650` → found the 11th field → cross-verified against [`radiantjs/lib/transaction/sighash.js:91-237`](https://github.com/RadiantBlockchain/radiantjs/blob/master/lib/transaction/sighash.js#L91) (two independent sources agreed).
- **Oracle built first**: Python port of radiantjs, triple-validated before any further device work (see Prevention).
- **Strategy choice**: Strategy A (device computes `hashOutputHashes` independently) beats Strategy B (host supplies it). B introduces a host-commitment channel that defeats the point of hardware signing.
- **Mid-implementation bug**: First byte-feeder placement was *after* the switch in `handle_output_state` — which fired for both the `OUTPUT_PARSING_NUMBER_OUTPUTS` case (1–3 vout-count-varint bytes) AND `OUTPUT_PARSING_OUTPUT`. Varint bytes got fed as "nValue," corrupting all subsequent hashing. Fix: move feeder **inside** the `OUTPUT_PARSING_OUTPUT` case. Prominent comment added to prevent regression.

## Working solution (code-level)

Landed as ~299 lines across 6 files in `Zyrtnin-org/lib-app-bitcoin@radiant-v1` (commit `82a5492`). RAM cost: `.bss.context` grew 968 B → 1200 B (+232 B, ~24%, well within Nano S Plus budget).

### 1. `context.h` — new state fields

```c
// Added to segwit_cache_s:
unsigned char hashedOutputHashes[32];

// Added to struct context_s:
cx_sha256_t hashOutputHashesCtx;        // rolling outer hash over per-output summaries
cx_sha256_t currentOutputScriptCtx;     // inner sha256 for current output's scriptPubKey
uint64_t currentOutputSatoshis;
unsigned int currentOutputBytesRemaining;
radiant_output_substate_t outputParsingSubstate;  // AMOUNT | SCRIPT_LEN | SCRIPT
```

### 2. `helpers.{h,c}` — four helpers (all no-op unless `COIN_KIND == COIN_KIND_RADIANT`)

- `radiant_output_hash_init()` — `cx_sha256_init_no_throw` both contexts, substate=`AMOUNT`, bytesRemaining=8
- `radiant_output_hash_reset()` — unconditional reset for cancel/interrupt; re-inits `currentOutputScriptCtx` in case cancel arrives mid-script (Security H2 from review)
- `radiant_output_hash_feed_byte(b)` — the per-output FSM
- `radiant_output_hash_finalize()` — `sha256d` of the rolling ctx → `segwit.cache.hashedOutputHashes`

**Critical inner loop** (end of `SCRIPT` state, one full scriptPubKey streamed into `currentOutputScriptCtx`):

```c
// Double-SHA256 the scriptPubKey
uint8_t digest1[32];
cx_hash_no_throw(&context.currentOutputScriptCtx.header, CX_LAST, NULL, 0, digest1, 32);
cx_sha256_t finalCtx; cx_sha256_init_no_throw(&finalCtx);
uint8_t scriptHash[32];
cx_hash_no_throw(&finalCtx.header, CX_LAST, digest1, 32, scriptHash, 32);

// Assemble 76-byte summary and feed into rolling hashOutputHashesCtx
uint8_t summary[76];
for (int i = 0; i < 8; i++)
  summary[i] = (context.currentOutputSatoshis >> (8 * i)) & 0xff;   // nValue LE
memmove(summary + 8, scriptHash, 32);
summary[40]=0; summary[41]=0; summary[42]=0; summary[43]=0;          // totalRefs=0 (4B LE, NOT varint)
memset(summary + 44, 0, 32);                                          // refsHash=zeros

cx_hash_no_throw(&context.hashOutputHashesCtx.header, 0, summary, 76, NULL, 0);

// Reset for next output
context.outputParsingSubstate = RADIANT_OUT_AMOUNT;
context.currentOutputBytesRemaining = 8;
context.currentOutputSatoshis = 0;
```

Canonical-P2PKH enforcement lives in the `SCRIPT_LEN` state: any varint-prefix byte or `script_len != 25` → `SW_INCORRECT_DATA`. v1 scope is P2PKH only; non-P2PKH outputs refused at the device. v2 replaces this check with real push-ref scanning.

### 3. `handler/hash_input_start.c` — call init

Add `radiant_output_hash_init()` alongside the existing segwit-hasher init on first APDU of the input-start sequence.

### 4. `handler/hash_input_finalize_full.c` — stream bytes per output

**CRITICAL**: the byte-feeder MUST live **inside** the `OUTPUT_PARSING_OUTPUT` case of `handle_output_state`, **NOT** post-switch. The post-switch position also fires for `OUTPUT_PARSING_NUMBER_OUTPUTS`, which discards 1–3 bytes of vout-count varint; those must not reach the Radiant FSM. Prominent inline comment warns against moving it back.

Also:
- `hash_input_finalize_full_reset()` calls `radiant_output_hash_reset()` so a cancel mid-script leaves no stale state (Security H2).
- Finalize `radiant_output_hash_finalize()` alongside the existing `hashedOutputs` finalization step.

### 5. `transaction.c:~721` — insert into preimage

```c
if (context.usingSegwit && context.segwitParsedOnce) {
  if (!context.usingOverwinter) {
    if (COIN_KIND == COIN_KIND_RADIANT) {
      cx_hash_no_throw(&context.transactionHashFull.sha256.header, 0,
                       context.segwit.cache.hashedOutputHashes,
                       sizeof(context.segwit.cache.hashedOutputHashes),
                       NULL, 0);
    }
    // Existing hashedOutputs append (unchanged)
    cx_hash_no_throw(&context.transactionHashFull.sha256.header, 0,
                     context.segwit.cache.hashedOutputs, 32, NULL, 0);
  }
}
```

### 6. Plugin-side defense-in-depth

`Zyrtnin-org/Electron-Wallet@radiant-ledger-512` — `electroncash_plugins/ledger/ledger.py` pre-checks each output against `^76a914[0-9a-f]{40}88ac$` before any APDU dispatch. User-visible error if they try to send to a P2SH or OP_RETURN destination, avoiding the ugly SW-code error from device-side rejection.

## Verification that it works

- **4 golden-vector fixtures** (real mainnet txs: `48bcbdef…`, `3521c21…`, `266fdbec…`, `b4debc15…`) covering 1-in/1-out sweep, 1-in/2-out change, 3-in/2-out multi-input, 11-in/1-out consolidation. 16 sighashes, 100% verified via `ecdsa.verify_digest` against published mainnet signatures.
- **Device↔oracle compare**: oracle sighash `db4097bd90b6ccf45bb64f7bcd3cee2f8bd40cddbcbe97d97eb390791f61657a` for the unstuck Ledger spend; device DER signature verifies against it + device pubkey via local secp256k1 → PASS.
- **Two Ledger-signed mainnet txs confirmed on-chain**:
  - `d942de8c94c2e1a9ed5afe14e8505556170e3d5243ecbfa80260a1feeaf3d679` — block 420756 (first unstuck spend)
  - `de3574979f986616b4152c4294b85562318292490d3587d8fe32aff456893743` — block 420762 (follow-up validation)

Release tag: `v0.0.3-sighash-fix` on `Zyrtnin-org/app-radiant`.

## Prevention

### How to avoid this class of problem next time

1. **Treat the preimage SPEC as ground truth, not the SIGHASH byte or fork-id value.** Those are necessary but not sufficient signals. When forking a BCH-family app for a new chain, read the target chain's `SignatureHash` function in its node source end-to-end before writing any app code. 30 minutes of node-code reading prevents weeks of device debugging.

2. **Build an oracle FIRST.** Port the target chain's reference implementation (JS or C++) verbatim to Python, and self-validate against a real mainnet tx: recompute the sighash, then verify the published signature against it via local `secp256k1`. If that verification passes, your preimage layout is correct. Cost: ~1 day. Payoff: surfaces discrepancies like `hashOutputHashes` before any device firmware work.

3. **Walking-skeleton end-to-end test before committing to a C implementation plan.** Build the crudest possible host-to-device signing path and broadcast 1 dust-sized unit on the real target network. If rejected, diagnose BEFORE expanding the design. This is exactly what caught `hashOutputHashes` at 1 RXD of exposure instead of after a month of implementation.

### Best practices when forking app-bitcoin for a new coin

Pre-implementation checklist — validate all 5 before writing code:

- SIGHASH flags set and how they compose
- Sighash preimage structure: every field, in order, with exact widths (diff against BCH byte-for-byte)
- Fork-id encoding, if any
- Transaction version branching, if any
- Script-type whitelist (P2PKH / P2SH / OP_RETURN / chain-specific opcodes)

When the target chain ships a JS reference library (e.g. `radiantjs`), port it verbatim into Python as the canonical oracle. Do not paraphrase, do not "simplify" — paraphrasing is how new fields get silently dropped. Ensure the device's v1 canonical-shape enforcement matches the host-side wallet pre-check. Defense in depth protects against a malicious host.

### Testing suggestions

- **Golden-vector fixtures**: 4+ real mainnet tx shapes — sweep, with-change, multi-input, consolidation. Each fixture stores oracle-computed sighash + the published mainnet signature. Both must verify via local `secp256k1` at build time and on every oracle-code change.
- **Cancel/interrupt device state test**: reject signing mid-flow on the device, retry immediately, confirm identical deterministic behavior (no stale preimage state).
- **CI matrix**: build both the original BCH variant AND the new chain variant on every commit. Prevents accidental contamination of the upstream code path.
- **Mainnet final-test rollback plan**: if a broadcast still rejects after device-vs-oracle compare passes, STOP. Drop into APDU tracing. Do not retry on mainnet without changing something material.

### Test cases to add

- **Unit**: Python oracle vs each golden vector — sighash matches expected bytes exactly.
- **Integration**: device signs → extract signature from `scriptSig` → `ecdsa.verify_digest(sig, oracle_sighash, device_pubkey)` returns `True`.
- **Regression**: canonical-P2PKH-only device behavior — non-P2PKH outputs are rejected with `SW_INCORRECT_DATA`, not silently signed.
- **Differential**: run the same unsigned tx through both the BCH-path oracle and the Radiant-path oracle; assert the preimages differ in exactly the expected fields (catches accidental path-sharing regressions).

## Related

### In-repo siblings

- [`INVESTIGATION.md`](../../../INVESTIGATION.md) — full arc of the sighash/preimage investigation that led to the `hashOutputHashes` finding
- [`docs/plans/2026-04-15-feat-hashoutputhashes-preimage-fix-plan.md`](../../plans/2026-04-15-feat-hashoutputhashes-preimage-fix-plan.md) — implementation plan for the preimage extension fix
- [`docs/brainstorms/2026-04-15-hashoutputhashes-remediation-brainstorm.md`](../../brainstorms/2026-04-15-hashoutputhashes-remediation-brainstorm.md) — pre-plan exploration of remediation options
- [`docs/plans/2026-04-14-feat-radiant-ledger-app-v1-plan.md`](../../plans/2026-04-14-feat-radiant-ledger-app-v1-plan.md) — original v1 Ledger-app plan (pre-sighash-fix context)
- [`scripts/radiant_preimage_oracle.py`](../../../scripts/radiant_preimage_oracle.py) — reference oracle producing the correct Radiant preimage
- [`scripts/fixtures/preimage-vectors.json`](../../../scripts/fixtures/preimage-vectors.json) — golden fixtures consumed by on-device tests
- `scripts/{test_oracle_against_vectors,oracle_self_validate,build_fixtures}.py` — oracle validation tooling

### Cross-repo canonical sources

- [`RadiantBlockchain/radiant-node`](https://github.com/RadiantBlockchain/radiant-node) — `src/script/interpreter.cpp:2636-2650` (sighash computation with `hashOutputHashes`), `src/primitives/transaction.h:475-540` (Radiant preimage struct layout)
- [`RadiantBlockchain/radiantjs`](https://github.com/RadiantBlockchain/radiantjs) — `lib/transaction/sighash.js:91-237` (JS reference implementation of the Radiant BIP143-variant preimage)
- [`Zyrtnin-org/lib-app-bitcoin`](https://github.com/Zyrtnin-org/lib-app-bitcoin) — `radiant-v1` branch, `helpers.c` (on-device preimage FSM)
- [`Zyrtnin-org/app-radiant`](https://github.com/Zyrtnin-org/app-radiant) — tag `v0.0.3-sighash-fix`
- [`Radiant-Core/Electron-Wallet#1`](https://github.com/Radiant-Core/Electron-Wallet/pull/1) — closed PR, historical context; the pre-fix attempt that did not produce valid signatures

### Mainnet artifacts (Ledger-signed Radiant txs)

- [`d942de8c94c2e1a9ed5afe14e8505556170e3d5243ecbfa80260a1feeaf3d679`](https://explorer.radiantblockchain.org/tx/d942de8c94c2e1a9ed5afe14e8505556170e3d5243ecbfa80260a1feeaf3d679) — block 420756
- [`de3574979f986616b4152c4294b85562318292490d3587d8fe32aff456893743`](https://explorer.radiantblockchain.org/tx/de3574979f986616b4152c4294b85562318292490d3587d8fe32aff456893743) — block 420762
