# Radiant Ledger App — v1 Brainstorm

**Date:** 2026-04-14
**Status:** Brainstorm complete — ready for `/workflows:plan`
**Scope:** v1 = plain RXD send/receive on Ledger Nano S Plus. Glyph/NFT support is explicitly **v2**.

---

## What We're Building

A sideloadable Ledger app that lets users sign plain Radiant (RXD) transactions on a Nano S Plus hardware wallet, produced by forking `LedgerHQ/app-bitcoin` and adding a `radiant` Makefile variant plus a small on-device address display patch.

Users install it via `python -m ledgerblue.loadApp ...`, accept the "unverified app" warning, and pair it with Electron Radiant to send/receive RXD with private keys that never leave the device.

**Out of scope for v1:**
- Glyph / NFT minting (new opcodes, script parser changes) → v2
- Nano S, Nano X, Stax, Flex → later
- Web wallets (WebHID), CLI signer → later
- Official Ledger Live listing → future, post-community-validation

---

## Why This Approach

**Community sideload, not official Ledger listing.** Same path BCH, BTG, and most non-top-10 coins took. No Ledger gatekeeping, months-long review, or legal agreement required. Ships in weeks, not quarters.

**Fork `app-bitcoin`, don't write from scratch.** Radiant's sighash is byte-identical to BCH's (`SIGHASH_ALL | SIGHASH_FORKID = 0x41`, fork value 0). The BCH signing code path is already battle-tested and reused by multiple Ledger variants. A clean-slate app would require re-implementing SIGHASH_FORKID preimage construction from scratch — a meaningful amount of additional C and on-device debugging work for no new capability. Verified in [radiant-node `src/script/sighashtype.h:17`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/sighashtype.h#L17).

**Thin variant + address display fix.** Makefile constants alone would ship faster, but showing wrong-looking addresses on the device screen during confirmation undermines the whole point of a hardware wallet. Radiant needs base58 `1…`-prefixed addresses on-screen (P2PKH version byte 0, same base58 layout as BTC mainnet) while still using BCH-style `SIGHASH_FORKID` signing — so v1 is a surgical blend of the `bitcoin_cash` variant's sighash path with the `bitcoin_legacy` variant's address-display path. Neither template works unmodified.

**Nano S Plus only.** Current-gen, actively sold, biggest active user base, what the closed [PR #1](https://github.com/Radiant-Core/Electron-Wallet/pull/1) already targeted. Single device = single QA matrix.

**Mainnet testing with multiple testers, skip testnet.** RXD fees are negligible, so running real mainnet transactions across 3-5 community testers catches device/firmware/mempool variance faster than building out a testnet signing pipeline that nobody will use again.

---

## Key Decisions

| Decision | Choice | Why |
|---|---|---|
| **Audience** | Community sideload | No Ledger relationship needed; ships in weeks |
| **Repo & trust** | Radiant-Core org + reproducible CI builds | Transparency via build reproducibility; no single-signer risk; sets up governance handoff |
| **Devices** | Nano S Plus only | Current-gen, single QA target; Nano S is EOL |
| **Host wallet** | Electron Radiant only | Existing `electroncash_plugins/ledger/ledger.py` already exists — just needs alignment |
| **Starting point** | Fork `LedgerHQ/app-bitcoin`; borrow sighash from `bitcoin_cash`, address display from `bitcoin_legacy` | BCH sighash is byte-identical to Radiant; BTC base58 display matches Radiant's `1…` addresses |
| **Implementation depth** | Thin variant + address display fix | Correct on-device UX without full script-parser rewrite |
| **Validation gate** | Multiple community testers, mainnet small amounts | RXD fees cheap enough that mainnet = the test environment |
| **Glyph support** | Explicitly deferred to v2 | V2 opcodes (`OP_PUSHINPUTREFSINGLETON` etc.) require script parser work; independent of v1 signing |

---

## Network Constants

Pulled from the Radiant node source where available. SLIP-44 is still unverified — see Open Questions #1.


Sources: [`chainparams.cpp:193-198`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/chainparams.cpp#L193), [`sighashtype.h:17`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/sighashtype.h#L17).

```makefile
else ifeq ($(COIN),radiant)
BIP44_COIN_TYPE=???          # UNVERIFIED — must confirm before first build (see Open Questions #1)
BIP44_COIN_TYPE_2=???
COIN_P2PKH_VERSION=0
COIN_P2SH_VERSION=5
COIN_FAMILY=1
COIN_COINID=\"Radiant\"
COIN_COINID_NAME="Radiant"
COIN_COINID_SHORT=\"RXD\"
COIN_KIND=COIN_KIND_RADIANT  # NEW enum — must add to C source
COIN_FORKID=0
endif
```

Additional parameters (for host plugin, not the app itself):
- WIF secret key prefix: `0x80`
- Extended key: xpub `0x0488B21E`, xprv `0x0488ADE4`
- P2P port: `7333`
- CashAddr prefix: `radaddr` (unused by app-bitcoin variants; base58 only)

---

## Definition of Done (v1)

A Nano S Plus with the Radiant app installed can:

1. Derive and display a Radiant P2PKH address matching what other Radiant wallets produce from the same seed at the same BIP44 path
2. Show the receive address on the device screen for user verification
3. Sign a standard P2PKH spend (1+ inputs, 1–2 outputs including change) and produce a transaction Radiant mainnet accepts
4. Be built reproducibly via pinned CI, with published artifact SHA256 hashes matching what community testers build locally
5. Install cleanly via `python -m ledgerblue.loadApp` on a stock Nano S Plus with current firmware

---

## Open Questions

1. **SLIP-44 coin type for RXD.** Not explicit in `radiant-node` source. Registry commonly lists 512 for RXD but this **must be verified** against what radiantjs and existing Radiant wallets actually derive at before finalizing `BIP44_COIN_TYPE`. A mismatch means addresses won't match other Radiant wallets using the same seed.

2. **How to combine the BCH sighash path with the BTC-legacy address display path in the C source.** The surgical blend could be implemented as `#ifdef COIN_KIND_RADIANT` guards inside existing BCH/BTC functions, as a new dispatch layer keyed on `COIN_KIND`, or as a third variant that selectively includes both sets of `.c` files. Planning phase must pick one and justify it; the choice affects how easy v2 diffs will be.

3. **Electron Radiant plugin alignment.** The existing [`electroncash_plugins/ledger/ledger.py`](https://github.com/Radiant-Core/Electron-Wallet/blob/master/electroncash_plugins/ledger/ledger.py) was forked from Electron Cash. It likely still sends BCH-flavored APDU CLA bytes and expects BCH address decoding. This is a parallel v1 workstream — the plan must scope both the app-side and plugin-side changes together, since neither ships without the other.

4. **Reproducible build environment.** Ledger's Docker image (`ledger-app-builder`) is the reference toolchain — needs to be pinned by digest in CI so artifact hashes are actually reproducible across builds.

5. **Sideload UX.** Who writes the install guide? What's the recovery story if a user bricks an app slot? These are v1 docs, not v1 code, but they block the "release" milestone.

---

## v1 → v2 Bridge

Things v1 should do well *because* v2 will need them:
- Clean Makefile variant so v2 Glyph work is a diff against v1, not a re-fork
- Avoid entrenching P2PKH-only assumptions in ways that would force a re-architecture for v2 (v2 will hit `nftCommitScript` and singleton outputs). v1 still implements P2PKH-only; it just shouldn't close doors.
- Test fixtures (unsigned tx → expected sig bytes) produced from [FlipperHub `blockchain_rpc.php`](https://github.com/Zyrtnin-org/Flipperhub/blob/master/blockchain_rpc.php) — these become regression tests for v2 signing changes

---

## Next Step

Run `/workflows:plan` against this document to produce the implementation plan: repo bootstrap, fork layout, CI reproducibility, Makefile variant, on-device address patch, Electron Radiant plugin alignment, multi-tester validation protocol.
