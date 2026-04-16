---
name: Radiant Glyph FT/NFT view-only wallet renderer — classifier template, node-RPC indexer, metadata decoder
description: How to classify, enumerate, and render Radiant Glyph UTXOs (NFT singletons + FT holders) for a Ledger-owned address using only Radiant Core RPC. Surfaces the exact 75-byte FT holder template (derived from 2309 mainnet samples), decodes the relevant opcodes against Radiant Core source, and provides a browser UI that renders on-chain CBOR metadata including embedded PNG images.
type: integration-issue
component: app-radiant, Electron-Wallet, view-only-ui, radiant-mainnet
severity: medium
resolved: 2026-04-16
related:
  - docs/solutions/integration-issues/radiant-glyph-spend-end-to-end-mainnet.md
  - docs/solutions/integration-issues/radiant-glyph-sign-device-vs-oracle-mismatch.md
  - docs/solutions/integration-issues/radiant-preimage-hashoutputhashes-missing.md
---

# Radiant Glyph FT/NFT view-only wallet renderer

## Context

[`radiant-glyph-spend-end-to-end-mainnet.md`](radiant-glyph-spend-end-to-end-mainnet.md) ended with Gotcha 1: *Electron Radiant doesn't recognize Glyph UTXOs* — its script classifier checks only for standard P2PKH/P2SH/OP_RETURN shapes, so a 63-byte NFT-prefixed or 75-byte FT-suffixed P2PKH never gets associated with the owning address, never appears in the Coins tab, and can't be spent from the GUI. To close that loop, we needed:

1. The **exact byte template** of an FT holder UTXO on mainnet (the NFT wrapper was already documented as `d8 <ref> 75 <P2PKH>` in the end-to-end doc; FTs were not).
2. A concrete **wallet classifier fix** Electron-Wallet can adopt.
3. A way to **enumerate balances for a Ledger-owned address** without depending on third-party block explorers.
4. A way to **render NFT/FT metadata** (name, image, protocol) end-to-end from chain data so we can prove the Ledger-custodied NFTs are normal, identifiable, fully-owned assets.

The end deliverable is a [view-only UI](../../../view-only-ui/) that does all of this against the live VPS `radiant-mainnet` container.

## Investigation summary

Steps taken, what worked, what was rejected:

### What didn't work (and why)

- **ElectrumX from the browser**: standard ElectrumX is raw TCP/SSL. No WSS endpoint advertised on `electrumx.radiant4people.com:50012`. Can't call from a web page.
- **`explorer.radiantblockchain.org/api/...`**: every guessed path returns 404 (`/api/tx/`, `/ext/gettx/`, `/rawtx/`, `/insight-api/tx/`). Express backend is scoped to server-rendered HTML.
- **`radiantexplorer.com/api/tx/<txid>`**: returns valid JSON with `vout[].scriptPubKey.hex` but **no `Access-Control-Allow-Origin` header** — browser fetch is blocked. Viable only via server-side proxy.
- **`glyph-explorer.rxd-radiant.com`**: Next.js SPA. Does advertise CORS (`access-control-allow-origin: *` on errors) but every public endpoint 404s — data-fetching is done via React Server Components, not REST. Dead end.
- **Hardcoded ref→reveal map**: too brittle; every new FT mint breaks the UI.

### What worked

- **Radiant Core RPC**: `getrawtransaction`, `scantxoutset start '[addr(X), raw(Y), ...]'`, `getblock <hash> 2`. Stable, authoritative, and sufficient for every query we need. Node already running on the VPS per the main project memory.
- **Block-scan algorithm for ref→reveal lookup**: given a 36-byte ref, the commit tx's `blockhash` comes back from `getrawtransaction`; the reveal tx almost always lives in that same block (verified for both the Glyph Protocol FT mint and the FlipperHub photo NFT mint — both resolved in `blocks_scanned: 1`). Walk up to 30 blocks for safety.
- **A 500-block mainnet scan** via `scripts/find_ft_utxo.py` gave us **2309 FT holder samples across 6 distinct token refs with 100% template conformance** — statistically strong evidence that the FT wrapper shape is a protocol-wide invariant, not per-token.
- **Cross-validation against Radiant Core source** ([`src/script/script.h`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/script.h), [`src/script/interpreter.cpp`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/interpreter.cpp)) turned byte patterns into semantics.

## Root cause — why Electron-Wallet misses Glyph UTXOs

Electron-Wallet (inherited from Electron Cash) classifies output scripts against a fixed whitelist of shapes. Any script that doesn't match the exact `P2PKH`, `P2SH`, or `OP_RETURN` layouts is categorized as "unknown" and never associated with a Radiant address. Radiant's Glyph protocol wraps standard P2PKH with either a prefix (NFT singletons) or a suffix (FT holders) — neither is on the whitelist. The wrapping is **consensus-permissive**: the P2PKH portion unlocks with exactly `<sig> <pubkey>`, and the Glyph portions are runtime no-ops or consensus-level invariants that don't alter the spend signature.

So the fix is not cryptographic or signing-related — it's a **script pattern recognition** fix. Once the classifier recognizes the Glyph wrapper shapes, everything downstream (balance display, coin selection, signing) already works.

## Solution — three artifacts

### 1. The classifier (the one-line fix for Electron-Wallet)

Match one of these exact regex patterns against the scriptPubKey hex:

```
Plain P2PKH (25B):   ^76a914[0-9a-f]{40}88ac$
NFT singleton (63B): ^d8[0-9a-f]{72}7576a914[0-9a-f]{40}88ac$
FT holder (75B):     ^76a914[0-9a-f]{40}88acbdd0[0-9a-f]{72}dec0e9aa76e378e4a269e69d$
```

On match, treat the 20-byte pkh portion as the owning address. The extracted 36-byte ref (for NFT/FT) identifies the token; group FT UTXOs by ref to compute per-token balance (sum the photon values of matching UTXOs — Radiant FT amount equals UTXO photon value, there is no separate amount field).

Source of the template constants: a 500-block mainnet scan (tip 420968 → 420469), 2309 FT holder samples across 6 distinct tokens. **Zero drift** in the 50-byte fixed portion (`88ac bd d0 … dec0e9aa76e378e4a269e69d`). Evidence in [`view-only-ui/fixtures/classifier-vectors.json`](../../../view-only-ui/fixtures/classifier-vectors.json) and [`view-only-ui/fixtures/known-refs.json`](../../../view-only-ui/fixtures/known-refs.json).

### 2. The node-RPC indexer (`view-only-ui/server.js`)

Zero-dependency Node HTTP proxy that bridges the browser to the VPS `radiant-mainnet` container over ssh. Five routes:

| Route | Underlying RPC | Purpose |
|---|---|---|
| `GET  /tx/<txid>` | `getrawtransaction <txid> 1` | Fetch tx JSON for per-output classification |
| `GET  /scan/addr/<address>` | `scantxoutset start '[addr(X)]'` | Plain RXD UTXOs for an address |
| `GET  /scan/raw/<spk_hex>` | `scantxoutset start '[raw(Y)]'` | UTXOs matching an exact 63B or 75B Glyph wrapper |
| `POST /scan/multi` | `scantxoutset start '[desc1, desc2, …]'` | Batch the above — one UTXO-set pass, all descriptors |
| `GET  /reveal/<ref_hex>` | `getrawtransaction` + `getblockheader` + block walk | Locate the reveal tx for a ref (for CBOR metadata extraction) |

Descriptor regex (`^(addr|raw)\([0-9a-zA-Z]+\)$`) blocks shell injection through user input. In-memory cache for `/reveal` lookups.

Proved against the FT-rich holder `15e1pB2h4Vj9psqaFHEuPMZMf8UPc9cCTr`: one `POST /scan/multi` call with 2 descriptors returned **11,296 UTXOs from a 28.6M-entry UTXO set in ~30s** — 1 plain P2PKH + 11,295 FT UTXOs of the dominant token.

Shell-quoting note: the initial implementation used `exec()` with an f-string concatenating everything into one shell line. When a `scantxoutset` descriptor like `addr(X)` ended up nested inside `ssh VPS '…'`, the VPS shell saw `addr(X)` unquoted and threw "syntax error near unexpected token `('". Fixed by switching to `spawn("ssh", [VPS, remoteCmd])` so the local Node shell never sees the remote command — only the VPS shell parses it, one level of quoting total.

### 3. The CBOR metadata extractor / renderer (`view-only-ui/index.html`)

Given a classified NFT or FT UTXO with a 36-byte ref:

1. Call `/reveal/<ref>` — server finds the reveal tx (spends commit's outpoint, embeds CBOR payload in `vin[0].scriptSig`).
2. Walk `vin[0].scriptSig` for push elements. The 3-byte push `676c79` is the **"gly" glyph-protocol marker**. The push immediately following it is the CBOR payload.
3. Decode with the MIT-licensed [paroga/cbor-js](https://github.com/paroga/cbor-js) vendor lib (12 KB, copied from the [radiant-glyph-nft-guide demo](../../../../radiant-glyph-nft-guide/demo/)).
4. Render `{ name, ticker, description, p (protocol array), main, loc, … }`. `main` can be raw bytes or `{t: mime, b: bytes}` — normalize both. For image types, detect MIME via magic bytes (PNG/JPEG/GIF/WebP/SVG) and emit a `data:` URL. For IPFS-only NFTs with no `main`, fall back to `https://ipfs.io/ipfs/<cid>`.

Verified end-to-end on mainnet:

- **Glyph Protocol FT** (ref `8b87c3c7…`): reveal tx `b965b32d…` at height 228604, CBOR payload 65,569 bytes, `main` is a valid 521×520 8-bit RGBA PNG, decodes as `{p: [1,4], ticker: "GLYPH", name: "Glyph Protocol", desc: "The first of its kind"}`.
- **FlipperHub NFT** (ref `08480623…`, the Ledger-custodied mint): reveal tx `6c32fcbb…` at height 420873, CBOR payload 640 bytes, `{p: [2], type: "photo", name: "FlipperHub #sub_…", attrs: {game, tournament, score, trust_score, photo_hash}}`. This mint omits `main` and `loc` is a **58-char truncated CIDv1** (decode fails — 4th-byte `hash_len` of 145 exceeds record), so all public IPFS gateways return 400/422. Surfacing this bug is itself a product of the tool working correctly; the renderer displays an explanatory error rather than hiding it.

## Prevention

- **Golden vectors**: [`view-only-ui/fixtures/classifier-vectors.json`](../../../view-only-ui/fixtures/classifier-vectors.json) has 12 scriptPubKey vectors (1 P2PKH from real mainnet, 1 NFT singleton, 3 FT holders across 2 distinct tokens, 1 241-byte FT control script as a negative case, 1 OP_RETURN, 3 malformed-input cases, 2 invalid-input cases) plus 3 round-trip/decode checks. Run `node fixtures/test_classifier.mjs` — exit 0 iff every classifier output matches expected type + pkh + ref. Pins the template. Any future drift breaks the runner.
- **Regex bounded**: the three shapes are matched with full-string anchors and exact byte counts. A 76-byte output with the FT middle but a different tail does not misclassify — it correctly falls through to `unknown`. Verified by the `malformed_ft_wrong_tail` / `malformed_ft_wrong_length` / `malformed_nft_wrong_drop_byte` vectors.
- **Independent cross-check via `scantxoutset raw()`**: the classifier's claim that a given (pkh, ref) pair has UTXOs of a given shape can be verified against the node's UTXO set by submitting the reconstructed 75B/63B hex to `raw(…)` and comparing counts. The view-only UI does this automatically on the Address Balances tab.
- **Protocol decode verified against Radiant Core source**: `OP_STATESEPARATOR` (0xbd) is a runtime NOP per [`interpreter.cpp:1946`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/interpreter.cpp#L1946). `OP_CODESCRIPTHASHVALUESUM_UTXOS/_OUTPUTS` (0xe3/0xe4) enforce Σ photon-value of inputs ≥ Σ photon-value of outputs per codeScript hash per [`interpreter.cpp:2167-2204`](https://github.com/RadiantBlockchain/radiant-node/blob/master/src/script/interpreter.cpp#L2167-L2204). These are not assumptions — they're read from source and cited in the UI footer.

## What to do next time a Glyph-wallet classification question comes up

1. Before assuming the protocol changed, **re-run** `scripts/find_ft_utxo.py --back 100`. If the 75-byte FT or 63-byte NFT template still matches > 99% of samples, the classifier is still correct.
2. If the template has drifted (e.g. a new protocol version introduces a new suffix), add a new vector to `classifier-vectors.json` capturing the real-mainnet drift sample, then extend `classifier.mjs` with a new case. The test runner catches regressions in the old cases automatically.
3. For any third-party explorer integration: first run `curl -sI -H "Origin: https://example.com" <url>` and check for `access-control-allow-origin`. Explorers without CORS need a server-side proxy — don't waste time on browser workarounds.
4. For "wallet doesn't recognize my NFT/FT" debugging: the first question is whether the upstream classifier recognizes the wrapper shape, NOT whether signing is broken. The signing path is unaffected by Glyph wrapping (proved on mainnet by `22d4e0e0…`).

## Files added in this session

All under [`view-only-ui/`](../../../view-only-ui/):

- `index.html` — single-file UI, 4 tabs (hex / tx JSON / fetch by txid / address balances), browser-side classifier, CBOR decoder, metadata renderer
- `classifier.mjs` — pure ES module (browser + Node), source of truth for the three regex patterns
- `server.js` — zero-dep Node proxy, five RPC routes, ssh bridge to VPS `radiant-mainnet`
- `vendor/cbor.min.js` — MIT-licensed paroga cbor-js, copied from the radiant-glyph-nft-guide demo
- `fixtures/classifier-vectors.json` — 13 golden vectors with real mainnet provenance
- `fixtures/known-refs.json` — 6 FT token refs observed in the 500-block scan
- `fixtures/test_classifier.mjs` — Node test runner, exit 0 iff all 15 checks pass
- `README.md` — architecture + run instructions + rationale for node-RPC over Glyph Explorer

Also added: [`scripts/find_ft_utxo.py`](../../../scripts/find_ft_utxo.py) — the mainnet scanner that produced the template constants.
