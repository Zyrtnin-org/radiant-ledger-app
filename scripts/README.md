# Phase 0 helper scripts

## Task 0.1 — Derivation cross-check

Confirms that BIP32/BIP44 derivation at `m/44'/512'/0'/0/0` produces the same math a stock Ledger Bitcoin app uses at `m/44'/0'/0'/0/0`, just with a different coin_type. This catches any BIP32 surprise **before** we invest in C work.

### Run

```bash
cd scripts
npm install
node task-0.1-derivation-crosscheck.js "<BIP39 mnemonic — USE A TEST SEED>"
```

### Pass criterion

The script prints two rows:
- `m/44'/0'/0'/0/0` — what stock Ledger BTC app + current Electron Radiant derive
- `m/44'/512'/0'/0/0` — what the new Radiant app will derive

Install the stock Ledger Bitcoin app on a Nano S Plus with the same test seed, then view the receive address at the first path in an Electron wallet. If it matches the `44'/0'` row from this script: **PASS** — BIP32/BIP44 derivation math is as expected. Proceed.

If it does not match: **STOP**. There is a BIP32 divergence (custom entropy handling, non-standard hardening, etc.) that must be understood before writing C.

### Security note

Use a throwaway test seed. Never run this with a seed that holds real funds.
