# Task 0.0 — LSB-014 path-lock verification runbook

**Goal:** prove that Ledger OS permits an **unsigned** community app to declare `--path "44'/512'"` at sideload time. If it doesn't, the whole plan (SLIP-44 coin type 512 for RXD) is infeasible.

**Time:** ~30 min once prerequisites are installed (1st build is ~5 min in Docker).

---

## Prerequisites (one-time)

Install on the Linux host:

```bash
# 1. ledgerblue (sideloader)
pip install ledgerblue --break-system-packages  # or use a venv

# 2. Ledger udev rules (required for USB HID access without sudo)
wget -q -O - https://raw.githubusercontent.com/LedgerHQ/udev-rules/master/add_udev_rules.sh | sudo bash
# Unplug + replug the device after this.

# 3. Confirm device is detected
lsusb | grep -i ledger
# Expect: a line with "2c97:5000" or similar for Nano S Plus. If nothing: USB cable is charge-only,
# device locked, or udev reload needed.
```

On the device:
- Unlock with PIN
- Stay on the home screen (do not open any app yet)

---

## Step 1 — Build `app-boilerplate` (unmodified) via pinned builder

We use a pinned digest so this step is itself the first reproducibility test.

```bash
cd /tmp
git clone https://github.com/LedgerHQ/app-boilerplate.git
cd app-boilerplate
git checkout ac10944e8bfed3d1e57af9a856dd6ab716a74a1b  # pinned SHA

# Enter the pinned builder image (amd64; the multi-arch index digest is used)
docker run --rm -it \
  -v "$(pwd):/app" \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite@sha256:b82bfff7862d890ea0c931f310ed1e9bce6efe2fac32986a2561aaa08bfc2834 \
  bash -c "cd /app && make BOLOS_SDK=\$NANOS_PLUS_SDK TARGET=nanos2"
```

After exit, `bin/app.hex` should exist on the host (bind mount).

---

## Step 2 — Sideload with the CRITICAL override

Here's the actual LSB-014 test. Note `--path "44'/512'"` — we are overriding what app-boilerplate natively declares:

```bash
python3 -m ledgerblue.loadApp \
  --targetId 0x33100004 \
  --tlv \
  --curve secp256k1 \
  --path "44'/512'" \
  --appFlags 0x000 \
  --fileName bin/app.hex \
  --appName "Path512Test" \
  --appVersion "0.0.1" \
  --dataSize 0 \
  --delete
```

(The `--apiLevel` will be read from the built .hex via `--tlv`; we don't set it explicitly.)

---

## Step 3 — Observe

**PASS** — device prompts:
1. "Allow unsafe manager?" → approve with both buttons
2. "Install app Path512Test / identifier <hash> / from unverified source" → approve
3. Command exits with success; `Path512Test` appears in the device's app list
4. Record: **PASS** in `INVESTIGATION.md`. Project proceeds.

**FAIL (path lock)** — one of:
- `loadApp` raises `Exception: Invalid status 6a80` / `6985` mentioning the path
- Device screen shows "This app is not allowed" or similar path-related warning before the normal install prompts
- Record: **FAIL**, capture the exact error + screen photo. Stop Phase 1 work; re-evaluate (is there a different SLIP-44 Ledger permits? official sponsorship?).

**WARN** — install succeeds but with an *additional* scary warning beyond the standard "unverified source":
- e.g. "This app may sign transactions for Bitcoin" or similar cross-chain warning
- Record: **WARN**, capture the warning text + photo. Decide whether user-acceptable. Likely still proceed but note in `INSTALL.md`.

---

## Step 4 — Clean up

Remove the test app from the device to free the slot:

```bash
python3 -m ledgerblue.deleteApp \
  --targetId 0x33100004 \
  --appName "Path512Test"
```

Or uninstall via Ledger Live UI.

---

## What this proves / doesn't prove

**Proves:** Ledger OS accepts `--path "44'/512'"` (or doesn't) for an unsigned app at install time. This is LSB-014 enforcement.

**Does not prove:** that runtime BIP32 derivation at `m/44'/512'/...` works inside an app we build. Task 0.1 (derivation cross-check) + Phase 1 integration test cover that.

**Does not prove:** that the Ledger Bitcoin app won't refuse to co-exist with our app. If there's an app-slot conflict, it'll surface in Phase 1 once we try to install our Radiant app alongside BTC.
