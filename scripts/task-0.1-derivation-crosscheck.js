#!/usr/bin/env node
/*
 * Task 0.1 — Derivation cross-check
 *
 * Goal: Confirm that a pure BIP32/BIP44 derivation at m/44'/512'/0'/0/0
 * produces the same pubkey/address that we expect from a Ledger Bitcoin
 * app run at m/44'/0'/0'/0/0 with the same seed, modulo the coin_type
 * difference.
 *
 * This is a pure-math check: no device needed for this script. Run it
 * with a test seed, then compare its output for m/44'/512'/0'/0/0 against
 * what your stock Ledger Bitcoin app produces at m/44'/0'/0'/0/0 when
 * loaded with the same seed.
 *
 * Both numbers should differ (different coin_type = different keys),
 * but if you swap the coin_type in the script to 0, it should produce
 * the exact pubkey the stock Bitcoin app gives you for m/44'/0'/0'/0/0.
 *
 * Usage:
 *   cd scripts && npm install bip32 bip39 tiny-secp256k1
 *   node task-0.1-derivation-crosscheck.js "<12 or 24 word BIP39 mnemonic>"
 *
 * WARNING: Use a TEST seed. Never use your real Ledger seed with this script.
 */

const { BIP32Factory } = require('bip32')
const bip39 = require('bip39')
const ecc = require('tiny-secp256k1')
const crypto = require('crypto')

const bip32 = BIP32Factory(ecc)

function hash160(buf) {
  const sha256 = crypto.createHash('sha256').update(buf).digest()
  return crypto.createHash('ripemd160').update(sha256).digest()
}

function base58check(versionByte, payload) {
  // Minimal base58check for P2PKH address display. Not a dependency to keep the script tiny.
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  const versioned = Buffer.concat([Buffer.from([versionByte]), payload])
  const checksum = crypto
    .createHash('sha256')
    .update(crypto.createHash('sha256').update(versioned).digest())
    .digest()
    .subarray(0, 4)
  const full = Buffer.concat([versioned, checksum])

  let x = BigInt('0x' + full.toString('hex'))
  let out = ''
  while (x > 0n) {
    out = ALPHABET[Number(x % 58n)] + out
    x = x / 58n
  }
  // preserve leading zero bytes as '1'
  for (const b of full) {
    if (b === 0) out = '1' + out
    else break
  }
  return out
}

function derive(seed, path) {
  const root = bip32.fromSeed(seed)
  const node = root.derivePath(path)
  const pubkey = Buffer.from(node.publicKey)
  const pkh = hash160(pubkey)
  const addrRadiant = base58check(0x00, pkh) // P2PKH version byte 0 (same as BTC mainnet)
  return { path, pubkey: pubkey.toString('hex'), pkh: pkh.toString('hex'), address: addrRadiant }
}

function main() {
  const mnemonic = process.argv[2]
  if (!mnemonic) {
    console.error('Usage: node task-0.1-derivation-crosscheck.js "<BIP39 mnemonic>"')
    console.error('\nUse a TEST seed. Never pass your real Ledger seed to this script.\n')
    process.exit(1)
  }
  if (!bip39.validateMnemonic(mnemonic)) {
    console.error('ERROR: mnemonic failed BIP39 validation.')
    process.exit(1)
  }
  const seed = bip39.mnemonicToSeedSync(mnemonic)

  const paths = [
    "m/44'/0'/0'/0/0",   // what stock Ledger Bitcoin app + Electron Radiant currently use
    "m/44'/512'/0'/0/0", // what the Radiant Ledger app will use in v1
  ]

  console.log('Task 0.1 — Derivation cross-check\n')
  console.log('Seed:', mnemonic.split(' ').length, 'words (not printing for security)')
  console.log('')
  console.log('Path'.padEnd(24), 'Address'.padEnd(36), 'PKH')
  console.log('-'.repeat(24), '-'.repeat(36), '-'.repeat(40))
  for (const p of paths) {
    const r = derive(seed, p)
    console.log(p.padEnd(24), r.address.padEnd(36), r.pkh)
  }
  console.log('')
  console.log('Verification steps:')
  console.log('  1. Install stock Ledger Bitcoin app on your Nano S Plus with this seed.')
  console.log('  2. In Ledger Live / an Electron-family wallet, view receive address at m/44\'/0\'/0\'/0/0.')
  console.log('  3. It should match the 44\'/0\' row above exactly.')
  console.log('  4. The 44\'/512\' row is what our new Radiant app will derive. Different address, same math.')
  console.log('')
  console.log('If step 3 matches: BIP32/BIP44 derivation is as expected. Task 0.1 PASS.')
  console.log('If step 3 does not match: STOP — there is a BIP32 divergence we need to understand before writing C.')
}

main()
