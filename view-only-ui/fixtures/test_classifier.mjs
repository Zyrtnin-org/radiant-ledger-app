#!/usr/bin/env node
/**
 * Golden-vector test runner for the Glyph script classifier.
 *
 * Mirrors ../../scripts/test_oracle_against_vectors.py in spirit — any change
 * to classifier.mjs must keep every vector passing.
 *
 *   node fixtures/test_classifier.mjs          # run all vectors
 *   node fixtures/test_classifier.mjs --verbose
 *
 * Exit 0 = all pass. Nonzero = at least one regression.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { classify, buildFtSpk, buildNftSpk, refToOutpoint } from "../classifier.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(__dirname, "classifier-vectors.json"), "utf8"));

const GREEN = "\x1b[32m", RED = "\x1b[31m", DIM = "\x1b[2m", END = "\x1b[0m";
const verbose = process.argv.includes("--verbose");

let pass = 0, fail = 0;
for (const v of vectors.vectors) {
  if (v.skip) { continue; }
  const got = classify(v.spk_hex);
  const exp = v.expected;
  const errors = [];
  if (got.type !== exp.type) errors.push(`type: expected ${exp.type}, got ${got.type}`);
  if (exp.pkh !== undefined && got.pkh !== exp.pkh) errors.push(`pkh: expected ${exp.pkh}, got ${got.pkh}`);
  if (exp.ref !== undefined && got.ref !== exp.ref) errors.push(`ref: expected ${exp.ref}, got ${got.ref}`);

  if (errors.length === 0) {
    pass++;
    if (verbose) console.log(`${GREEN}✓${END} ${v.name}  ${DIM}(${got.type})${END}`);
  } else {
    fail++;
    console.log(`${RED}✗${END} ${v.name}`);
    console.log(`  ${DIM}source: ${v.source}${END}`);
    for (const e of errors) console.log(`  ${RED}${e}${END}`);
  }
}

// Round-trip tests: build FT/NFT spks from (pkh, ref) and confirm classify() round-trips.
console.log("\n--- round-trip builders ---");
const testPkh = "32e092994ebdf8db0861b0e9208878c4221c4721";
const testRef = "8b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000";

for (const [label, builder, type] of [
  ["buildFtSpk",  buildFtSpk,  "ft"],
  ["buildNftSpk", buildNftSpk, "nft"],
]) {
  const spk = builder(testPkh, testRef);
  const r = classify(spk);
  if (r.type === type && r.pkh === testPkh && r.ref === testRef) {
    pass++;
    if (verbose) console.log(`${GREEN}✓${END} ${label} round-trip`);
  } else {
    fail++;
    console.log(`${RED}✗${END} ${label} round-trip — got ${JSON.stringify(r)}`);
  }
}

// refToOutpoint sanity: ref from the dominant FT token decodes to a txid shape.
const outpoint = refToOutpoint(testRef);
if (/^[0-9a-f]{64}$/.test(outpoint.txid) && outpoint.vout === 0) {
  pass++;
  if (verbose) console.log(`${GREEN}✓${END} refToOutpoint → ${outpoint.txid}:${outpoint.vout}`);
} else {
  fail++;
  console.log(`${RED}✗${END} refToOutpoint → unexpected ${JSON.stringify(outpoint)}`);
}

// --- XSS / MIME regression: assert index.html's SAFE_IMG_MIMES never includes
// SVG and that detectImageMime does not emit SVG. A loosened allowlist here
// would let attacker-minted glyphs embed <svg onload=...> and XSS viewers.
console.log("\n--- MIME allowlist regression ---");
const indexHtml = readFileSync(join(__dirname, "..", "index.html"), "utf8");
{
  const m = indexHtml.match(/SAFE_IMG_MIMES\s*=\s*new Set\(\[([^\]]+)\]/);
  if (!m) {
    fail++;
    console.log(`${RED}✗${END} could not find SAFE_IMG_MIMES definition — did the name change?`);
  } else {
    const listed = m[1];
    if (/image\/svg/i.test(listed)) {
      fail++;
      console.log(`${RED}✗${END} SAFE_IMG_MIMES contains image/svg+xml — XSS regression`);
    } else {
      pass++;
      if (verbose) console.log(`${GREEN}✓${END} SAFE_IMG_MIMES excludes SVG`);
    }
  }
}
// Ensure detectImageMime never returns image/svg for an SVG byte sequence.
{
  if (/return\s+["']image\/svg/i.test(indexHtml)) {
    fail++;
    console.log(`${RED}✗${END} detectImageMime emits image/svg — XSS regression`);
  } else {
    pass++;
    if (verbose) console.log(`${GREEN}✓${END} detectImageMime does not emit image/svg`);
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
