**🔗 Radiant Glyph: FT Guide + View-Only Renderer**

Two updates to the community Ledger + Glyph tooling:

**📖 radiant-glyph-guide — now covers Fungible Tokens**
- **FT holder template (75B)** decoded from 2,309 mainnet samples across 6 tokens — 100% template conformance
- **Wallet classifier regex** for P2PKH / NFT / FT — drop into Electron-Wallet to make Glyph UTXOs visible
- **Conservation mechanism** decoded from Radiant Core source: `OP_STATESEPARATOR` + `OP_CODESCRIPTHASHVALUESUM` enforce token supply invariants
- CID validation, V2 fee rates, infrastructure setup, and more

→ https://github.com/Zyrtnin-org/radiant-glyph-guide

**🔍 Glyph View-Only Renderer**
Browser tool that classifies + renders Glyph NFT/FT assets from chain data:
- Classifies scriptPubKeys as NFT singleton (63B), FT holder (75B), or P2PKH — 15/15 golden-vector tests
- Decodes CBOR metadata from reveal txs: name, ticker, protocol, embedded images
- Verified end-to-end: Glyph Protocol FT renders with on-chain PNG; FlipperHub NFTs with IPFS images
- Ledger compatible — standard `<sig> <pubkey>` signing, no firmware changes needed
- Security reviewed: 4-reviewer audit, HTML-escaped, no credential leaks

→ https://github.com/Zyrtnin-org/radiant-ledger-app (`view-only-ui/`)

**Why it matters:** These classifier patterns are the fix Electron-Wallet needs to show Glyph assets. Test the view-only tool now — clone, point at your address, see your tokens. Ledger Nano S Plus testers especially welcome.
