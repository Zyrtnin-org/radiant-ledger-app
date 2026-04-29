# Changelog

Notable changes to this repository (the planning + verification + view-only UI
side of the Radiant Ledger app). The Ledger device firmware itself has its own
changelog at https://github.com/MudwoodLabs/app-radiant.

## 2026-04-29

### Changed
- **Relicensed from MIT to Apache 2.0.** Aligns with the upstream
  `MudwoodLabs/app-radiant` firmware repo (Apache 2.0, inherited from
  LedgerHQ/app-bitcoin) and with Mudwood Labs' broader infrastructure-tier OSS
  posture. Apache 2.0 adds an explicit patent grant from contributors and a
  defensive termination clause that MIT lacks.
- **Repository transferred** from `Zyrtnin-org/radiant-ledger-app` to
  `MudwoodLabs/radiant-ledger-app`. GitHub auto-redirects the old URL.
- **README link targets updated** to `MudwoodLabs/...` for all sibling repos
  that were also moved (`app-radiant`, `lib-app-bitcoin`, `Electron-Wallet`).

### Added
- `NOTICE` file required by Apache 2.0 §4. Names Mudwood Labs as the copyright
  holder and identifies vendored MIT-licensed files (`view-only-ui/vendor/cbor.min.js`).
- `CHANGELOG.md` (this file).

### Notes for downstream users
- Apache 2.0 is permissively compatible with MIT. Anyone who pulled an old
  MIT-tagged commit retains MIT rights on that snapshot. Going forward, all
  releases are Apache 2.0.
- Vendored third-party code keeps its original license (MIT for cbor.min.js).
  Apache 2.0 explicitly permits incorporation of MIT-licensed work.
