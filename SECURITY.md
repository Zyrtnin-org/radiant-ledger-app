# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in radiant-ledger-app, please report it
**privately** rather than filing a public GitHub issue.

Send disclosure to: **security@mudwoodlabs.com**

Alternatively, use GitHub's private vulnerability reporting:
<https://github.com/MudwoodLabs/radiant-ledger-app/security/advisories/new>

Include:

- A description of the issue and its impact
- Reproduction steps or a proof-of-concept
- Affected versions / components (scripts, view-only-ui)
- Your name / handle for credit (optional — anonymous reports accepted)

We aim to:

- Acknowledge receipt within **2 business days**
- Provide an initial assessment within **7 business days**
- Coordinate a fix and disclosure timeline based on severity, typically
  within **90 days** following Google Project Zero norms

## Scope

Security reports are welcome on:

- Key derivation or signing logic in the helper scripts (`/scripts/`)
- Oracle validation logic and preimage handling (`radiant_preimage_oracle.py`)
- Any code that handles private keys, seeds, or signs transactions

Out of scope:

- Vulnerabilities in dependencies (please report to the upstream project)
- Social-engineering attacks against users or maintainers
- Issues requiring physical access to a victim's device
- Issues already documented in the public CHANGELOG or issue tracker

## Status

This is a **hardware-wallet planning and validation repository**, not a
production deployment tool. It is not intended for mainnet use without
independent security review. Use at your own risk.

## Disclosure

We ask for 90 days to fix before public disclosure. If we haven't
responded within 14 days, feel free to escalate by any public channel.
