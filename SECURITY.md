# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private vulnerability reporting at `Security → Advisories → Report a vulnerability` in the canonical repository. If that surface is unavailable, email `devdas98x@gmail.com` with the subject `SECURITY: wallet-hd-derivation-kit` and avoid attaching real keys, mnemonics, seeds, or wallet data.

ROYO STUDIOS will acknowledge a complete report within 72 hours, investigate privately, coordinate a fix and disclosure date, and credit the reporter unless anonymity is requested. No bounty is promised.

## Supported versions

| Version | Security fixes |
|---|---|
| 1.x latest | Yes |
| Older 1.x | Upgrade required |
| Pre-1.0 | No |

## Security status

- The project is offline-only at runtime and has no telemetry, RPC, balance lookup, analytics, or update check.
- Private material is returned only by explicitly named private APIs or CLI `--show-secrets`.
- The repository uses public vectors, differential conformance, dependency audits, fuzz/property tests, CodeQL, Scorecard, SBOMs, checksums, and release attestations.
- The software has **not** received an independent third-party security audit. Do not describe it as audited.
- This library derives keys; it does not provide secure storage, signing policy, hardware-wallet isolation, backup, recovery, or transaction validation.

Read the [threat model](docs/threat-model.md), [private-material guide](PRIVATE_MATERIAL.md), and [public audit checklist](AUDIT_CHECKLIST.md) before production use.
