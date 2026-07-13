# Agent instructions

The canonical source is `https://github.com/devdasx/wallet-hd-derivation-kit`. Never modify registry copies independently. Change behavior first in `spec/` and `test-vectors/`, update all seven native implementations, run `npm run conformance`, then update docs.

Private APIs must remain explicitly named. Never add network I/O, telemetry, remote configuration, real secrets, invented extended-key prefixes, unhardened Solana derivation, or a claim of independent audit. Preserve the schema version unless making a deliberate compatibility release.

Required pre-release commands are documented in `scripts/verify-all.sh`. A release is a signed `vX.Y.Z` tag whose manifests all contain the same version.
