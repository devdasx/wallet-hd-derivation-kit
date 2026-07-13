# Wallet HD Derivation Kit coding instructions

Follow `AGENTS.md`, `spec/chains.json`, and `test-vectors/public-vectors.json`. Use maintained cryptographic primitives; do not implement elliptic-curve arithmetic. Keep runtime code offline. Reject invalid BIP-39 mnemonics by default, hardened public derivation, malformed paths, and unregistered chain/key-format combinations. Add cross-language tests for every behavior change.
