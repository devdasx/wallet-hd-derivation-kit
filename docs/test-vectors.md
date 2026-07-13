---
layout: default
title: Public HD wallet test vectors
description: Reproducible BIP32, BIP39, BIP86, SLIP10, SLIP132 and multi-chain address vectors.
permalink: /test-vectors/
---

# Public test vectors

The versioned [`test-vectors`](https://github.com/devdasx/wallet-hd-derivation-kit/tree/main/test-vectors) directory is the machine-readable v1 collection. It contains only published, permanently compromised test material:

- `bip32-official.json`: every valid BIP-32 vector 1–4, both leading-zero cases, and every invalid extended key from vector 5.
- `slip10-ed25519-official.json`: the complete first Ed25519 SLIP-0010 derivation chain.
- `public-vectors.json`: BIP-39, BIP-86, SLIP-0132, and verified addresses for all 18 v1 chains.

`npm run conformance` feeds the 18-chain cases to Swift, JavaScript, Python, Rust, Go, Dart, and Kotlin and fails on any disagreement. Every native extended-key parser consumes the shared BIP-32 invalid-key collection. JavaScript and Rust independently reproduce all BIP-32 and SLIP-0010 nodes, while `wallethd vectors verify` checks the complete collection in the release CLI.

BIP-39 mnemonic and passphrase processing uses Unicode NFKD normalization. The Go suite includes an explicit composed/decomposed passphrase equivalence regression test; the other runtimes delegate this requirement to their pinned BIP-39 primitives.

Never replace test material with a real wallet secret. New vectors require a standards citation or an independently reproduced reference output.
