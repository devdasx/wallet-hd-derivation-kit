---
layout: default
title: Launching Wallet HD Derivation Kit 1.0
description: Why ROYO STUDIOS built one offline HD-wallet derivation contract in seven native languages.
permalink: /launch/
---

# Launching Wallet HD Derivation Kit 1.0

Wallet derivation code often fragments by language: a path or address that looks right in one implementation can silently differ elsewhere. Wallet HD Derivation Kit makes a narrower promise: one documented v1 chain matrix, one public vector collection, and independent native Swift, JavaScript, Python, Rust, Go, Dart, and Kotlin implementations that must agree before release.

The package covers Bitcoin BIP-44/49/84/86 and registered SLIP-0132 formats, selected transparent UTXO chains, EIP-55 EVM networks, TRON, and hardened SLIP-0010 Solana. It does not pretend Bitcoin xpub formats are universal and does not advertise unsupported chain-specific schemes.

Trust work is part of the product: normal outputs omit secrets, the CLI requires deliberate secret input and private export, runtime networking is absent, parsers are fuzzed, dependencies are audited, and tagged releases carry checksums, SBOMs, signatures, and provenance. The project is not independently audited yet, and says so plainly.

Start with the [30-second examples](../), inspect the [vectors](../test-vectors/), and review the [security posture](../security/) before deciding whether it fits your system.
