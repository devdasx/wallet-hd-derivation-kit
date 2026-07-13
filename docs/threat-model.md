---
layout: default
title: Threat model
description: Assets, trust boundaries, attacker capabilities, mitigations and non-goals for Wallet HD Derivation Kit.
permalink: /threat-model/
---

# Threat model

## Assets and boundaries

Mnemonics, passphrases, seeds, private keys, and extended private keys are spend-authorizing secrets. Extended public keys and address batches are privacy-sensitive metadata. The library boundary begins with caller-supplied bytes and ends with a deterministic result; storage, process isolation, UI capture, clipboard, logs, and transport belong to the host application.

## Considered attackers

- Malformed paths, extended keys, encodings, and chain identifiers intended to trigger acceptance bugs, crashes, overflow, or excessive work.
- Dependency or release-supply-chain compromise.
- Accidental secret disclosure through normal serialization or CLI arguments.
- Cross-language implementation drift producing a valid-looking but wrong address.

## Mitigations

Strict bounds/checksums, maintained curve libraries, explicit chain context, no hardened xpub derivation, no Solana public derivation, bounded batches, private-only APIs, hidden/permission-checked CLI input, exact dependencies, signed tagged releases, SBOMs/attestations, fuzzing, public vectors, and seven-runtime differential conformance.

## Non-goals

Protection from a compromised host, malicious caller, side-channel-capable co-tenant, exposed process memory, insecure backups, weak passphrases, clipboard capture, or incorrect transaction-signing policy is outside this package. High-value systems should use independently audited hardware-backed key isolation.
