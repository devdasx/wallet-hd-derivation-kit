---
layout: default
title: Security posture
description: Threat model, offline-only guarantee, private key boundaries, dependency policy, fuzzing and audit status.
permalink: /security/
---

# Security posture

The runtime is offline-only, normal APIs omit private material, public vectors are differential-tested in seven runtimes, dependency audits run weekly, and parsers/decoders are fuzzed. Releases include checksums, SBOMs, attestations, and signatures.

The package is not a key vault, signer, transaction validator, backup system, hardware-wallet boundary, or substitute for an independent audit. The project **has not yet been independently audited**.

Read [SECURITY.md](https://github.com/devdasx/wallet-hd-derivation-kit/blob/main/SECURITY.md), the [threat model](../threat-model/), [private-material guide](https://github.com/devdasx/wallet-hd-derivation-kit/blob/main/PRIVATE_MATERIAL.md), and [audit checklist](https://github.com/devdasx/wallet-hd-derivation-kit/blob/main/AUDIT_CHECKLIST.md).
