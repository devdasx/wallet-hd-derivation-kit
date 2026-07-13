---
layout: default
title: Migration from hd-extended-key-kit
description: Move from the legacy JavaScript-only hd-extended-key-kit package to Wallet HD Derivation Kit.
permalink: /migration/
---

# Migrate from `hd-extended-key-kit`

Replace the dependency with `wallet-hd-derivation-kit`, import the equivalent camelCase API, and pass an explicit `chain` when deriving an address from an extended public key. Validate results against your existing known addresses before deployment. The old repository remains read-only to preserve history and releases; this repository is the canonical maintained source.
