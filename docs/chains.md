---
layout: default
title: Supported HD wallet chains and standards
description: Verified chain matrix, derivation paths, address formats, and extended-key standards boundaries.
permalink: /chains/
---

# Supported chains

The authoritative matrix is [`spec/chains.json`](https://github.com/devdasx/wallet-hd-derivation-kit/blob/main/spec/chains.json). Bitcoin supports BIP-44/49/84/86 and registered SLIP-0132 formats. Litecoin supports registered Ltub/Ltpv and Mtub/Mtpv; no unregistered native-SegWit prefix is invented. Dogecoin, Dash, DigiByte, BCH, and Zcash support their listed BIP-44 transparent address formats. EVM networks use EIP-55, TRON uses Base58Check, and Solana uses hardened SLIP-0010 Ed25519.

An extended-key version does not uniquely identify every chain. Address derivation from an xpub therefore requires an explicit chain. Solana has no xpub or public child derivation.
