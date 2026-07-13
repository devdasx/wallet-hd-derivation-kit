---
layout: default
title: Flutter HD wallet derivation
description: Use wallet_hd_derivation_kit on iOS, Android, desktop, and Flutter without platform FFI.
permalink: /flutter/
---

# Flutter

```sh
flutter pub add wallet_hd_derivation_kit
```

Call `deriveAddress(source: {'mnemonic': mnemonic}, chain: 'solana')` from a service or isolate. Do not keep real mnemonics in widget state, diagnostics, crash reports, screenshots, or source code. [Tested Flutter app](https://github.com/devdasx/wallet-hd-derivation-kit/tree/main/examples/flutter).
