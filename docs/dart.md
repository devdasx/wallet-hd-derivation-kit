---
layout: default
title: Dart HD wallet derivation
description: Install wallet_hd_derivation_kit from pub.dev for pure Dart BIP32, SLIP10 and multi-chain addresses.
permalink: /dart/
---

# Dart

```sh
dart pub add wallet_hd_derivation_kit
```

```dart
final result = deriveAddress(
  source: {'mnemonic': Platform.environment['WALLET_MNEMONIC']!},
  chain: 'bitcoin-cash',
);
print(result['address']);
```

The library is pure Dart and shares the same public API with the Flutter package. [Runnable example](https://github.com/devdasx/wallet-hd-derivation-kit/tree/main/examples/dart).
