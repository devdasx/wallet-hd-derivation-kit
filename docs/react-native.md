---
layout: default
title: React Native HD wallet derivation
description: Use the pure JavaScript wallet HD derivation package from Metro without native FFI or subprocesses.
permalink: /react-native/
---

# React Native

```sh
npm install wallet-hd-derivation-kit
```

```ts
import { deriveAddress } from "wallet-hd-derivation-kit/react-native";
const address = deriveAddress({ source: { mnemonic }, chain: "solana" }).address;
```

No native module or linking step is required. Keep mnemonics in platform secure storage and out of component props, Redux logs, error reporting, and development tooling. [App example](https://github.com/devdasx/wallet-hd-derivation-kit/tree/main/examples/react-native).
