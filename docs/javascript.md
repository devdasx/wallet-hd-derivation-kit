---
layout: default
title: JavaScript and Node.js HD wallet derivation
description: Install wallet-hd-derivation-kit from npm, GitHub Packages, or JSR and derive addresses offline with pure ESM.
permalink: /javascript/
---

# JavaScript / Node.js

```sh
npm install wallet-hd-derivation-kit
```

```js
import { deriveAddress, deriveAccountPublicKey } from "wallet-hd-derivation-kit";
const source = { mnemonic: process.env.WALLET_MNEMONIC };
console.log(deriveAddress({ source, chain: "ethereum" }).address);
console.log(deriveAccountPublicKey({ source, chain: "bitcoin" }).extendedPublicKey);
```

The package is pure ESM for Node 20+, bundlers, Deno through JSR, and browsers with a deliberate local secret boundary. It has no network client. [Runnable example](https://github.com/devdasx/wallet-hd-derivation-kit/tree/main/examples/javascript).
