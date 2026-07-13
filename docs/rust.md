---
layout: default
title: Rust HD wallet derivation
description: Add the wallet-hd-derivation-kit crate for native k256, Ed25519, BIP32, SLIP10 and multi-chain address derivation.
permalink: /rust/
---

# Rust

```sh
cargo add wallet-hd-derivation-kit@1.0.0
```

```rust
use wallet_hd_derivation_kit::{derive_address, DeriveOptions, Source};
let source = Source::mnemonic(std::env::var("WALLET_MNEMONIC")?, "");
let result = derive_address(&source, DeriveOptions { chain: "bitcoin", ..Default::default() })?;
println!("{}", result.address);
```

The same crate provides the `wallethd` binary. `Source` validation and bounded batch APIs return typed errors. [Runnable example](https://github.com/devdasx/wallet-hd-derivation-kit/tree/main/examples/rust).
