---
layout: default
title: Swift HD wallet derivation
description: Install WalletHDDerivationKit with Swift Package Manager or CocoaPods and derive verified Bitcoin, EVM, TRON, and Solana addresses offline.
permalink: /swift/
---

# Swift

Swift Package Manager requires Swift tools 6.2 or newer. In Xcode add `https://github.com/devdasx/wallet-hd-derivation-kit` from `1.0.0`, or add `.package(url: "https://github.com/devdasx/wallet-hd-derivation-kit.git", from: "1.0.0")`. CocoaPods users add `pod 'WalletHDDerivationKit', '~> 1.0'`.

```swift
import WalletHDDerivationKit

let words = ProcessInfo.processInfo.environment["WALLET_MNEMONIC"]!
let result = try WalletHDDerivationKit.deriveAddress(
    source: .mnemonic(words), chain: .bitcoin, scriptType: .p2wpkh
)
print(result.address)
```

`deriveAccountPrivateKey` is the explicit secret-export API. Normal result types are `Codable` and contain no private field. [Runnable example](https://github.com/devdasx/wallet-hd-derivation-kit/tree/main/examples/swift).
