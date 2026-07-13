# Dependency policy

Dependencies are exact-pinned in registry manifests or locked to exact resolved versions in committed lockfiles. Dart publishes the ecosystem-recommended compatible constraint while `pubspec.lock` records the exact release-tested graph. Automated updates must pass every native test, the shared differential harness, clean-consumer packaging, audit workflows, and offline runtime checks.

Curve arithmetic is never implemented by this project. Swift Package Manager uses the maintained `secp256k1.swift` binding to Bitcoin Core secp256k1. CocoaPods uses the exact-pinned `secp256k1Wrapper` 0.0.5 source snapshot because the upstream 0.23.2 CocoaPods XCFramework omits its imported `libsecp256k1` module; the fallback calls only upstream C validation, public-key, serialization, and tweak APIs and is checked against the same public vectors. JavaScript uses Noble primitives; Python uses `bip-utils`; Rust uses `k256` and `ed25519-dalek`; Go uses `btcec/v2` and the standard Ed25519 package; Dart uses `blockchain_utils`; Kotlin uses Bouncy Castle. BIP-39 helpers are provided by pinned ecosystem packages.

New cryptographic dependencies require documented maintenance activity, license compatibility, reproducible public vectors, vulnerability review, and at least two independent implementations agreeing on output. Unreviewed dependency additions are release blockers.
