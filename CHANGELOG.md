# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and semantic versioning.

## [1.0.1] - 2026-07-13

### Fixed

- Pin the JitPack build to Java 17 and the committed Gradle 9.6.1 wrapper so the Kotlin/JVM artifact builds reproducibly instead of falling back to Gradle 6 and Java 8.
- Make JitPack use its requested `com.github.devdasx` coordinates and release version without changing Maven Central's canonical coordinates.
- Fail release discovery when JitPack reports a failed build instead of treating any API response as success.
- Replace the long-lived crates.io release secret with repository-, workflow-, and environment-bound OIDC trusted publishing.

## [1.0.0] - 2026-07-13

### Added

- Native Swift, JavaScript/React Native, Python, Rust, Go, Dart/Flutter, and Kotlin/JVM/Android libraries.
- Bitcoin BIP-44/49/84/86, SLIP-0132 keys, supported UTXO chains, EVM networks, TRON, and Solana SLIP-0010.
- Safe `wallethd` CLI, installers, Homebrew formula, release binaries, and GHCR image.
- Shared schema/vectors, seven-runtime differential conformance, examples, fuzzing, benchmarks, audits, security documentation, and release automation.

[1.0.1]: https://github.com/devdasx/wallet-hd-derivation-kit/releases/tag/v1.0.1
[1.0.0]: https://github.com/devdasx/wallet-hd-derivation-kit/releases/tag/v1.0.0
