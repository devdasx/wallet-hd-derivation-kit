# Wallet HD Derivation Kit

[![CI](https://github.com/devdasx/wallet-hd-derivation-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/devdasx/wallet-hd-derivation-kit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/devdasx/wallet-hd-derivation-kit)](https://github.com/devdasx/wallet-hd-derivation-kit/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen)](https://github.com/devdasx/wallet-hd-derivation-kit/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/devdasx/wallet-hd-derivation-kit/badge)](https://securityscorecards.dev/viewer/?uri=github.com/devdasx/wallet-hd-derivation-kit)
[![Security policy](https://img.shields.io/badge/security-policy-green.svg)](SECURITY.md)
[![Swift Package Index](https://img.shields.io/badge/Swift_Package_Index-compatible-orange)](https://swiftpackageindex.com/devdasx/wallet-hd-derivation-kit)
[![CocoaPods](https://img.shields.io/cocoapods/v/WalletHDDerivationKit.svg)](https://cocoapods.org/pods/WalletHDDerivationKit)
[![Homebrew](https://img.shields.io/badge/Homebrew-devdasx%2Fcrypto--kits-orange)](https://github.com/devdasx/homebrew-crypto-kits)
[![npm](https://img.shields.io/npm/v/wallet-hd-derivation-kit)](https://www.npmjs.com/package/wallet-hd-derivation-kit)
[![JSR](https://jsr.io/badges/@devdasx/wallet-hd)](https://jsr.io/@devdasx/wallet-hd)
[![PyPI](https://img.shields.io/pypi/v/wallet-hd-derivation-kit)](https://pypi.org/project/wallet-hd-derivation-kit/)
[![crates.io](https://img.shields.io/crates/v/wallet-hd-derivation-kit)](https://crates.io/crates/wallet-hd-derivation-kit)
[![docs.rs](https://docs.rs/wallet-hd-derivation-kit/badge.svg)](https://docs.rs/wallet-hd-derivation-kit)
[![Go Reference](https://pkg.go.dev/badge/github.com/devdasx/wallet-hd-derivation-kit.svg)](https://pkg.go.dev/github.com/devdasx/wallet-hd-derivation-kit)
[![pub.dev](https://img.shields.io/pub/v/wallet_hd_derivation_kit)](https://pub.dev/packages/wallet_hd_derivation_kit)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.devdasx/wallet-hd-derivation-kit)](https://central.sonatype.com/artifact/io.github.devdasx/wallet-hd-derivation-kit)
[![JitPack](https://jitpack.io/v/devdasx/wallet-hd-derivation-kit.svg)](https://jitpack.io/#devdasx/wallet-hd-derivation-kit/v1.0.0)
[![GitHub Packages](https://img.shields.io/badge/GitHub_Packages-%40devdasx%2Fwallet--hd--derivation--kit-181717)](https://github.com/devdasx/wallet-hd-derivation-kit/pkgs/npm/wallet-hd-derivation-kit)

Production-oriented, offline HD-wallet derivation for Swift, JavaScript, React Native, Python, Rust, Go, Dart/Flutter, Kotlin/JVM/Android, and the `wallethd` CLI. Every implementation is native to its language and checked against the same public vectors.

> Security: derivation is deterministic, but secret handling is your responsibility. Never paste a real mnemonic into source code, logs, analytics, issue reports, or an online playground. This project has not yet received an independent third-party audit.

## 30-second start

JavaScript:

```sh
npm install wallet-hd-derivation-kit
```

```js
import { deriveAddress } from "wallet-hd-derivation-kit";

const result = deriveAddress({
  source: { mnemonic: process.env.WALLET_MNEMONIC },
  chain: "bitcoin",
});
console.log(result.address); // private material is not in this result
```

CLI:

```sh
brew install devdasx/crypto-kits/wallethd
wallethd address --chain bitcoin --prompt --pretty
```

The CLI reads mnemonic/seed material through a hidden prompt, stdin, or a permission-checked file. Mnemonics, seeds, and passphrases are never accepted as command-line values. Private output requires `--show-secrets`.

## Install

| Platform | Command |
|---|---|
| Swift Package Manager | `.package(url: "https://github.com/devdasx/wallet-hd-derivation-kit.git", from: "1.0.0")` |
| CocoaPods | `pod 'WalletHDDerivationKit', '~> 1.0'` |
| npm | `npm install wallet-hd-derivation-kit` |
| GitHub npm | `npm install @devdasx/wallet-hd-derivation-kit` |
| JSR | `deno add jsr:@devdasx/wallet-hd` |
| Python | `python -m pip install wallet-hd-derivation-kit` |
| Rust | `cargo add wallet-hd-derivation-kit` |
| Go | `go get github.com/devdasx/wallet-hd-derivation-kit@v1.0.0` |
| Dart / Flutter | `dart pub add wallet_hd_derivation_kit` / `flutter pub add wallet_hd_derivation_kit` |
| Kotlin / Android | `implementation("io.github.devdasx:wallet-hd-derivation-kit:1.0.0")` |
| Homebrew CLI | `brew install devdasx/crypto-kits/wallethd` |
| Cargo CLI | `cargo install wallet-hd-derivation-kit --version 1.0.0 --locked` |
| Shell installer | `curl -fsSL https://raw.githubusercontent.com/devdasx/wallet-hd-derivation-kit/v1.0.0/install.sh \| sh` |
| Container | `docker run --rm ghcr.io/devdasx/wallethd:1.0.0 list-chains` |

Swift Package Manager requires Swift tools 6.2 or newer. CocoaPods consumers compile the same Swift sources with the toolchain selected by their application.

See the verified examples for [Swift](docs/swift.md), [JavaScript](docs/javascript.md), [React Native](docs/react-native.md), [Python](docs/python.md), [Rust](docs/rust.md), [Go](docs/go.md), [Dart](docs/dart.md), [Flutter](docs/flutter.md), [Kotlin](docs/kotlin.md), and [CLI](docs/cli.md).

## Supported chains

| Family | Chains and behavior |
|---|---|
| Bitcoin | Mainnet/testnet BIP-44/49/84/86; P2PKH, nested/native SegWit, Taproot; x/y/z/t/u/v pub/prv |
| Litecoin | BIP-44/49, Ltub/Ltpv and Mtub/Mtpv; native SegWit addresses may be derived from seed without inventing a prefix |
| UTXO BIP-44 | Dogecoin, Dash, DigiByte, Bitcoin Cash CashAddr, Zcash transparent |
| EVM | Ethereum, Ethereum Classic, Polygon, BNB Smart Chain, Avalanche C-Chain, Arbitrum, Optimism, Base; EIP-55 |
| TRON | BIP-44 coin type 195 and Base58Check `T…` addresses |
| Solana | Hardened SLIP-0010 Ed25519 and Base58 public-key addresses |

The machine-readable matrix is [spec/chains.json](spec/chains.json). Cardano, Substrate, Cosmos, Stellar, NEAR, and XRP are intentionally not advertised in v1 because their chain-specific derivation rules require separate work.

### Standards boundary

`xpub`, `ypub`, and `zpub` are Bitcoin-style BIP-32/SLIP-0132 serialized keys, not universal chain formats. Generic secp256k1 extended keys require an explicit chain when deriving an address because version bytes do not identify every coin. Solana uses hardened SLIP-0010 Ed25519 and has neither a BIP-32 xpub nor public child derivation.

## Public API

Each language provides idiomatic equivalents of:

```text
deriveNode(source, curve, path)
deriveAccountPublicKey(source, chain, scriptType, account)
deriveAccountPrivateKey(...)
deriveAddress(source, chain, account, change, index, scriptType)
deriveAddresses(..., start, count)
deriveAddressFromExtendedPublicKey(...)
parseExtendedKey(...)
serializeExtendedKey(...)
supportedChains()
```

`source` is a checksum-validated English BIP-39 mnemonic plus optional passphrase, or a 16–64 byte seed. Paths must be absolute and may use `'`, `h`, or `H` for hardened components. Normal result serialization excludes private data; private key exports are available only from explicitly named private APIs.

## CLI

```text
wallethd account       Derive an account xpub; --show-secrets selects private output
wallethd address       Derive one address
wallethd addresses     Derive a bounded batch
wallethd from-xpub     Derive watch-only addresses
wallethd derive-path   Derive an explicit path
wallethd inspect-key   Parse an extended key
wallethd list-chains   Print machine-readable chain support
wallethd vectors verify
wallethd demo          Run only published test vectors
wallethd completion    Generate shell completions
wallethd version
```

Successful data commands emit JSON schema v1 and exit `0`. Any usage, secret-input, verification, or derivation failure exits `2` and writes a concise error to stderr. The CLI makes no telemetry, RPC, balance, update-check, or other network request.

## Correctness and trust

- Seven native implementations agree on all 18 default chain vectors in `npm run conformance`.
- Tests cover watch-only public derivation, public/private child equivalence, BIP-86, SLIP-0132, malformed paths, invalid checksums, batch limits, and serialization round trips.
- Public vectors live in the versioned [test-vectors](test-vectors/) collection, including every official BIP-32 valid/invalid vector and the SLIP-0010 Ed25519 chain.
- Dependency choices and exact pins are documented in [DEPENDENCIES.md](DEPENDENCIES.md).
- Threats, non-goals, secret boundaries, fuzzing, and audit status are documented in [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).
- No API performs runtime network I/O. See [OFFLINE.md](OFFLINE.md).

## Source of truth and releases

GitHub is the only source repository. Registry packages are immutable builds of signed `vX.Y.Z` tags; registry copies are never edited independently. A merge to `main` redeploys documentation. Release jobs are separately rerunnable and skip versions that already exist.

Repository: <https://github.com/devdasx/wallet-hd-derivation-kit>

Documentation: <https://devdasx.github.io/wallet-hd-derivation-kit/>

Changelog: [CHANGELOG.md](CHANGELOG.md)

Security policy: [SECURITY.md](SECURITY.md)

MIT © ROYO STUDIOS.
