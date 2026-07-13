---
layout: default
title: HD wallet derivation benchmarks
description: Reproducible account, address, batch, watch-only, extended-key, EVM, and Solana benchmark results.
permalink: /benchmarks/
---

# Benchmarks

Run `npm run benchmark` from a clean checkout. Results measure the JavaScript public API as a portable performance sentinel in scheduled CI. They are not cross-machine rankings and do not imply security.

<!-- BENCHMARK_RESULTS -->

Reference run: Apple M4 Max, macOS arm64, Node.js v26.5.0, 2026-07-13.

| Operation | Result |
|---|---:|
| BIP-39 mnemonic validation + seed | 181 ops/sec |
| Bitcoin account derivation | 155 ops/sec |
| One Bitcoin address | 148 ops/sec |
| 1,000 Bitcoin addresses | 6,611 ms/batch |
| xpub watch-only address | 1,684 ops/sec |
| Extended-key parsing | 17,647 ops/sec |
| One EVM address | 149 ops/sec |
| One Solana address | 178 ops/sec |

These figures include BIP-39 seed stretching in seed-based address operations. Watch-only and parse operations do not repeat mnemonic PBKDF2 work.

Nightly performance smoke tests run with `--check` and compare milliseconds per operation with the checked-in conservative regression ceilings. Those ceilings are at least 2× the observed baseline on the supported runner class, reducing flaky failures while catching large regressions.
