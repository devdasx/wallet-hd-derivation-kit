---
layout: default
title: wallethd CLI installation and usage
description: Install the offline wallethd CLI with Homebrew, Cargo, shell, PowerShell, release binaries, or GHCR.
permalink: /cli/
---

# `wallethd` CLI

Install with Homebrew (`brew install devdasx/crypto-kits/wallethd`), Cargo (`cargo install wallet-hd-derivation-kit --version 1.0.0 --locked`), or the checksum-verifying installers in the repository.

```sh
wallethd address --chain bitcoin --prompt --pretty
printf '%s\n' "$WALLET_MNEMONIC" | wallethd addresses --chain ethereum --count 5 --mnemonic-stdin
wallethd from-xpub --chain bitcoin --extended-public-key "$ZPUB" --index 10
wallethd vectors verify
wallethd completion zsh > ~/.zfunc/_wallethd
```

Private output is off by default and requires `--show-secrets`. Mnemonics, seeds, and passphrases are never accepted as command-line values. Use `--prompt`, a `--*-stdin` source, or a `--*-file` source; secret files must be mode `0600` or stricter on Unix. A non-empty mnemonic passphrase comes from the hidden prompt or `--passphrase-file`. The stable JSON output schema is [schema v1](../schema/v1.json).

Exit code `0` means success. Exit code `2` means invalid usage, rejected secret input, derivation failure, or vector-verification failure; diagnostics go to stderr.
