#!/bin/sh
set -eu
MNEMONIC='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
printf '%s\n' "$MNEMONIC" | wallethd address --chain bitcoin --mnemonic-stdin --pretty
wallethd demo --chain solana
