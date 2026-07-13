# Private-material handling

1. Prefer watch-only xpub derivation when private keys are unnecessary.
2. Read mnemonics from a hidden prompt, protected secret store, or file with owner-only permissions. Never pass secrets in command arguments, URLs, logs, crash reports, environment dumps, or source control.
3. Keep private results in the smallest possible scope. Normal address/account-public APIs deliberately omit them.
4. Clear mutable buffers where the host language permits it. Garbage-collected strings and copied values cannot be reliably zeroized.
5. Never use the published example mnemonic for funds; it is public and compromised by design.
6. Treat an xprv/zprv/yprv, seed, or mnemonic as authority over all descendant funds. Treat an xpub as sensitive wallet metadata even though it cannot spend.
7. Use hardware-backed signing and independently audited key storage for high-value production systems.
