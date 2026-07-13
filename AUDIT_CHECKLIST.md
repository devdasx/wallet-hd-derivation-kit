# Public audit checklist

- [ ] Match every BIP-32 official vector, including leading-zero cases.
- [ ] Match BIP-39 NFKD/Unicode and invalid-checksum vectors.
- [ ] Match SLIP-0010 Ed25519, SLIP-0132, and BIP-86 vectors.
- [ ] Review Base58Check, Bech32/Bech32m, CashAddr, EIP-55, TRON, and Solana encoders.
- [ ] Prove non-hardened private/public child equivalence.
- [ ] Reject hardened xpub children, malformed paths, overflow, bad checksums, and invalid seed lengths.
- [ ] Confirm normal result serialization contains no private field.
- [ ] Reproduce all seven-language conformance outputs from a clean checkout.
- [ ] Run fuzzers, dependency audits, SAST, and network-disabled examples.
- [ ] Match release checksums, SBOM, provenance, and GitHub tag commit.
- [ ] Record reviewer, date, commit SHA, tool versions, findings, and remediation.

An internal checklist is not an independent security audit.
