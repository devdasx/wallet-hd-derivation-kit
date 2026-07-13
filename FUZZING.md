# Fuzzing

Every pull request runs adversarial shared vectors through all seven native path/key/address implementations. Rust additionally runs property tests for arbitrary derivation-path strings and random public/private child equivalence. Rust `cargo-fuzz` targets exercise path parsing, extended-key parsing, and address derivation; Go fuzz targets independently exercise path and extended-key parsing. The longer Rust and Go campaigns run nightly with retained corpora. Crashes, hangs, panics, invalid-key acceptance, and public/private derivation disagreements fail the job.

The Rust harnesses are `parse_path`, `parse_extended_key`, and `derive_address`. Start one locally with `cargo install cargo-fuzz --version 0.13.2 && cargo fuzz run parse_path`. Start Go fuzzing with `go test -fuzz=Fuzz -fuzztime=60s ./...`. Never seed fuzz corpora with real secret material.
