#![no_main]

use libfuzzer_sys::fuzz_target;
use wallet_hd_derivation_kit::{derive_address, supported_chains, DeriveOptions, Source};

fuzz_target!(|data: &[u8]| {
    if data.len() < 20 {
        return;
    }
    let seed_length = 16 + usize::from(data[0] % 49);
    if data.len() < seed_length + 5 {
        return;
    }
    let source = Source::Seed(data[1..=seed_length].to_vec());
    let chains = supported_chains();
    let selected = &chains[usize::from(data[seed_length + 1]) % chains.len()];
    let options = DeriveOptions {
        chain: selected.id,
        account: u32::from(data[seed_length + 2]) % 4,
        change: u32::from(data[seed_length + 3]) % 2,
        index: u32::from(data[seed_length + 4]) % 64,
        ..Default::default()
    };
    let _ = derive_address(&source, options);
});
