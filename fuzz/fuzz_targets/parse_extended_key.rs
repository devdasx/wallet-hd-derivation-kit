#![no_main]

use libfuzzer_sys::fuzz_target;
use wallet_hd_derivation_kit::parse_extended_key;

fuzz_target!(|data: &[u8]| {
    if let Ok(serialized) = std::str::from_utf8(data) {
        let _ = parse_extended_key(serialized);
    }
});
