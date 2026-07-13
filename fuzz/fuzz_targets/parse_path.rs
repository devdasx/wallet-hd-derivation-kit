#![no_main]

use libfuzzer_sys::fuzz_target;
use wallet_hd_derivation_kit::parse_path;

fuzz_target!(|data: &[u8]| {
    if let Ok(path) = std::str::from_utf8(data) {
        let _ = parse_path(path);
    }
});
