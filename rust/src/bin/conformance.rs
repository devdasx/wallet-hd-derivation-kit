use std::collections::BTreeMap;
use wallet_hd_derivation_kit::{derive_address, DeriveOptions, Source, CHAINS};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let source = Source::mnemonic(words, "");
    let values = CHAINS
        .iter()
        .map(|chain| {
            let value = derive_address(
                &source,
                DeriveOptions {
                    chain: chain.id,
                    ..Default::default()
                },
            )?;
            Ok((chain.id, value.address))
        })
        .collect::<Result<BTreeMap<_, _>, wallet_hd_derivation_kit::HdError>>()?;
    println!("WALLETHD_CONFORMANCE={}", serde_json::to_string(&values)?);
    Ok(())
}
