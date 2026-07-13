use wallet_hd_derivation_kit::{derive_address, DeriveOptions, Source};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let value = derive_address(
        &Source::mnemonic(words, ""),
        DeriveOptions { chain: "tron", ..Default::default() },
    )?;
    println!("{}", value.address);
    Ok(())
}
