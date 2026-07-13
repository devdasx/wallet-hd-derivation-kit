use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
};
use wallet_hd_derivation_kit::{
    derive_account_private_key, derive_account_public_key, derive_address,
    derive_address_from_extended_public_key, derive_addresses, parse_extended_key, DeriveOptions,
    ExtendedPrivateKey, ParsedExtendedKey, Source, CHAINS,
};

const DEMO_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[derive(Parser)]
#[command(
    name = "wallethd",
    version,
    about = "Offline multi-chain HD wallet derivation"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Account(Common),
    Address(Common),
    Addresses {
        #[command(flatten)]
        common: Common,
        #[arg(long, default_value_t = 0)]
        start: u32,
        #[arg(long, default_value_t = 20)]
        count: u32,
    },
    FromXpub {
        #[arg(long)]
        chain: String,
        #[arg(long)]
        extended_public_key: String,
        #[arg(long, default_value_t = 0)]
        change: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
        #[arg(long)]
        script_type: Option<String>,
    },
    DerivePath(Common),
    InspectKey {
        extended_key: String,
    },
    ListChains,
    Vectors {
        #[arg(default_value = "verify")]
        action: String,
    },
    Demo {
        #[arg(long, default_value = "bitcoin")]
        chain: String,
        #[arg(long)]
        script_type: Option<String>,
    },
    Completion {
        shell: Shell,
    },
    Version,
}

#[derive(clap::Args, Default)]
struct Common {
    #[arg(long, default_value = "bitcoin")]
    chain: String,
    #[arg(long)]
    format: Option<String>,
    #[arg(long)]
    script_type: Option<String>,
    #[arg(long)]
    path: Option<String>,
    #[arg(long, default_value_t = 0)]
    account: u32,
    #[arg(long, default_value_t = 0)]
    change: u32,
    #[arg(long, default_value_t = 0)]
    index: u32,
    #[arg(long)]
    mnemonic_stdin: bool,
    #[arg(long)]
    mnemonic_file: Option<PathBuf>,
    #[arg(long)]
    seed_stdin: bool,
    #[arg(long)]
    seed_file: Option<PathBuf>,
    #[arg(long)]
    prompt: bool,
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
    #[arg(long)]
    show_secrets: bool,
    #[arg(long)]
    pretty: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Account(common) => {
            let source = source(&common)?;
            let options = options(&common);
            if common.show_secrets {
                print(
                    &derive_account_private_key(&source, options)?,
                    common.pretty,
                )?;
            } else {
                print(&derive_account_public_key(&source, options)?, common.pretty)?;
            }
        }
        Commands::Address(common) | Commands::DerivePath(common) => {
            let value = derive_address(&source(&common)?, options(&common))?;
            print(&value, common.pretty)?;
        }
        Commands::Addresses {
            common,
            start,
            count,
        } => {
            let value = derive_addresses(&source(&common)?, options(&common), start, count)?;
            print(&value, common.pretty)?;
        }
        Commands::FromXpub {
            chain,
            extended_public_key,
            change,
            index,
            script_type,
        } => print(
            &derive_address_from_extended_public_key(
                &extended_public_key,
                Some(&chain),
                change,
                index,
                script_type.as_deref(),
            )?,
            true,
        )?,
        Commands::InspectKey { extended_key } => match parse_extended_key(&extended_key)? {
            ParsedExtendedKey::Private(node, version) => print(
                &serde_json::json!({"schemaVersion":1,"kind":"private","version":format!("{version:08x}"),"depth":node.depth,"childNumber":node.child_number,"parentFingerprint":hex::encode(node.parent_fingerprint),"publicKeyHex":hex::encode(node.public_key())}),
                true,
            )?,
            ParsedExtendedKey::Public(node, version) => print(
                &serde_json::json!({"schemaVersion":1,"kind":"public","version":format!("{version:08x}"),"depth":node.depth,"childNumber":node.child_number,"parentFingerprint":hex::encode(node.parent_fingerprint),"publicKeyHex":hex::encode(node.public_key)}),
                true,
            )?,
        },
        Commands::ListChains => print(CHAINS, true)?,
        Commands::Vectors { action } => {
            if action != "verify" {
                return Err("only 'vectors verify' is supported".into());
            }
            verify_vectors()?;
        }
        Commands::Demo { chain, script_type } => print(
            &derive_address(
                &Source::mnemonic(DEMO_MNEMONIC, ""),
                DeriveOptions {
                    chain: &chain,
                    script_type: script_type.as_deref(),
                    ..Default::default()
                },
            )?,
            true,
        )?,
        Commands::Completion { shell } => {
            generate(shell, &mut Cli::command(), "wallethd", &mut io::stdout())
        }
        Commands::Version => println!("{}", env!("CARGO_PKG_VERSION")),
    }
    Ok(())
}

fn verify_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let bip32: serde_json::Value =
        serde_json::from_str(include_str!("../../test-vectors/bip32-official.json"))?;
    let mut bip32_nodes = 0;
    for vector in bip32["vectors"]
        .as_array()
        .ok_or("invalid BIP32 vector file")?
    {
        let seed = hex::decode(vector["seedHex"].as_str().ok_or("missing BIP32 seed")?)?;
        let root = ExtendedPrivateKey::master(&seed)?;
        for expected in vector["nodes"].as_array().ok_or("missing BIP32 nodes")? {
            let path = expected["path"].as_str().ok_or("missing BIP32 path")?;
            let node = root.derive_path(path)?;
            if node.serialize_public(0x0488_b21e)
                != expected["extendedPublicKey"]
                    .as_str()
                    .ok_or("missing xpub")?
                || node.serialize_private(0x0488_ade4)
                    != expected["extendedPrivateKey"]
                        .as_str()
                        .ok_or("missing xprv")?
            {
                return Err(format!("BIP32 vector mismatch at {path}").into());
            }
            bip32_nodes += 1;
        }
    }
    let invalid = bip32["invalidExtendedKeys"]
        .as_array()
        .ok_or("missing invalid BIP32 vectors")?;
    for expected in invalid {
        if parse_extended_key(expected["value"].as_str().ok_or("missing invalid key")?).is_ok() {
            return Err(format!("accepted invalid BIP32 key: {}", expected["reason"]).into());
        }
    }

    let slip10: serde_json::Value = serde_json::from_str(include_str!(
        "../../test-vectors/slip10-ed25519-official.json"
    ))?;
    let slip_source = Source::Seed(hex::decode(
        slip10["seedHex"].as_str().ok_or("missing SLIP10 seed")?,
    )?);
    let mut slip10_nodes = 0;
    for expected in slip10["nodes"].as_array().ok_or("missing SLIP10 nodes")? {
        let path = expected["path"].as_str().ok_or("missing SLIP10 path")?;
        let node = wallet_hd_derivation_kit::derive_node(&slip_source, "ed25519", path)?;
        let secret = derive_account_private_key(
            &slip_source,
            DeriveOptions {
                chain: "solana",
                path: Some(path),
                ..Default::default()
            },
        )?;
        if node.chain_code_hex != expected["chainCodeHex"]
            || node.public_key_hex != expected["publicKeyHex"]
            || secret.private_key_hex != expected["privateKeyHex"]
        {
            return Err(format!("SLIP10 vector mismatch at {path}").into());
        }
        slip10_nodes += 1;
    }

    let public: serde_json::Value =
        serde_json::from_str(include_str!("../../test-vectors/public-vectors.json"))?;
    let mnemonic = public["source"]["mnemonic"]
        .as_str()
        .ok_or("missing public-vector mnemonic")?;
    let public_source = Source::mnemonic(mnemonic, "");
    let addresses = public["addresses"]
        .as_array()
        .ok_or("missing public address vectors")?;
    for expected in addresses {
        let chain = expected["chain"].as_str().ok_or("missing vector chain")?;
        let path = expected["path"].as_str().ok_or("missing vector path")?;
        let script_type = expected["scriptType"]
            .as_str()
            .ok_or("missing script type")?;
        let value = derive_address(
            &public_source,
            DeriveOptions {
                chain,
                path: Some(path),
                script_type: Some(script_type),
                ..Default::default()
            },
        )?;
        if value.address != expected["address"].as_str().ok_or("missing address")? {
            return Err(format!("address vector mismatch for {chain}").into());
        }
    }
    println!(
        "verified: {bip32_nodes} BIP32 nodes, {} invalid keys, {slip10_nodes} SLIP10 nodes, {} chain addresses",
        invalid.len(),
        addresses.len()
    );
    Ok(())
}

fn source(common: &Common) -> Result<Source, Box<dyn std::error::Error>> {
    let source_count = [
        common.prompt,
        common.mnemonic_stdin,
        common.mnemonic_file.is_some(),
        common.seed_stdin,
        common.seed_file.is_some(),
    ]
    .into_iter()
    .filter(|selected| *selected)
    .count();
    if source_count != 1 {
        return Err("select exactly one secret source: --prompt, --mnemonic-stdin, --mnemonic-file, --seed-stdin, or --seed-file".into());
    }

    if common.seed_stdin || common.seed_file.is_some() {
        if common.passphrase_file.is_some() {
            return Err("--passphrase-file applies only to mnemonic sources".into());
        }
        let value = if common.seed_stdin {
            read_stdin_secret()?
        } else {
            read_secret_file(common.seed_file.as_ref().unwrap())?
        };
        return Ok(Source::Seed(hex::decode(value.trim())?));
    }

    let words = if common.prompt {
        rpassword::prompt_password("Mnemonic: ")?
    } else if common.mnemonic_stdin {
        read_stdin_secret()?
    } else if let Some(path) = &common.mnemonic_file {
        read_secret_file(path)?
    } else {
        unreachable!("source count was validated")
    };
    let passphrase = if common.prompt {
        rpassword::prompt_password("Passphrase (optional): ")?
    } else if let Some(path) = &common.passphrase_file {
        read_secret_file(path)?
            .trim_end_matches(['\r', '\n'])
            .to_owned()
    } else {
        String::new()
    };
    Ok(Source::mnemonic(words.trim(), passphrase))
}

fn read_stdin_secret() -> Result<String, Box<dyn std::error::Error>> {
    let mut value = String::new();
    io::stdin().read_to_string(&mut value)?;
    Ok(value)
}

fn read_secret_file(path: &PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err("secret source must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("secret file permissions must be 0600 or stricter".into());
        }
    }
    Ok(fs::read_to_string(path)?)
}

fn options(common: &Common) -> DeriveOptions<'_> {
    DeriveOptions {
        chain: &common.chain,
        format: common.format.as_deref(),
        script_type: common.script_type.as_deref(),
        path: common.path.as_deref(),
        account: common.account,
        change: common.change,
        index: common.index,
    }
}

fn print<T: serde::Serialize + ?Sized>(value: &T, pretty: bool) -> Result<(), serde_json::Error> {
    println!(
        "{}",
        if pretty {
            serde_json::to_string_pretty(value)?
        } else {
            serde_json::to_string(value)?
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn secret_file(contents: &str) -> PathBuf {
        let name = format!(
            "wallethd-secret-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(name);
        fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    #[test]
    fn secret_sources_are_exclusive_and_permission_checked() {
        assert!(source(&Common::default()).is_err());
        let seed_path = secret_file("000102030405060708090a0b0c0d0e0f\n");
        let value = source(&Common {
            seed_file: Some(seed_path.clone()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(value.seed().unwrap().len(), 16);

        let mnemonic_path = secret_file(DEMO_MNEMONIC);
        let passphrase_path = secret_file("TREZOR\n");
        let value = source(&Common {
            mnemonic_file: Some(mnemonic_path.clone()),
            passphrase_file: Some(passphrase_path.clone()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(value.seed().unwrap().len(), 64);
        assert!(source(&Common {
            mnemonic_file: Some(mnemonic_path.clone()),
            seed_file: Some(seed_path.clone()),
            ..Default::default()
        })
        .is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(source(&Common {
                seed_file: Some(seed_path.clone()),
                ..Default::default()
            })
            .is_err());
        }
        for path in [seed_path, mnemonic_path, passphrase_path] {
            let _ = fs::remove_file(path);
        }
    }
}
