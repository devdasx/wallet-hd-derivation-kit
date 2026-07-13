use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use k256::{
    elliptic_curve::{
        ff::PrimeField,
        group::Group,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
};
use ripemd::Ripemd160;
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha512 = Hmac<Sha512>;
pub const HARDENED_OFFSET: u32 = 0x8000_0000;
pub const API_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum HdError {
    #[error("invalid BIP39 English mnemonic")]
    InvalidMnemonic,
    #[error("seed must be between 16 and 64 bytes")]
    InvalidSeed,
    #[error("invalid derivation path: {0}")]
    InvalidPath(String),
    #[error("unsupported chain: {0}")]
    UnsupportedChain(String),
    #[error("unsupported script type: {0}")]
    UnsupportedScript(String),
    #[error("unsupported extended-key format: {0}")]
    UnsupportedFormat(String),
    #[error("extended public keys can derive only non-hardened children")]
    HardenedPublicDerivation,
    #[error("invalid BIP32 key material")]
    InvalidKey,
    #[error("invalid extended key")]
    InvalidExtendedKey,
    #[error("chain is required because extended-key version bytes do not identify every coin")]
    ChainRequired,
    #[error("Solana SLIP10 does not define extended public keys")]
    NoExtendedPublicKey,
}

pub type Result<T> = std::result::Result<T, HdError>;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub enum Source {
    Mnemonic { words: String, passphrase: String },
    Seed(Vec<u8>),
}

impl Source {
    pub fn mnemonic(words: impl Into<String>, passphrase: impl Into<String>) -> Self {
        Self::Mnemonic {
            words: words.into(),
            passphrase: passphrase.into(),
        }
    }

    pub fn seed(&self) -> Result<Vec<u8>> {
        match self {
            Source::Seed(seed) if (16..=64).contains(&seed.len()) => Ok(seed.clone()),
            Source::Seed(_) => Err(HdError::InvalidSeed),
            Source::Mnemonic { words, passphrase } => {
                let mnemonic = Mnemonic::parse_in_normalized(Language::English, words)
                    .map_err(|_| HdError::InvalidMnemonic)?;
                Ok(mnemonic.to_seed(passphrase).to_vec())
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Format {
    pub name: &'static str,
    pub public_version: u32,
    pub private_version: u32,
    pub purpose: u32,
    pub script_type: &'static str,
}

const XPUB: Format = Format {
    name: "xpub",
    public_version: 0x0488_b21e,
    private_version: 0x0488_ade4,
    purpose: 44,
    script_type: "p2pkh",
};
const YPUB: Format = Format {
    name: "ypub",
    public_version: 0x049d_7cb2,
    private_version: 0x049d_7878,
    purpose: 49,
    script_type: "p2sh-p2wpkh",
};
const ZPUB: Format = Format {
    name: "zpub",
    public_version: 0x04b2_4746,
    private_version: 0x04b2_430c,
    purpose: 84,
    script_type: "p2wpkh",
};
const TPUB: Format = Format {
    name: "tpub",
    public_version: 0x0435_87cf,
    private_version: 0x0435_8394,
    purpose: 44,
    script_type: "p2pkh",
};
const UPUB: Format = Format {
    name: "upub",
    public_version: 0x044a_5262,
    private_version: 0x044a_4e28,
    purpose: 49,
    script_type: "p2sh-p2wpkh",
};
const VPUB: Format = Format {
    name: "vpub",
    public_version: 0x045f_1cf6,
    private_version: 0x045f_18bc,
    purpose: 84,
    script_type: "p2wpkh",
};
const LTUB: Format = Format {
    name: "Ltub",
    public_version: 0x019d_a462,
    private_version: 0x019d_9cfe,
    purpose: 44,
    script_type: "p2pkh",
};
const MTUB: Format = Format {
    name: "Mtub",
    public_version: 0x01b2_6ef6,
    private_version: 0x01b2_6792,
    purpose: 49,
    script_type: "p2sh-p2wpkh",
};

pub fn format(name: &str) -> Result<Format> {
    match name {
        "xpub" => Ok(XPUB),
        "ypub" => Ok(YPUB),
        "zpub" => Ok(ZPUB),
        "tpub" => Ok(TPUB),
        "upub" => Ok(UPUB),
        "vpub" => Ok(VPUB),
        "Ltub" => Ok(LTUB),
        "Mtub" => Ok(MTUB),
        _ => Err(HdError::UnsupportedFormat(name.into())),
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Chain {
    pub id: &'static str,
    pub name: &'static str,
    pub symbol: &'static str,
    pub coin_type: u32,
    pub curve: &'static str,
    pub default_format: Option<&'static str>,
    pub default_script_type: &'static str,
    #[serde(skip)]
    pub p2pkh: &'static [u8],
    #[serde(skip)]
    pub p2sh: &'static [u8],
    pub hrp: Option<&'static str>,
}

pub const CHAINS: &[Chain] = &[
    Chain {
        id: "bitcoin",
        name: "Bitcoin",
        symbol: "BTC",
        coin_type: 0,
        curve: "secp256k1",
        default_format: Some("zpub"),
        default_script_type: "p2wpkh",
        p2pkh: &[0x00],
        p2sh: &[0x05],
        hrp: Some("bc"),
    },
    Chain {
        id: "bitcoin-testnet",
        name: "Bitcoin Testnet",
        symbol: "TBTC",
        coin_type: 1,
        curve: "secp256k1",
        default_format: Some("vpub"),
        default_script_type: "p2wpkh",
        p2pkh: &[0x6f],
        p2sh: &[0xc4],
        hrp: Some("tb"),
    },
    Chain {
        id: "litecoin",
        name: "Litecoin",
        symbol: "LTC",
        coin_type: 2,
        curve: "secp256k1",
        default_format: Some("Ltub"),
        default_script_type: "p2pkh",
        p2pkh: &[0x30],
        p2sh: &[0x32],
        hrp: Some("ltc"),
    },
    Chain {
        id: "dogecoin",
        name: "Dogecoin",
        symbol: "DOGE",
        coin_type: 3,
        curve: "secp256k1",
        default_format: Some("xpub"),
        default_script_type: "p2pkh",
        p2pkh: &[0x1e],
        p2sh: &[0x16],
        hrp: None,
    },
    Chain {
        id: "dash",
        name: "Dash",
        symbol: "DASH",
        coin_type: 5,
        curve: "secp256k1",
        default_format: Some("xpub"),
        default_script_type: "p2pkh",
        p2pkh: &[0x4c],
        p2sh: &[0x10],
        hrp: None,
    },
    Chain {
        id: "digibyte",
        name: "DigiByte",
        symbol: "DGB",
        coin_type: 20,
        curve: "secp256k1",
        default_format: Some("xpub"),
        default_script_type: "p2pkh",
        p2pkh: &[0x1e],
        p2sh: &[0x3f],
        hrp: Some("dgb"),
    },
    Chain {
        id: "bitcoin-cash",
        name: "Bitcoin Cash",
        symbol: "BCH",
        coin_type: 145,
        curve: "secp256k1",
        default_format: Some("xpub"),
        default_script_type: "cashaddr",
        p2pkh: &[0x00],
        p2sh: &[0x05],
        hrp: None,
    },
    Chain {
        id: "zcash-transparent",
        name: "Zcash Transparent",
        symbol: "ZEC",
        coin_type: 133,
        curve: "secp256k1",
        default_format: Some("xpub"),
        default_script_type: "p2pkh",
        p2pkh: &[0x1c, 0xb8],
        p2sh: &[0x1c, 0xbd],
        hrp: None,
    },
    Chain {
        id: "ethereum",
        name: "Ethereum",
        symbol: "ETH",
        coin_type: 60,
        curve: "secp256k1",
        default_format: None,
        default_script_type: "evm",
        p2pkh: &[],
        p2sh: &[],
        hrp: None,
    },
    Chain {
        id: "ethereum-classic",
        name: "Ethereum Classic",
        symbol: "ETC",
        coin_type: 61,
        curve: "secp256k1",
        default_format: None,
        default_script_type: "evm",
        p2pkh: &[],
        p2sh: &[],
        hrp: None,
    },
    Chain {
        id: "polygon",
        name: "Polygon",
        symbol: "POL",
        coin_type: 60,
        curve: "secp256k1",
        default_format: None,
        default_script_type: "evm",
        p2pkh: &[],
        p2sh: &[],
        hrp: None,
    },
    Chain {
        id: "bsc",
        name: "BNB Smart Chain",
        symbol: "BNB",
        coin_type: 60,
        curve: "secp256k1",
        default_format: None,
        default_script_type: "evm",
        p2pkh: &[],
        p2sh: &[],
        hrp: None,
    },
    Chain {
        id: "avalanche-c",
        name: "Avalanche C-Chain",
        symbol: "AVAX",
        coin_type: 60,
        curve: "secp256k1",
        default_format: None,
        default_script_type: "evm",
        p2pkh: &[],
        p2sh: &[],
        hrp: None,
    },
    Chain {
        id: "arbitrum",
        name: "Arbitrum",
        symbol: "ARB",
        coin_type: 60,
        curve: "secp256k1",
        default_format: None,
        default_script_type: "evm",
        p2pkh: &[],
        p2sh: &[],
        hrp: None,
    },
    Chain {
        id: "optimism",
        name: "Optimism",
        symbol: "OP",
        coin_type: 60,
        curve: "secp256k1",
        default_format: None,
        default_script_type: "evm",
        p2pkh: &[],
        p2sh: &[],
        hrp: None,
    },
    Chain {
        id: "base",
        name: "Base",
        symbol: "ETH",
        coin_type: 60,
        curve: "secp256k1",
        default_format: None,
        default_script_type: "evm",
        p2pkh: &[],
        p2sh: &[],
        hrp: None,
    },
    Chain {
        id: "tron",
        name: "TRON",
        symbol: "TRX",
        coin_type: 195,
        curve: "secp256k1",
        default_format: None,
        default_script_type: "tron",
        p2pkh: &[],
        p2sh: &[],
        hrp: None,
    },
    Chain {
        id: "solana",
        name: "Solana",
        symbol: "SOL",
        coin_type: 501,
        curve: "ed25519",
        default_format: None,
        default_script_type: "solana",
        p2pkh: &[],
        p2sh: &[],
        hrp: None,
    },
];

pub fn supported_chains() -> &'static [Chain] {
    CHAINS
}

pub fn chain(id: &str) -> Result<Chain> {
    CHAINS
        .iter()
        .find(|item| item.id == id)
        .copied()
        .ok_or_else(|| HdError::UnsupportedChain(id.into()))
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ExtendedPrivateKey {
    pub private_key: [u8; 32],
    pub chain_code: [u8; 32],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
}

#[derive(Clone, Debug)]
pub struct ExtendedPublicKey {
    pub public_key: [u8; 33],
    pub chain_code: [u8; 32],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
}

impl ExtendedPrivateKey {
    pub fn master(seed: &[u8]) -> Result<Self> {
        if !(16..=64).contains(&seed.len()) {
            return Err(HdError::InvalidSeed);
        }
        let mut material = seed.to_vec();
        loop {
            let digest = hmac_sha512(b"Bitcoin seed", &material);
            let private_key: [u8; 32] = digest[..32].try_into().unwrap();
            if scalar(&private_key).is_ok() {
                return Ok(Self {
                    private_key,
                    chain_code: digest[32..].try_into().unwrap(),
                    depth: 0,
                    parent_fingerprint: [0; 4],
                    child_number: 0,
                });
            }
            material = digest.to_vec();
        }
    }

    pub fn public_key(&self) -> [u8; 33] {
        let scalar = scalar(&self.private_key).expect("validated private key");
        let point = (ProjectivePoint::GENERATOR * scalar)
            .to_affine()
            .to_encoded_point(true);
        point.as_bytes().try_into().unwrap()
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        hash160(&self.public_key())[..4].try_into().unwrap()
    }

    pub fn derive(&self, index: u32) -> Result<Self> {
        let mut data = Vec::with_capacity(37);
        if index >= HARDENED_OFFSET {
            data.push(0);
            data.extend(self.private_key);
        } else {
            data.extend(self.public_key());
        }
        data.extend(index.to_be_bytes());
        let digest = hmac_sha512(&self.chain_code, &data);
        let tweak = scalar(&digest[..32].try_into().unwrap())?;
        let child = tweak + scalar(&self.private_key)?;
        if bool::from(child.is_zero()) {
            return Err(HdError::InvalidKey);
        }
        Ok(Self {
            private_key: child.to_bytes().into(),
            chain_code: digest[32..].try_into().unwrap(),
            depth: self.depth.checked_add(1).ok_or(HdError::InvalidKey)?,
            parent_fingerprint: self.fingerprint(),
            child_number: index,
        })
    }

    pub fn derive_path(&self, path: &str) -> Result<Self> {
        parse_path(path)?
            .into_iter()
            .try_fold(self.clone(), |node, index| node.derive(index))
    }

    pub fn neuter(&self) -> ExtendedPublicKey {
        ExtendedPublicKey {
            public_key: self.public_key(),
            chain_code: self.chain_code,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
        }
    }

    pub fn serialize_private(&self, version: u32) -> String {
        let mut key = [0u8; 33];
        key[1..].copy_from_slice(&self.private_key);
        serialize_key(
            version,
            self.depth,
            &self.parent_fingerprint,
            self.child_number,
            &self.chain_code,
            &key,
        )
    }

    pub fn serialize_public(&self, version: u32) -> String {
        self.neuter().serialize_public(version)
    }
}

impl ExtendedPublicKey {
    pub fn fingerprint(&self) -> [u8; 4] {
        hash160(&self.public_key)[..4].try_into().unwrap()
    }

    pub fn derive(&self, index: u32) -> Result<Self> {
        if index >= HARDENED_OFFSET {
            return Err(HdError::HardenedPublicDerivation);
        }
        let mut data = self.public_key.to_vec();
        data.extend(index.to_be_bytes());
        let digest = hmac_sha512(&self.chain_code, &data);
        let tweak = scalar(&digest[..32].try_into().unwrap())?;
        let encoded = EncodedPoint::from_bytes(self.public_key).map_err(|_| HdError::InvalidKey)?;
        let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
            .ok_or(HdError::InvalidKey)?;
        let child = ProjectivePoint::GENERATOR * tweak + ProjectivePoint::from(affine);
        if bool::from(child.is_identity()) {
            return Err(HdError::InvalidKey);
        }
        let point = child.to_affine().to_encoded_point(true);
        Ok(Self {
            public_key: point.as_bytes().try_into().unwrap(),
            chain_code: digest[32..].try_into().unwrap(),
            depth: self.depth.checked_add(1).ok_or(HdError::InvalidKey)?,
            parent_fingerprint: self.fingerprint(),
            child_number: index,
        })
    }

    pub fn serialize_public(&self, version: u32) -> String {
        serialize_key(
            version,
            self.depth,
            &self.parent_fingerprint,
            self.child_number,
            &self.chain_code,
            &self.public_key,
        )
    }
}

pub enum ParsedExtendedKey {
    Private(ExtendedPrivateKey, u32),
    Public(ExtendedPublicKey, u32),
}

pub fn parse_extended_key(value: &str) -> Result<ParsedExtendedKey> {
    let decoded = bs58::decode(value)
        .with_check(None)
        .into_vec()
        .map_err(|_| HdError::InvalidExtendedKey)?;
    if decoded.len() != 78 {
        return Err(HdError::InvalidExtendedKey);
    }
    let version = u32::from_be_bytes(decoded[..4].try_into().unwrap());
    let depth = decoded[4];
    let parent_fingerprint = decoded[5..9].try_into().unwrap();
    let child_number = u32::from_be_bytes(decoded[9..13].try_into().unwrap());
    let chain_code = decoded[13..45].try_into().unwrap();
    let is_private = decoded[45] == 0;
    let registered = [XPUB, YPUB, ZPUB, TPUB, UPUB, VPUB, LTUB, MTUB]
        .iter()
        .any(|candidate| {
            version
                == if is_private {
                    candidate.private_version
                } else {
                    candidate.public_version
                }
        });
    if !registered || (depth == 0 && (parent_fingerprint != [0; 4] || child_number != 0)) {
        return Err(HdError::InvalidExtendedKey);
    }
    if is_private {
        let private_key = decoded[46..78].try_into().unwrap();
        scalar(&private_key)?;
        Ok(ParsedExtendedKey::Private(
            ExtendedPrivateKey {
                private_key,
                chain_code,
                depth,
                parent_fingerprint,
                child_number,
            },
            version,
        ))
    } else {
        let public_key = decoded[45..78].try_into().unwrap();
        let encoded =
            EncodedPoint::from_bytes(public_key).map_err(|_| HdError::InvalidExtendedKey)?;
        Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
            .ok_or(HdError::InvalidExtendedKey)?;
        Ok(ParsedExtendedKey::Public(
            ExtendedPublicKey {
                public_key,
                chain_code,
                depth,
                parent_fingerprint,
                child_number,
            },
            version,
        ))
    }
}

pub fn parse_path(path: &str) -> Result<Vec<u32>> {
    if path == "m" || path == "M" {
        return Ok(vec![]);
    }
    let mut parts = path.split('/');
    if !matches!(parts.next(), Some("m" | "M")) {
        return Err(HdError::InvalidPath(path.into()));
    }
    let values: Vec<_> = parts.collect();
    if values.is_empty() || values.len() > 255 {
        return Err(HdError::InvalidPath(path.into()));
    }
    values
        .into_iter()
        .map(|part| {
            let hardened = part.ends_with(['\'', 'h', 'H']);
            let raw = if hardened {
                &part[..part.len() - 1]
            } else {
                part
            };
            if raw.is_empty() || (raw.len() > 1 && raw.starts_with('0')) {
                return Err(HdError::InvalidPath(path.into()));
            }
            let value: u32 = raw.parse().map_err(|_| HdError::InvalidPath(path.into()))?;
            if value >= HARDENED_OFFSET {
                return Err(HdError::InvalidPath(path.into()));
            }
            Ok(if hardened {
                value + HARDENED_OFFSET
            } else {
                value
            })
        })
        .collect()
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DerivedAddress {
    pub schema_version: u8,
    pub chain: String,
    pub curve: String,
    pub path: String,
    pub account: u32,
    pub change: u32,
    pub index: u32,
    pub script_type: String,
    pub address: String,
    pub public_key_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeResult {
    pub schema_version: u8,
    pub curve: String,
    pub path: String,
    pub public_key_hex: String,
    pub chain_code_hex: String,
    pub depth: u8,
    pub child_number: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountPublicKey {
    pub schema_version: u8,
    pub chain: String,
    pub curve: String,
    pub path: String,
    pub format: String,
    pub extended_public_key: String,
    pub public_key_hex: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountPrivateKey {
    pub schema_version: u8,
    pub chain: String,
    pub curve: String,
    pub path: String,
    pub format: Option<String>,
    pub extended_private_key: Option<String>,
    pub private_key_hex: String,
    pub public_key_hex: String,
}

#[derive(Clone, Debug, Default)]
pub struct DeriveOptions<'a> {
    pub chain: &'a str,
    pub format: Option<&'a str>,
    pub script_type: Option<&'a str>,
    pub path: Option<&'a str>,
    pub account: u32,
    pub change: u32,
    pub index: u32,
}

pub fn derive_node(source: &Source, curve: &str, path: &str) -> Result<NodeResult> {
    let seed = source.seed()?;
    match curve {
        "secp256k1" => {
            let node = ExtendedPrivateKey::master(&seed)?.derive_path(path)?;
            Ok(NodeResult {
                schema_version: API_SCHEMA_VERSION,
                curve: curve.into(),
                path: path.into(),
                public_key_hex: hex::encode(node.public_key()),
                chain_code_hex: hex::encode(node.chain_code),
                depth: node.depth,
                child_number: node.child_number,
            })
        }
        "ed25519" => {
            let node = slip10_ed25519(&seed, path)?;
            Ok(NodeResult {
                schema_version: API_SCHEMA_VERSION,
                curve: curve.into(),
                path: path.into(),
                public_key_hex: hex::encode(node.public_key),
                chain_code_hex: hex::encode(node.chain_code),
                depth: node.depth,
                child_number: node.child_number,
            })
        }
        _ => Err(HdError::UnsupportedFormat(curve.into())),
    }
}

pub fn serialize_extended_key(key: &ParsedExtendedKey, version: Option<u32>) -> String {
    match key {
        ParsedExtendedKey::Private(node, original) => {
            node.serialize_private(version.unwrap_or(*original))
        }
        ParsedExtendedKey::Public(node, original) => {
            node.serialize_public(version.unwrap_or(*original))
        }
    }
}

pub fn derive_account_public_key(
    source: &Source,
    options: DeriveOptions<'_>,
) -> Result<AccountPublicKey> {
    let chain = chain(if options.chain.is_empty() {
        "bitcoin"
    } else {
        options.chain
    })?;
    if chain.curve == "ed25519" {
        return Err(HdError::NoExtendedPublicKey);
    }
    let fmt = resolve_format(chain, options.format, options.script_type)?;
    let path = options
        .path
        .map(str::to_owned)
        .unwrap_or_else(|| account_path(chain, options.account, options.script_type, fmt));
    let node = ExtendedPrivateKey::master(&source.seed()?)?.derive_path(&path)?;
    Ok(AccountPublicKey {
        schema_version: API_SCHEMA_VERSION,
        chain: chain.id.into(),
        curve: chain.curve.into(),
        path,
        format: fmt.name.into(),
        extended_public_key: node.serialize_public(fmt.public_version),
        public_key_hex: hex::encode(node.public_key()),
    })
}

pub fn derive_account_private_key(
    source: &Source,
    options: DeriveOptions<'_>,
) -> Result<AccountPrivateKey> {
    let chain = chain(if options.chain.is_empty() {
        "bitcoin"
    } else {
        options.chain
    })?;
    let path = options.path.map(str::to_owned).unwrap_or_else(|| {
        account_path(
            chain,
            options.account,
            options.script_type,
            resolve_format(chain, options.format, options.script_type).unwrap_or(XPUB),
        )
    });
    let seed = source.seed()?;
    if chain.curve == "ed25519" {
        let node = slip10_ed25519(&seed, &path)?;
        return Ok(AccountPrivateKey {
            schema_version: API_SCHEMA_VERSION,
            chain: chain.id.into(),
            curve: chain.curve.into(),
            path,
            format: None,
            extended_private_key: None,
            private_key_hex: hex::encode(node.private_key),
            public_key_hex: hex::encode(node.public_key),
        });
    }
    let fmt = resolve_format(chain, options.format, options.script_type)?;
    let node = ExtendedPrivateKey::master(&seed)?.derive_path(&path)?;
    Ok(AccountPrivateKey {
        schema_version: API_SCHEMA_VERSION,
        chain: chain.id.into(),
        curve: chain.curve.into(),
        path,
        format: Some(fmt.name.into()),
        extended_private_key: Some(node.serialize_private(fmt.private_version)),
        private_key_hex: hex::encode(node.private_key),
        public_key_hex: hex::encode(node.public_key()),
    })
}

pub fn derive_address(source: &Source, options: DeriveOptions<'_>) -> Result<DerivedAddress> {
    let chain = chain(if options.chain.is_empty() {
        "bitcoin"
    } else {
        options.chain
    })?;
    let script_type = options.script_type.unwrap_or(chain.default_script_type);
    let seed = source.seed()?;
    if chain.curve == "ed25519" {
        let path = options.path.map(str::to_owned).unwrap_or_else(|| {
            format!(
                "m/44'/{}'/{}'/{}'",
                chain.coin_type, options.account, options.index
            )
        });
        let node = slip10_ed25519(&seed, &path)?;
        return Ok(address_result(
            chain,
            path,
            options,
            script_type,
            bs58::encode(node.public_key).into_string(),
            node.public_key.to_vec(),
        ));
    }
    let fmt = resolve_format(chain, options.format, Some(script_type)).unwrap_or(XPUB);
    let path = options.path.map(str::to_owned).unwrap_or_else(|| {
        format!(
            "{}/{}/{}",
            account_path(chain, options.account, Some(script_type), fmt),
            options.change,
            options.index
        )
    });
    let node = ExtendedPrivateKey::master(&seed)?.derive_path(&path)?;
    let public_key = node.public_key();
    let address = public_key_to_address(&public_key, chain, script_type)?;
    Ok(address_result(
        chain,
        path,
        options,
        script_type,
        address,
        public_key.to_vec(),
    ))
}

pub fn derive_addresses(
    source: &Source,
    mut options: DeriveOptions<'_>,
    start: u32,
    count: u32,
) -> Result<Vec<DerivedAddress>> {
    if count == 0 || count > 10_000 {
        return Err(HdError::InvalidPath(
            "count must be between 1 and 10000".into(),
        ));
    }
    (start..start.checked_add(count).ok_or(HdError::InvalidKey)?)
        .map(|index| {
            options.index = index;
            derive_address(source, options.clone())
        })
        .collect()
}

pub fn derive_address_from_extended_public_key(
    value: &str,
    chain_id: Option<&str>,
    change: u32,
    index: u32,
    script_type: Option<&str>,
) -> Result<DerivedAddress> {
    let chain = chain(chain_id.ok_or(HdError::ChainRequired)?)?;
    let (node, version) = match parse_extended_key(value)? {
        ParsedExtendedKey::Public(node, version) => (node, version),
        _ => return Err(HdError::InvalidExtendedKey),
    };
    let node = node.derive(change)?.derive(index)?;
    let script = script_type.unwrap_or_else(|| match version {
        0x049d_7cb2 | 0x044a_5262 | 0x01b2_6ef6 => "p2sh-p2wpkh",
        0x04b2_4746 | 0x045f_1cf6 => "p2wpkh",
        _ => chain.default_script_type,
    });
    let address = public_key_to_address(&node.public_key, chain, script)?;
    Ok(address_result(
        chain,
        format!("{change}/{index}"),
        DeriveOptions {
            chain: chain.id,
            change,
            index,
            ..Default::default()
        },
        script,
        address,
        node.public_key.to_vec(),
    ))
}

fn resolve_format(chain: Chain, requested: Option<&str>, script: Option<&str>) -> Result<Format> {
    let name = requested
        .or_else(|| {
            if script == Some("p2tr") {
                Some("xpub")
            } else {
                chain.default_format
            }
        })
        .unwrap_or("xpub");
    let fmt = format(name)?;
    let allowed = match chain.id {
        "bitcoin" => ["xpub", "ypub", "zpub"].as_slice(),
        "bitcoin-testnet" => ["tpub", "upub", "vpub"].as_slice(),
        "litecoin" => ["Ltub", "Mtub"].as_slice(),
        _ => ["xpub"].as_slice(),
    };
    if !allowed.contains(&fmt.name) {
        return Err(HdError::UnsupportedFormat(name.into()));
    }
    Ok(fmt)
}

fn account_path(chain: Chain, account: u32, script: Option<&str>, fmt: Format) -> String {
    let purpose = if script == Some("p2tr") {
        86
    } else {
        fmt.purpose
    };
    format!("m/{purpose}'/{}'/{account}'", chain.coin_type)
}

fn address_result(
    chain: Chain,
    path: String,
    options: DeriveOptions<'_>,
    script: &str,
    address: String,
    public_key: Vec<u8>,
) -> DerivedAddress {
    DerivedAddress {
        schema_version: API_SCHEMA_VERSION,
        chain: chain.id.into(),
        curve: chain.curve.into(),
        path,
        account: options.account,
        change: options.change,
        index: options.index,
        script_type: script.into(),
        address,
        public_key_hex: hex::encode(public_key),
    }
}

fn public_key_to_address(public_key: &[u8], chain: Chain, script: &str) -> Result<String> {
    match script {
        "evm" => Ok(evm_address(public_key)?),
        "tron" => Ok(tron_address(public_key)?),
        "cashaddr" => Ok(cash_address("bitcoincash", &hash160(public_key))),
        "p2pkh" => Ok(base58check(&[chain.p2pkh, &hash160(public_key)].concat())),
        "p2sh-p2wpkh" => {
            let redeem = [&[0x00, 0x14][..], &hash160(public_key)].concat();
            Ok(base58check(&[chain.p2sh, &hash160(&redeem)].concat()))
        }
        "p2wpkh" => Ok(segwit_address(
            chain
                .hrp
                .ok_or_else(|| HdError::UnsupportedScript(script.into()))?,
            0,
            &hash160(public_key),
        )),
        "p2tr" => Ok(segwit_address(
            chain
                .hrp
                .ok_or_else(|| HdError::UnsupportedScript(script.into()))?,
            1,
            &taproot_output_key(public_key)?,
        )),
        _ => Err(HdError::UnsupportedScript(script.into())),
    }
}

fn evm_address(public_key: &[u8]) -> Result<String> {
    let encoded = EncodedPoint::from_bytes(public_key).map_err(|_| HdError::InvalidKey)?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or(HdError::InvalidKey)?;
    let uncompressed = affine.to_encoded_point(false);
    let digest = Keccak256::digest(&uncompressed.as_bytes()[1..]);
    Ok(eip55(&digest[12..]))
}

fn tron_address(public_key: &[u8]) -> Result<String> {
    let encoded = EncodedPoint::from_bytes(public_key).map_err(|_| HdError::InvalidKey)?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or(HdError::InvalidKey)?;
    let uncompressed = affine.to_encoded_point(false);
    let digest = Keccak256::digest(&uncompressed.as_bytes()[1..]);
    Ok(base58check(&[&[0x41], &digest[12..]].concat()))
}

fn eip55(bytes: &[u8]) -> String {
    let lower = hex::encode(bytes);
    let hash = hex::encode(Keccak256::digest(lower.as_bytes()));
    let mut output = String::from("0x");
    for (index, character) in lower.chars().enumerate() {
        if character.is_ascii_alphabetic()
            && u8::from_str_radix(&hash[index..=index], 16).unwrap() >= 8
        {
            output.push(character.to_ascii_uppercase());
        } else {
            output.push(character);
        }
    }
    output
}

fn taproot_output_key(public_key: &[u8]) -> Result<Vec<u8>> {
    let x_only = &public_key[1..];
    let even =
        EncodedPoint::from_bytes([&[0x02], x_only].concat()).map_err(|_| HdError::InvalidKey)?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&even))
        .ok_or(HdError::InvalidKey)?;
    let tweak_bytes: [u8; 32] = tagged_hash(b"TapTweak", x_only).into();
    let tweak = scalar(&tweak_bytes)?;
    let output = ProjectivePoint::from(affine) + ProjectivePoint::GENERATOR * tweak;
    Ok(output.to_affine().to_encoded_point(true).as_bytes()[1..].to_vec())
}

struct Slip10Node {
    private_key: [u8; 32],
    public_key: [u8; 32],
    chain_code: [u8; 32],
    depth: u8,
    child_number: u32,
}

fn slip10_ed25519(seed: &[u8], path: &str) -> Result<Slip10Node> {
    if !(16..=64).contains(&seed.len()) {
        return Err(HdError::InvalidSeed);
    }
    let mut digest = hmac_sha512(b"ed25519 seed", seed);
    let mut private_key: [u8; 32] = digest[..32].try_into().unwrap();
    let mut chain_code: [u8; 32] = digest[32..].try_into().unwrap();
    let mut depth = 0u8;
    let mut child_number = 0u32;
    for index in parse_path(path)? {
        if index < HARDENED_OFFSET {
            return Err(HdError::HardenedPublicDerivation);
        }
        let data = [&[0], &private_key[..], &index.to_be_bytes()].concat();
        digest = hmac_sha512(&chain_code, &data);
        private_key = digest[..32].try_into().unwrap();
        chain_code = digest[32..].try_into().unwrap();
        depth = depth
            .checked_add(1)
            .ok_or_else(|| HdError::InvalidPath(path.into()))?;
        child_number = index;
    }
    let public_key = SigningKey::from_bytes(&private_key)
        .verifying_key()
        .to_bytes();
    Ok(Slip10Node {
        private_key,
        public_key,
        chain_code,
        depth,
        child_number,
    })
}

fn scalar(bytes: &[u8; 32]) -> Result<Scalar> {
    let value =
        Option::<Scalar>::from(Scalar::from_repr((*bytes).into())).ok_or(HdError::InvalidKey)?;
    if bool::from(value.is_zero()) {
        Err(HdError::InvalidKey)
    } else {
        Ok(value)
    }
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts arbitrary key sizes");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hash160(bytes: &[u8]) -> Vec<u8> {
    Ripemd160::digest(Sha256::digest(bytes)).to_vec()
}
fn base58check(payload: &[u8]) -> String {
    bs58::encode(payload).with_check().into_string()
}
fn serialize_key(
    version: u32,
    depth: u8,
    parent: &[u8; 4],
    child: u32,
    chain_code: &[u8; 32],
    key: &[u8; 33],
) -> String {
    let payload = [
        &version.to_be_bytes()[..],
        &[depth],
        parent,
        &child.to_be_bytes(),
        chain_code,
        key,
    ]
    .concat();
    base58check(&payload)
}

const BECH32_ALPHABET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
fn segwit_address(hrp: &str, version: u8, program: &[u8]) -> String {
    let mut words = vec![version];
    words.extend(convert_bits(program, 8, 5, true).unwrap());
    bech32_encode(hrp, &words, if version == 0 { 1 } else { 0x2bc8_30a3 })
}
fn bech32_encode(hrp: &str, words: &[u8], constant: u32) -> String {
    let mut values: Vec<u8> = hrp.bytes().map(|byte| byte >> 5).collect();
    values.push(0);
    values.extend(hrp.bytes().map(|byte| byte & 31));
    values.extend(words);
    values.extend([0; 6]);
    let polymod = bech32_polymod(&values) ^ constant;
    let checksum: Vec<u8> = (0..6)
        .map(|index| ((polymod >> (5 * (5 - index))) & 31) as u8)
        .collect();
    let data: String = words
        .iter()
        .chain(checksum.iter())
        .map(|value| BECH32_ALPHABET[*value as usize] as char)
        .collect();
    format!("{hrp}1{data}")
}
fn bech32_polymod(values: &[u8]) -> u32 {
    let generators = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut checksum = 1u32;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x1ff_ffff) << 5) ^ *value as u32;
        for (index, generator) in generators.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut output = vec![];
    let mask = (1u32 << to) - 1;
    for value in data {
        if (*value as u32) >> from != 0 {
            return Err(HdError::InvalidKey);
        }
        acc = (acc << from) | *value as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            output.push(((acc >> bits) & mask) as u8);
        }
    }
    if pad && bits > 0 {
        output.push(((acc << (to - bits)) & mask) as u8);
    } else if !pad && (bits >= from || ((acc << (to - bits)) & mask) != 0) {
        return Err(HdError::InvalidKey);
    }
    Ok(output)
}

fn cash_address(prefix: &str, hash: &[u8]) -> String {
    let mut bytes = vec![0];
    bytes.extend(hash);
    let payload = convert_bits(&bytes, 8, 5, true).unwrap();
    let mut values: Vec<u8> = prefix.bytes().map(|byte| byte & 31).collect();
    values.push(0);
    values.extend(&payload);
    values.extend([0; 8]);
    let polymod = cashaddr_polymod(&values) ^ 1;
    let checksum: Vec<u8> = (0..8)
        .map(|index| ((polymod >> (5 * (7 - index))) & 31) as u8)
        .collect();
    let data: String = payload
        .iter()
        .chain(checksum.iter())
        .map(|value| BECH32_ALPHABET[*value as usize] as char)
        .collect();
    format!("{prefix}:{data}")
}
fn cashaddr_polymod(values: &[u8]) -> u64 {
    let generators = [
        0x98f2_bc8e61,
        0x79b7_6d99e2,
        0xf33e_5fb3c4,
        0xae2e_abe2a8,
        0x1e4f_43e470,
    ];
    let mut checksum = 1u64;
    for value in values {
        let top = checksum >> 35;
        checksum = ((checksum & 0x07_ff_ff_ff_ff) << 5) ^ *value as u64;
        for (index, generator) in generators.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}
fn tagged_hash(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    Sha256::digest([&tag_hash[..], &tag_hash[..], message].concat()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    fn source() -> Source {
        Source::mnemonic(WORDS, "")
    }

    #[test]
    fn slip132_and_bip86_vectors() {
        let zpub = derive_account_public_key(
            &source(),
            DeriveOptions {
                chain: "bitcoin",
                format: Some("zpub"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(zpub.extended_public_key, "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs");
        let address = derive_address(
            &source(),
            DeriveOptions {
                chain: "bitcoin",
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            address.address,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        let taproot = derive_address(
            &source(),
            DeriveOptions {
                chain: "bitcoin",
                script_type: Some("p2tr"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            taproot.address,
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
    }

    #[test]
    fn multi_chain_vectors() {
        for (id, expected) in [
            ("litecoin", "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez"),
            ("dogecoin", "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC"),
            ("ethereum", "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
            ("tron", "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"),
            ("solana", "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"),
        ] {
            assert_eq!(
                derive_address(
                    &source(),
                    DeriveOptions {
                        chain: id,
                        ..Default::default()
                    }
                )
                .unwrap()
                .address,
                expected
            );
        }
    }

    #[test]
    fn public_and_private_children_match() {
        let root = ExtendedPrivateKey::master(&source().seed().unwrap())
            .unwrap()
            .derive_path("m/84'/0'/0'")
            .unwrap();
        assert_eq!(
            root.derive(0).unwrap().public_key(),
            root.neuter().derive(0).unwrap().public_key
        );
        assert!(root.neuter().derive(HARDENED_OFFSET).is_err());
    }

    #[test]
    fn all_official_bip32_vectors_and_invalid_keys() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../test-vectors/bip32-official.json")).unwrap();
        for vector in vectors["vectors"].as_array().unwrap() {
            let seed = hex::decode(vector["seedHex"].as_str().unwrap()).unwrap();
            let root = ExtendedPrivateKey::master(&seed).unwrap();
            for expected in vector["nodes"].as_array().unwrap() {
                let path = expected["path"].as_str().unwrap();
                let node = root.derive_path(path).unwrap();
                assert_eq!(
                    node.serialize_public(XPUB.public_version),
                    expected["extendedPublicKey"].as_str().unwrap(),
                    "{path}"
                );
                assert_eq!(
                    node.serialize_private(XPUB.private_version),
                    expected["extendedPrivateKey"].as_str().unwrap(),
                    "{path}"
                );
            }
        }
        for invalid in vectors["invalidExtendedKeys"].as_array().unwrap() {
            assert!(
                parse_extended_key(invalid["value"].as_str().unwrap()).is_err(),
                "accepted {}",
                invalid["reason"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn official_slip10_ed25519_vector() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../test-vectors/slip10-ed25519-official.json"
        ))
        .unwrap();
        let seed = hex::decode(vectors["seedHex"].as_str().unwrap()).unwrap();
        for expected in vectors["nodes"].as_array().unwrap() {
            let path = expected["path"].as_str().unwrap();
            let node = slip10_ed25519(&seed, path).unwrap();
            assert_eq!(hex::encode(node.chain_code), expected["chainCodeHex"]);
            assert_eq!(hex::encode(node.private_key), expected["privateKeyHex"]);
            assert_eq!(hex::encode(node.public_key), expected["publicKeyHex"]);
        }
    }

    #[test]
    fn public_api_branches_and_failure_boundaries() {
        assert_eq!(supported_chains().len(), 18);
        assert!(chain("unknown").is_err());
        assert!(Source::Seed(vec![0; 15]).seed().is_err());
        assert!(Source::mnemonic("abandon abandon", "").seed().is_err());
        assert!(ExtendedPrivateKey::master(&[0; 15]).is_err());
        for name in [
            "xpub", "ypub", "zpub", "tpub", "upub", "vpub", "Ltub", "Mtub",
        ] {
            assert_eq!(format(name).unwrap().name, name);
        }
        assert!(format("unknown").is_err());

        let secp = derive_node(&source(), "secp256k1", "m/0h/1H/2'").unwrap();
        assert_eq!(secp.depth, 3);
        let ed = derive_node(&source(), "ed25519", "m/0'").unwrap();
        assert_eq!(ed.depth, 1);
        assert!(derive_node(&source(), "p256", "m").is_err());
        assert!(derive_node(&source(), "ed25519", "m/0").is_err());

        let account = derive_account_public_key(&source(), DeriveOptions::default()).unwrap();
        let parsed_public = parse_extended_key(&account.extended_public_key).unwrap();
        assert_eq!(
            serialize_extended_key(&parsed_public, None),
            account.extended_public_key
        );
        assert!(derive_account_public_key(
            &source(),
            DeriveOptions {
                chain: "solana",
                ..Default::default()
            }
        )
        .is_err());
        assert!(derive_account_public_key(
            &source(),
            DeriveOptions {
                chain: "bitcoin",
                format: Some("tpub"),
                ..Default::default()
            }
        )
        .is_err());

        let secret = derive_account_private_key(
            &source(),
            DeriveOptions {
                chain: "bitcoin",
                format: Some("xpub"),
                path: Some("m"),
                ..Default::default()
            },
        )
        .unwrap();
        let parsed_private =
            parse_extended_key(secret.extended_private_key.as_deref().unwrap()).unwrap();
        assert_eq!(
            serialize_extended_key(&parsed_private, Some(XPUB.private_version)),
            secret.extended_private_key.unwrap()
        );
        let solana_secret = derive_account_private_key(
            &source(),
            DeriveOptions {
                chain: "solana",
                ..Default::default()
            },
        )
        .unwrap();
        assert!(solana_secret.extended_private_key.is_none());

        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../test-vectors/public-vectors.json")).unwrap();
        for expected in vectors["addresses"].as_array().unwrap() {
            let chain = expected["chain"].as_str().unwrap();
            let path = expected["path"].as_str().unwrap();
            let script_type = expected["scriptType"].as_str().unwrap();
            assert_eq!(
                derive_address(
                    &source(),
                    DeriveOptions {
                        chain,
                        path: Some(path),
                        script_type: Some(script_type),
                        ..Default::default()
                    }
                )
                .unwrap()
                .address,
                expected["address"]
            );
        }
        assert_eq!(
            derive_addresses(&source(), DeriveOptions::default(), 3, 4)
                .unwrap()
                .len(),
            4
        );
        assert!(derive_addresses(&source(), DeriveOptions::default(), 0, 0).is_err());
        assert!(derive_addresses(&source(), DeriveOptions::default(), 0, 10_001).is_err());
        assert!(derive_addresses(&source(), DeriveOptions::default(), u32::MAX, 2).is_err());

        let watched = derive_address_from_extended_public_key(
            &account.extended_public_key,
            Some("bitcoin"),
            0,
            0,
            None,
        )
        .unwrap();
        assert_eq!(
            watched.address,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert!(derive_address_from_extended_public_key(
            &account.extended_public_key,
            None,
            0,
            0,
            None
        )
        .is_err());
        let serialized_private = match &parsed_private {
            ParsedExtendedKey::Private(node, _) => node.serialize_private(XPUB.private_version),
            _ => unreachable!(),
        };
        assert!(derive_address_from_extended_public_key(
            &serialized_private,
            Some("bitcoin"),
            0,
            0,
            None
        )
        .is_err());
        assert!(derive_address_from_extended_public_key(
            &account.extended_public_key,
            Some("bitcoin"),
            HARDENED_OFFSET,
            0,
            None
        )
        .is_err());

        for path in ["relative/0", "m/", "m/00", "m/abc", "m/2147483648"] {
            assert!(parse_path(path).is_err(), "accepted {path}");
        }
        assert_eq!(parse_path("M/0h/1H/2'").unwrap().len(), 3);
        assert!(parse_extended_key("not-a-key").is_err());
        assert!(public_key_to_address(&[4; 33], chain("ethereum").unwrap(), "evm").is_err());
        assert!(public_key_to_address(&[4; 33], chain("tron").unwrap(), "tron").is_err());
        assert!(public_key_to_address(
            &ExtendedPrivateKey::master(&[0; 16]).unwrap().public_key(),
            chain("dogecoin").unwrap(),
            "p2wpkh"
        )
        .is_err());
        assert!(public_key_to_address(
            &ExtendedPrivateKey::master(&[0; 16]).unwrap().public_key(),
            chain("bitcoin").unwrap(),
            "unknown"
        )
        .is_err());
    }

    proptest! {
        #[test]
        fn arbitrary_derivation_paths_never_panic(value in ".{0,512}") {
            let _ = parse_path(&value);
        }

        #[test]
        fn random_non_hardened_private_and_public_children_agree(index in 0u32..HARDENED_OFFSET) {
            let root = ExtendedPrivateKey::master(&[7; 32]).unwrap().derive_path("m/84'/0'/0'").unwrap();
            prop_assert_eq!(root.derive(index).unwrap().public_key(), root.neuter().derive(index).unwrap().public_key);
        }
    }
}
