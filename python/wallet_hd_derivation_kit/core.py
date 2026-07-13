"""Behavioral implementation for Wallet HD Derivation Kit.

The module performs no network I/O. Elliptic-curve operations and address
encoders are provided by ``bip-utils`` and its audited upstream primitives;
this module owns path policy, chain policy, safe result shapes, and the shared
cross-language API contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from bip_utils import (
    Base58Decoder,
    BchP2PKHAddrEncoder,
    Bip32KeyNetVersions,
    Bip32Slip10Ed25519,
    Bip32Slip10Secp256k1,
    Bip39Languages,
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    EthAddrEncoder,
    P2PKHAddrEncoder,
    P2SHAddrEncoder,
    P2TRAddrEncoder,
    P2WPKHAddrEncoder,
    SolAddrEncoder,
    TrxAddrEncoder,
)

API_SCHEMA_VERSION = 1
HARDENED = 0x80000000


class HDWalletError(ValueError):
    """Raised for invalid or unsupported derivation requests."""


FORMATS: dict[str, dict[str, Any]] = {
    "xpub": {"public": "0488b21e", "private": "0488ade4", "purpose": 44, "script": "p2pkh"},
    "ypub": {"public": "049d7cb2", "private": "049d7878", "purpose": 49, "script": "p2sh-p2wpkh"},
    "zpub": {"public": "04b24746", "private": "04b2430c", "purpose": 84, "script": "p2wpkh"},
    "tpub": {"public": "043587cf", "private": "04358394", "purpose": 44, "script": "p2pkh"},
    "upub": {"public": "044a5262", "private": "044a4e28", "purpose": 49, "script": "p2sh-p2wpkh"},
    "vpub": {"public": "045f1cf6", "private": "045f18bc", "purpose": 84, "script": "p2wpkh"},
    "Ltub": {"public": "019da462", "private": "019d9cfe", "purpose": 44, "script": "p2pkh"},
    "Mtub": {"public": "01b26ef6", "private": "01b26792", "purpose": 49, "script": "p2sh-p2wpkh"},
}


def _evm(name: str, symbol: str, coin_type: int = 60) -> dict[str, Any]:
    return {"name": name, "symbol": symbol, "coinType": coin_type, "curve": "secp256k1", "kind": "evm", "defaultScriptType": "evm"}


CHAINS: dict[str, dict[str, Any]] = {
    "bitcoin": {"name": "Bitcoin", "symbol": "BTC", "coinType": 0, "curve": "secp256k1", "defaultFormat": "zpub", "formats": ["xpub", "ypub", "zpub"], "p2pkh": "00", "p2sh": "05", "hrp": "bc"},
    "bitcoin-testnet": {"name": "Bitcoin Testnet", "symbol": "TBTC", "coinType": 1, "curve": "secp256k1", "defaultFormat": "vpub", "formats": ["tpub", "upub", "vpub"], "p2pkh": "6f", "p2sh": "c4", "hrp": "tb"},
    "litecoin": {"name": "Litecoin", "symbol": "LTC", "coinType": 2, "curve": "secp256k1", "defaultFormat": "Ltub", "formats": ["Ltub", "Mtub"], "p2pkh": "30", "p2sh": "32", "hrp": "ltc"},
    "dogecoin": {"name": "Dogecoin", "symbol": "DOGE", "coinType": 3, "curve": "secp256k1", "defaultFormat": "xpub", "formats": ["xpub"], "p2pkh": "1e", "p2sh": "16"},
    "dash": {"name": "Dash", "symbol": "DASH", "coinType": 5, "curve": "secp256k1", "defaultFormat": "xpub", "formats": ["xpub"], "p2pkh": "4c", "p2sh": "10"},
    "digibyte": {"name": "DigiByte", "symbol": "DGB", "coinType": 20, "curve": "secp256k1", "defaultFormat": "xpub", "formats": ["xpub", "ypub", "zpub"], "p2pkh": "1e", "p2sh": "3f", "hrp": "dgb"},
    "bitcoin-cash": {"name": "Bitcoin Cash", "symbol": "BCH", "coinType": 145, "curve": "secp256k1", "defaultFormat": "xpub", "formats": ["xpub"], "p2pkh": "00", "p2sh": "05", "cashaddrPrefix": "bitcoincash", "defaultScriptType": "cashaddr"},
    "zcash-transparent": {"name": "Zcash Transparent", "symbol": "ZEC", "coinType": 133, "curve": "secp256k1", "defaultFormat": "xpub", "formats": ["xpub"], "p2pkh": "1cb8", "p2sh": "1cbd"},
    "ethereum": _evm("Ethereum", "ETH"),
    "ethereum-classic": _evm("Ethereum Classic", "ETC", 61),
    "polygon": _evm("Polygon", "POL"),
    "bsc": _evm("BNB Smart Chain", "BNB"),
    "avalanche-c": _evm("Avalanche C-Chain", "AVAX"),
    "arbitrum": _evm("Arbitrum", "ARB"),
    "optimism": _evm("Optimism", "OP"),
    "base": _evm("Base", "ETH"),
    "tron": {"name": "TRON", "symbol": "TRX", "coinType": 195, "curve": "secp256k1", "kind": "tron", "defaultScriptType": "tron"},
    "solana": {"name": "Solana", "symbol": "SOL", "coinType": 501, "curve": "ed25519", "kind": "solana", "defaultScriptType": "solana"},
}


def _source_seed(source: Mapping[str, Any] | bytes | bytearray) -> bytes:
    if isinstance(source, (bytes, bytearray)):
        seed = bytes(source)
    elif isinstance(source, Mapping) and source.get("seed") is not None:
        raw = source["seed"]
        seed = bytes.fromhex(raw) if isinstance(raw, str) else bytes(raw)
    elif isinstance(source, Mapping) and source.get("seedHex") is not None:
        seed = bytes.fromhex(str(source["seedHex"]))
    elif isinstance(source, Mapping) and isinstance(source.get("mnemonic"), str):
        mnemonic = " ".join(str(source["mnemonic"]).strip().split())
        if source.get("validate", True) and not Bip39MnemonicValidator(Bip39Languages.ENGLISH).IsValid(mnemonic):
            raise HDWalletError("invalid BIP39 English mnemonic")
        seed = Bip39SeedGenerator(mnemonic).Generate(str(source.get("passphrase", "")))
    else:
        raise HDWalletError("source must provide mnemonic, seed, or seedHex")
    if not 16 <= len(seed) <= 64:
        raise HDWalletError("seed must be between 16 and 64 bytes")
    return seed


def _path(path: str, *, ed25519: bool = False) -> str:
    if path == "m":
        return path
    if not isinstance(path, str) or not path.startswith("m/"):
        raise HDWalletError("path must be absolute and start with m")
    parts = path.split("/")[1:]
    if not parts or len(parts) > 255:
        raise HDWalletError("path depth must be between 1 and 255")
    normalized: list[str] = []
    for part in parts:
        hardened = part.endswith(("'", "h", "H"))
        digits = part[:-1] if hardened else part
        if not digits.isascii() or not digits.isdigit():
            raise HDWalletError(f"invalid path component: {part}")
        index = int(digits)
        if not 0 <= index < HARDENED:
            raise HDWalletError("path index must be between 0 and 2147483647")
        if ed25519 and not hardened:
            raise HDWalletError("SLIP-0010 Ed25519 supports hardened children only")
        suffix = "'" if hardened else ""
        normalized.append(f"{index}{suffix}")
    return "m/" + "/".join(normalized)


def _chain(chain_id: str) -> dict[str, Any]:
    try:
        return CHAINS[chain_id]
    except KeyError as exc:
        raise HDWalletError(f"unsupported chain: {chain_id}") from exc


def _format(chain_id: str, fmt: str | None, script_type: str | None) -> tuple[str, dict[str, Any]] | None:
    chain = _chain(chain_id)
    if "formats" not in chain:
        return None
    selected = fmt or ("xpub" if script_type == "p2tr" else chain["defaultFormat"])
    if selected not in chain["formats"]:
        raise HDWalletError(f"format {selected} is not registered for {chain_id}")
    return selected, FORMATS[selected]


def _versions(fmt: dict[str, Any]) -> Bip32KeyNetVersions:
    return Bip32KeyNetVersions(bytes.fromhex(fmt["public"]), bytes.fromhex(fmt["private"]))


def _account_path(chain_id: str, account: int, fmt: str | None, script_type: str | None) -> str:
    account = _index(account, "account")
    chain = _chain(chain_id)
    if chain["curve"] == "ed25519":
        return f"m/44'/{chain['coinType']}'/{account}'"
    if chain.get("kind") in {"evm", "tron"}:
        return f"m/44'/{chain['coinType']}'/{account}'"
    purpose = 86 if script_type == "p2tr" else _format(chain_id, fmt, script_type)[1]["purpose"]  # type: ignore[index]
    return f"m/{purpose}'/{chain['coinType']}'/{account}'"


def _index(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < HARDENED:
        raise HDWalletError(f"{name} must be between 0 and 2147483647")
    return value


def derive_node(source: Mapping[str, Any] | bytes, curve: str = "secp256k1", path: str = "m") -> dict[str, Any]:
    seed = _source_seed(source)
    if curve == "ed25519":
        node = Bip32Slip10Ed25519.FromSeed(seed).DerivePath(_path(path, ed25519=True))
        public = node.PublicKey().RawCompressed().ToBytes()[1:]
    elif curve == "secp256k1":
        node = Bip32Slip10Secp256k1.FromSeed(seed).DerivePath(_path(path))
        public = node.PublicKey().RawCompressed().ToBytes()
    else:
        raise HDWalletError(f"unsupported curve: {curve}")
    return {
        "schemaVersion": API_SCHEMA_VERSION,
        "curve": curve,
        "path": path,
        "publicKeyHex": public.hex(),
        "chainCodeHex": node.ChainCode().ToHex(),
        "depth": node.Depth().ToInt(),
        "childNumber": node.Index().ToInt(),
    }


def derive_account_public_key(source: Mapping[str, Any] | bytes, chain: str = "bitcoin", script_type: str | None = None, account: int = 0, format: str | None = None, path: str | None = None) -> dict[str, Any]:
    info = _chain(chain)
    if info["curve"] == "ed25519":
        raise HDWalletError("Solana SLIP-0010 does not define extended public keys")
    selected, fmt = _format(chain, format, script_type) or ("xpub", FORMATS["xpub"])
    resolved_path = _path(path or _account_path(chain, account, format, script_type))
    node = Bip32Slip10Secp256k1.FromSeed(_source_seed(source), _versions(fmt)).DerivePath(resolved_path)
    return {
        "schemaVersion": API_SCHEMA_VERSION,
        "chain": chain,
        "curve": "secp256k1",
        "path": resolved_path,
        "format": selected,
        "extendedPublicKey": node.PublicKey().ToExtended(),
        "publicKeyHex": node.PublicKey().RawCompressed().ToHex(),
    }


def derive_account_private_key(source: Mapping[str, Any] | bytes, chain: str = "bitcoin", script_type: str | None = None, account: int = 0, format: str | None = None, path: str | None = None) -> dict[str, Any]:
    """Explicitly export account private material."""
    info = _chain(chain)
    resolved_path = _path(path or _account_path(chain, account, format, script_type), ed25519=info["curve"] == "ed25519")
    if info["curve"] == "ed25519":
        node = Bip32Slip10Ed25519.FromSeed(_source_seed(source)).DerivePath(resolved_path)
        return {"schemaVersion": 1, "chain": chain, "curve": "ed25519", "path": resolved_path, "extendedPrivateKey": None, "privateKeyHex": node.PrivateKey().Raw().ToHex(), "publicKeyHex": node.PublicKey().RawCompressed().ToBytes()[1:].hex()}
    selected, fmt = _format(chain, format, script_type) or ("xpub", FORMATS["xpub"])
    node = Bip32Slip10Secp256k1.FromSeed(_source_seed(source), _versions(fmt)).DerivePath(resolved_path)
    return {"schemaVersion": 1, "chain": chain, "curve": "secp256k1", "path": resolved_path, "format": selected, "extendedPrivateKey": node.PrivateKey().ToExtended(), "privateKeyHex": node.PrivateKey().Raw().ToHex(), "publicKeyHex": node.PublicKey().RawCompressed().ToHex()}


def _address(public: bytes, chain_id: str, script_type: str) -> str:
    chain = _chain(chain_id)
    if chain.get("kind") == "evm":
        return EthAddrEncoder.EncodeKey(public)
    if chain.get("kind") == "tron":
        return TrxAddrEncoder.EncodeKey(public)
    if script_type == "cashaddr":
        return BchP2PKHAddrEncoder.EncodeKey(public, hrp=chain["cashaddrPrefix"], net_ver=b"\x00")
    if script_type == "p2tr":
        return P2TRAddrEncoder.EncodeKey(public, hrp=chain["hrp"])
    if script_type == "p2wpkh":
        if "hrp" not in chain:
            raise HDWalletError(f"native SegWit is not registered for {chain_id}")
        return P2WPKHAddrEncoder.EncodeKey(public, hrp=chain["hrp"])
    if script_type == "p2sh-p2wpkh":
        return P2SHAddrEncoder.EncodeKey(public, net_ver=bytes.fromhex(chain["p2sh"]))
    if script_type == "p2pkh":
        return P2PKHAddrEncoder.EncodeKey(public, net_ver=bytes.fromhex(chain["p2pkh"]))
    raise HDWalletError(f"unsupported script type: {script_type}")


def derive_address(source: Mapping[str, Any] | bytes, chain: str = "bitcoin", account: int = 0, change: int = 0, index: int = 0, script_type: str | None = None, format: str | None = None, path: str | None = None) -> dict[str, Any]:
    info = _chain(chain)
    account, change, index = _index(account, "account"), _index(change, "change"), _index(index, "index")
    script = script_type or info.get("defaultScriptType") or (_format(chain, format, None) or (None, {"script": "p2pkh"}))[1]["script"]
    if info["curve"] == "ed25519":
        resolved_path = _path(path or f"m/44'/{info['coinType']}'/{account}'/{index}'", ed25519=True)
        node = Bip32Slip10Ed25519.FromSeed(_source_seed(source)).DerivePath(resolved_path)
        raw_public = node.PublicKey().RawCompressed().ToBytes()
        public = raw_public[1:]
        address = SolAddrEncoder.EncodeKey(raw_public)
    else:
        resolved_path = _path(path or f"{_account_path(chain, account, format, script_type)}/{change}/{index}")
        node = Bip32Slip10Secp256k1.FromSeed(_source_seed(source)).DerivePath(resolved_path)
        public = node.PublicKey().RawCompressed().ToBytes()
        address = _address(public, chain, script)
    return {"schemaVersion": 1, "chain": chain, "curve": info["curve"], "path": resolved_path, "account": account, "change": change, "index": index, "scriptType": script, "address": address, "publicKeyHex": public.hex()}


def derive_addresses(source: Mapping[str, Any] | bytes, *, start: int = 0, count: int = 20, **kwargs: Any) -> list[dict[str, Any]]:
    start = _index(start, "start")
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 10_000 or start + count > HARDENED:
        raise HDWalletError("count must be between 1 and 10000 and stay within the index range")
    return [derive_address(source, index=start + offset, **kwargs) for offset in range(count)]


@dataclass(frozen=True)
class ParsedExtendedKey:
    """Parsed extended-key metadata plus an opaque native node."""

    value: str
    version_hex: str
    format: str
    is_private: bool
    depth: int
    child_number: int
    parent_fingerprint_hex: str
    chain_code_hex: str
    public_key_hex: str
    _node: Any = field(repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if key != "_node"}


def parse_extended_key(value: str) -> ParsedExtendedKey:
    try:
        payload = Base58Decoder.CheckDecode(value)
    except Exception as exc:
        raise HDWalletError("invalid extended key checksum or encoding") from exc
    if len(payload) != 78:
        raise HDWalletError("extended key payload must be 78 bytes")
    version = payload[:4].hex()
    found = next(((name, fmt, private) for name, fmt in FORMATS.items() for private in (False, True) if version == fmt["private" if private else "public"]), None)
    if found is None:
        raise HDWalletError(f"unknown extended-key version: {version}")
    name, fmt, is_private = found
    depth = payload[4]
    if depth == 0 and (payload[5:9] != b"\x00\x00\x00\x00" or payload[9:13] != b"\x00\x00\x00\x00"):
        raise HDWalletError("root extended key must have zero parent fingerprint and child number")
    try:
        node = Bip32Slip10Secp256k1.FromExtendedKey(value, _versions(fmt))
    except Exception as exc:
        raise HDWalletError("invalid extended key material") from exc
    return ParsedExtendedKey(value, version, name, is_private, node.Depth().ToInt(), node.Index().ToInt(), node.ParentFingerPrint().ToHex(), node.ChainCode().ToHex(), node.PublicKey().RawCompressed().ToHex(), node)


def serialize_extended_key(parsed: ParsedExtendedKey, *, private: bool = False, format: str | None = None) -> str:
    """Serialize a parsed key; private export requires ``private=True``."""
    fmt_name = format or parsed.format
    if fmt_name not in FORMATS:
        raise HDWalletError(f"unsupported extended-key format: {fmt_name}")
    node = parsed._node
    # Reparse with the requested version while preserving all key metadata.
    current = node.PrivateKey().ToExtended() if private and not node.IsPublicOnly() else node.PublicKey().ToExtended()
    payload = Base58Decoder.CheckDecode(current)
    version = FORMATS[fmt_name]["private" if private else "public"]
    from bip_utils import Base58Encoder
    if private and node.IsPublicOnly():
        raise HDWalletError("private material is not available from an extended public key")
    return Base58Encoder.CheckEncode(bytes.fromhex(version) + payload[4:])


def derive_address_from_extended_public_key(extended_public_key: str, *, chain: str, change: int = 0, index: int = 0, script_type: str | None = None) -> dict[str, Any]:
    info = _chain(chain)
    if info["curve"] != "secp256k1":
        raise HDWalletError("extended public derivation is available only for secp256k1 chains")
    parsed = parse_extended_key(extended_public_key)
    if parsed.is_private:
        raise HDWalletError("use an extended public key, not an extended private key")
    change, index = _index(change, "change"), _index(index, "index")
    node = parsed._node.ChildKey(change).ChildKey(index)
    public = node.PublicKey().RawCompressed().ToBytes()
    inferred = {"ypub": "p2sh-p2wpkh", "upub": "p2sh-p2wpkh", "Mtub": "p2sh-p2wpkh", "zpub": "p2wpkh", "vpub": "p2wpkh"}.get(parsed.format)
    script = script_type or inferred or info.get("defaultScriptType") or "p2pkh"
    return {"schemaVersion": 1, "chain": chain, "curve": "secp256k1", "path": f"{change}/{index}", "account": 0, "change": change, "index": index, "scriptType": script, "address": _address(public, chain, script), "publicKeyHex": public.hex()}


def supported_chains() -> list[dict[str, Any]]:
    return [{"id": chain_id, **info} for chain_id, info in CHAINS.items()]
