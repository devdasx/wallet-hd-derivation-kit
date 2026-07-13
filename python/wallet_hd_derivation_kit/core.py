"""Offline HD derivation with pinned, narrowly scoped cryptographic primitives.

Elliptic-curve arithmetic is delegated to libsecp256k1 through ``coincurve``
and to libsodium through ``PyNaCl``. This module implements standards framing,
path policy, serialization, and address encodings; it performs no network I/O.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping

from coincurve import PrivateKey, PublicKey
from Crypto.Hash import RIPEMD160, keccak
from mnemonic import Mnemonic
from nacl.signing import SigningKey

API_SCHEMA_VERSION = 1
HARDENED = 0x80000000
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_GENERATORS = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
CASHADDR_GENERATORS = (0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470)
_MNEMONIC = Mnemonic("english")


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
    return {
        "name": name,
        "symbol": symbol,
        "coinType": coin_type,
        "curve": "secp256k1",
        "kind": "evm",
        "defaultScriptType": "evm",
    }


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


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _hash160(value: bytes) -> bytes:
    digest = RIPEMD160.new()
    digest.update(_sha256(value))
    return digest.digest()


def _keccak256(value: bytes) -> bytes:
    digest = keccak.new(digest_bits=256)
    digest.update(value)
    return digest.digest()


def _ser32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise HDWalletError("invalid uint32")
    return value.to_bytes(4, "big")


def _base58_encode(value: bytes) -> str:
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, digit = divmod(number, 58)
        encoded = BASE58_ALPHABET[digit] + encoded
    leading = len(value) - len(value.lstrip(b"\0"))
    return "1" * leading + (encoded or ("" if leading else "1"))


def _base58_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise HDWalletError("base58 value must not be empty")
    number = 0
    for character in value:
        digit = BASE58_ALPHABET.find(character)
        if digit < 0:
            raise HDWalletError(f"invalid base58 character: {character}")
        number = number * 58 + digit
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading = len(value) - len(value.lstrip("1"))
    return b"\0" * leading + body


def _base58check_encode(payload: bytes) -> str:
    return _base58_encode(payload + _sha256(_sha256(payload))[:4])


def _base58check_decode(value: str) -> bytes:
    decoded = _base58_decode(value)
    if len(decoded) < 5:
        raise HDWalletError("invalid Base58Check length")
    payload, checksum = decoded[:-4], decoded[-4:]
    if not hmac.compare_digest(checksum, _sha256(_sha256(payload))[:4]):
        raise HDWalletError("invalid Base58Check checksum")
    return payload


def _convert_bits(data: bytes | list[int], from_bits: int, to_bits: int, pad: bool) -> list[int]:
    accumulator = 0
    bits = 0
    output: list[int] = []
    mask = (1 << to_bits) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise HDWalletError("invalid convertBits value")
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            output.append((accumulator >> bits) & mask)
    if pad and bits:
        output.append((accumulator << (to_bits - bits)) & mask)
    elif not pad and (bits >= from_bits or ((accumulator << (to_bits - bits)) & mask)):
        raise HDWalletError("invalid incomplete bit group")
    return output


def _bech32_polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(BECH32_GENERATORS):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _segwit_address(hrp: str | None, version: int, program: bytes) -> str:
    if not hrp:
        raise HDWalletError("chain does not define a SegWit HRP")
    words = [version, *_convert_bits(program, 8, 5, True)]
    expanded = [ord(character) >> 5 for character in hrp] + [0] + [ord(character) & 31 for character in hrp]
    constant = 1 if version == 0 else 0x2BC830A3
    polymod = _bech32_polymod(expanded + words + [0] * 6) ^ constant
    checksum = [(polymod >> (5 * (5 - index))) & 31 for index in range(6)]
    return f"{hrp}1{''.join(BECH32_ALPHABET[word] for word in words + checksum)}"


def _cashaddr_polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 35
        checksum = ((checksum & 0x07FFFFFFFF) << 5) ^ value
        for index, generator in enumerate(CASHADDR_GENERATORS):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _cash_address(prefix: str, public_key_hash: bytes) -> str:
    payload = _convert_bits(b"\0" + public_key_hash, 8, 5, True)
    prefix_values = [ord(character) & 31 for character in prefix]
    polymod = _cashaddr_polymod(prefix_values + [0] + payload + [0] * 8) ^ 1
    checksum = [(polymod >> (5 * (7 - index))) & 31 for index in range(8)]
    return f"{prefix}:{''.join(BECH32_ALPHABET[value] for value in payload + checksum)}"


def _source_seed(source: Mapping[str, Any] | bytes | bytearray) -> bytes:
    try:
        if isinstance(source, (bytes, bytearray)):
            seed = bytes(source)
        elif isinstance(source, Mapping) and source.get("seed") is not None:
            raw = source["seed"]
            seed = bytes.fromhex(raw) if isinstance(raw, str) else bytes(raw)
        elif isinstance(source, Mapping) and source.get("seedHex") is not None:
            seed = bytes.fromhex(str(source["seedHex"]))
        elif isinstance(source, Mapping) and isinstance(source.get("mnemonic"), str):
            mnemonic = " ".join(str(source["mnemonic"]).strip().split())
            if source.get("validate", True) and not _MNEMONIC.check(mnemonic):
                raise HDWalletError("invalid BIP39 English mnemonic")
            seed = _MNEMONIC.to_seed(mnemonic, str(source.get("passphrase", "")))
        else:
            raise HDWalletError("source must provide mnemonic, seed, or seedHex")
    except (TypeError, ValueError) as exc:
        if isinstance(exc, HDWalletError):
            raise
        raise HDWalletError("invalid seed encoding") from exc
    if not 16 <= len(seed) <= 64:
        raise HDWalletError("seed must be between 16 and 64 bytes")
    return seed


def _path(path: str, *, ed25519: bool = False) -> list[int]:
    if path == "m":
        return []
    if not isinstance(path, str) or not path.startswith("m/"):
        raise HDWalletError("path must be absolute and start with m")
    parts = path.split("/")[1:]
    if not parts or len(parts) > 255:
        raise HDWalletError("path depth must be between 1 and 255")
    output: list[int] = []
    for part in parts:
        hardened = part.endswith(("'", "h", "H"))
        digits = part[:-1] if hardened else part
        if not digits.isascii() or not digits.isdigit() or (len(digits) > 1 and digits.startswith("0")):
            raise HDWalletError(f"invalid path component: {part}")
        index = int(digits)
        if not 0 <= index < HARDENED:
            raise HDWalletError("path index must be between 0 and 2147483647")
        if ed25519 and not hardened:
            raise HDWalletError("SLIP-0010 Ed25519 supports hardened children only")
        output.append(index + (HARDENED if hardened else 0))
    return output


@dataclass(frozen=True)
class _SecpNode:
    private_key: bytes | None = field(default=None, repr=False)
    public_key: bytes = b""
    chain_code: bytes = b""
    depth: int = 0
    parent_fingerprint: bytes = b"\0\0\0\0"
    child_number: int = 0

    @classmethod
    def from_seed(cls, seed: bytes) -> _SecpNode:
        material = seed
        while True:
            digest = hmac.new(b"Bitcoin seed", material, hashlib.sha512).digest()
            scalar = int.from_bytes(digest[:32], "big")
            if 0 < scalar < SECP256K1_ORDER:
                private_key = digest[:32]
                return cls(private_key, PrivateKey(private_key).public_key.format(compressed=True), digest[32:])
            material = digest

    @property
    def fingerprint(self) -> bytes:
        return _hash160(self.public_key)[:4]

    def derive(self, index: int) -> _SecpNode:
        if not 0 <= index <= 0xFFFFFFFF or self.depth >= 255:
            raise HDWalletError("child index or depth out of range")
        hardened = index >= HARDENED
        if hardened and self.private_key is None:
            raise HDWalletError("extended public keys cannot derive hardened children")
        data = (b"\0" + self.private_key if hardened else self.public_key) + _ser32(index)  # type: ignore[operator]
        digest = hmac.new(self.chain_code, data, hashlib.sha512).digest()
        tweak = int.from_bytes(digest[:32], "big")
        if tweak >= SECP256K1_ORDER:
            raise HDWalletError("invalid BIP32 child tweak")
        if self.private_key is not None:
            scalar = (int.from_bytes(self.private_key, "big") + tweak) % SECP256K1_ORDER
            if scalar == 0:
                raise HDWalletError("invalid zero BIP32 child key")
            private_key = scalar.to_bytes(32, "big")
            public_key = PrivateKey(private_key).public_key.format(compressed=True)
        else:
            if tweak == 0:
                public_key = self.public_key
            else:
                try:
                    public_key = PublicKey(self.public_key).add(digest[:32]).format(compressed=True)
                except ValueError as exc:
                    raise HDWalletError("invalid zero BIP32 public child") from exc
            private_key = None
        return _SecpNode(private_key, public_key, digest[32:], self.depth + 1, self.fingerprint, index)

    def derive_path(self, path: str) -> _SecpNode:
        node = self
        for index in _path(path):
            node = node.derive(index)
        return node

    def serialize(self, version: bytes, *, private: bool) -> str:
        if len(version) != 4:
            raise HDWalletError("extended-key version must be four bytes")
        if private:
            if self.private_key is None:
                raise HDWalletError("private material is not available from an extended public key")
            key_data = b"\0" + self.private_key
        else:
            key_data = self.public_key
        payload = version + bytes([self.depth]) + self.parent_fingerprint + _ser32(self.child_number) + self.chain_code + key_data
        return _base58check_encode(payload)


@dataclass(frozen=True)
class _EdNode:
    private_key: bytes = field(repr=False)
    public_key: bytes = b""
    chain_code: bytes = field(default=b"", repr=False)
    depth: int = 0
    child_number: int = 0


def _ed25519_from_seed(seed: bytes, path: str) -> _EdNode:
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    private_key, chain_code = digest[:32], digest[32:]
    depth = 0
    child_number = 0
    for index in _path(path, ed25519=True):
        digest = hmac.new(chain_code, b"\0" + private_key + _ser32(index), hashlib.sha512).digest()
        private_key, chain_code = digest[:32], digest[32:]
        depth += 1
        child_number = index
    return _EdNode(private_key, bytes(SigningKey(private_key).verify_key), chain_code, depth, child_number)


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


def _index(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < HARDENED:
        raise HDWalletError(f"{name} must be between 0 and 2147483647")
    return value


def _account_path(chain_id: str, account: int, fmt: str | None, script_type: str | None) -> str:
    account = _index(account, "account")
    chain = _chain(chain_id)
    if chain["curve"] == "ed25519" or chain.get("kind") in {"evm", "tron"}:
        return f"m/44'/{chain['coinType']}'/{account}'"
    purpose = 86 if script_type == "p2tr" else _format(chain_id, fmt, script_type)[1]["purpose"]  # type: ignore[index]
    return f"m/{purpose}'/{chain['coinType']}'/{account}'"


def _evm_address(public_key: bytes) -> tuple[str, bytes]:
    uncompressed = PublicKey(public_key).format(compressed=False)
    raw = _keccak256(uncompressed[1:])[-20:]
    clean = raw.hex()
    checksum_hash = _keccak256(clean.encode("ascii")).hex()
    checksummed = "".join(character.upper() if int(checksum_hash[index], 16) >= 8 else character for index, character in enumerate(clean))
    return "0x" + checksummed, raw


def _taproot_output_key(public_key: bytes) -> bytes:
    x_only = PublicKey(public_key).format(compressed=True)[1:]
    tag_hash = _sha256(b"TapTweak")
    tweak_bytes = _sha256(tag_hash + tag_hash + x_only)
    if int.from_bytes(tweak_bytes, "big") >= SECP256K1_ORDER:
        raise HDWalletError("invalid Taproot tweak")
    return PublicKey(b"\x02" + x_only).add(tweak_bytes).format(compressed=True)[1:]


def _address(public_key: bytes, chain_id: str, script_type: str) -> str:
    chain = _chain(chain_id)
    if chain.get("kind") == "evm":
        return _evm_address(public_key)[0]
    if chain.get("kind") == "tron":
        return _base58check_encode(b"\x41" + _evm_address(public_key)[1])
    if script_type == "cashaddr":
        return _cash_address(chain["cashaddrPrefix"], _hash160(public_key))
    if script_type == "p2tr":
        return _segwit_address(chain.get("hrp"), 1, _taproot_output_key(public_key))
    if script_type == "p2wpkh":
        return _segwit_address(chain.get("hrp"), 0, _hash160(public_key))
    if script_type == "p2sh-p2wpkh":
        redeem_script = b"\0\x14" + _hash160(public_key)
        return _base58check_encode(bytes.fromhex(chain["p2sh"]) + _hash160(redeem_script))
    if script_type == "p2pkh":
        return _base58check_encode(bytes.fromhex(chain["p2pkh"]) + _hash160(public_key))
    raise HDWalletError(f"unsupported script type: {script_type}")


def derive_node(source: Mapping[str, Any] | bytes, curve: str = "secp256k1", path: str = "m") -> dict[str, Any]:
    seed = _source_seed(source)
    if curve == "ed25519":
        derived_node: _EdNode | _SecpNode = _ed25519_from_seed(seed, path)
    elif curve == "secp256k1":
        derived_node = _SecpNode.from_seed(seed).derive_path(path)
    else:
        raise HDWalletError(f"unsupported curve: {curve}")
    return {"schemaVersion": API_SCHEMA_VERSION, "curve": curve, "path": path, "publicKeyHex": derived_node.public_key.hex(), "chainCodeHex": derived_node.chain_code.hex(), "depth": derived_node.depth, "childNumber": derived_node.child_number}


def derive_account_public_key(source: Mapping[str, Any] | bytes, chain: str = "bitcoin", script_type: str | None = None, account: int = 0, format: str | None = None, path: str | None = None) -> dict[str, Any]:
    info = _chain(chain)
    if info["curve"] == "ed25519":
        raise HDWalletError("Solana SLIP-0010 does not define extended public keys")
    selected, fmt = _format(chain, format, script_type) or ("xpub", FORMATS["xpub"])
    resolved_path = path or _account_path(chain, account, format, script_type)
    node = _SecpNode.from_seed(_source_seed(source)).derive_path(resolved_path)
    return {"schemaVersion": API_SCHEMA_VERSION, "chain": chain, "curve": "secp256k1", "path": resolved_path, "format": selected, "extendedPublicKey": node.serialize(bytes.fromhex(fmt["public"]), private=False), "publicKeyHex": node.public_key.hex()}


def derive_account_private_key(source: Mapping[str, Any] | bytes, chain: str = "bitcoin", script_type: str | None = None, account: int = 0, format: str | None = None, path: str | None = None) -> dict[str, Any]:
    """Explicitly export account private material."""
    info = _chain(chain)
    resolved_path = path or _account_path(chain, account, format, script_type)
    if info["curve"] == "ed25519":
        ed_node = _ed25519_from_seed(_source_seed(source), resolved_path)
        return {"schemaVersion": 1, "chain": chain, "curve": "ed25519", "path": resolved_path, "extendedPrivateKey": None, "privateKeyHex": ed_node.private_key.hex(), "publicKeyHex": ed_node.public_key.hex()}
    selected, fmt = _format(chain, format, script_type) or ("xpub", FORMATS["xpub"])
    secp_node = _SecpNode.from_seed(_source_seed(source)).derive_path(resolved_path)
    assert secp_node.private_key is not None
    return {"schemaVersion": 1, "chain": chain, "curve": "secp256k1", "path": resolved_path, "format": selected, "extendedPrivateKey": secp_node.serialize(bytes.fromhex(fmt["private"]), private=True), "privateKeyHex": secp_node.private_key.hex(), "publicKeyHex": secp_node.public_key.hex()}


def derive_address(source: Mapping[str, Any] | bytes, chain: str = "bitcoin", account: int = 0, change: int = 0, index: int = 0, script_type: str | None = None, format: str | None = None, path: str | None = None) -> dict[str, Any]:
    info = _chain(chain)
    account, change, index = _index(account, "account"), _index(change, "change"), _index(index, "index")
    script = script_type or info.get("defaultScriptType") or (_format(chain, format, None) or (None, {"script": "p2pkh"}))[1]["script"]
    if info["curve"] == "ed25519":
        resolved_path = path or f"m/44'/{info['coinType']}'/{account}'/{index}'"
        ed_node = _ed25519_from_seed(_source_seed(source), resolved_path)
        public_key = ed_node.public_key
        address = _base58_encode(public_key)
    else:
        resolved_path = path or f"{_account_path(chain, account, format, script_type)}/{change}/{index}"
        secp_node = _SecpNode.from_seed(_source_seed(source)).derive_path(resolved_path)
        public_key = secp_node.public_key
        address = _address(public_key, chain, script)
    return {"schemaVersion": 1, "chain": chain, "curve": info["curve"], "path": resolved_path, "account": account, "change": change, "index": index, "scriptType": script, "address": address, "publicKeyHex": public_key.hex()}


def derive_addresses(source: Mapping[str, Any] | bytes, *, start: int = 0, count: int = 20, **kwargs: Any) -> list[dict[str, Any]]:
    start = _index(start, "start")
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 10_000 or start + count > HARDENED:
        raise HDWalletError("count must be between 1 and 10000 and stay within the index range")
    return [derive_address(source, index=start + offset, **kwargs) for offset in range(count)]


@dataclass(frozen=True)
class ParsedExtendedKey:
    """Parsed extended-key metadata plus an opaque native node."""

    value: str = field(repr=False)
    version_hex: str = ""
    format: str = ""
    is_private: bool = False
    depth: int = 0
    child_number: int = 0
    parent_fingerprint_hex: str = ""
    chain_code_hex: str = field(default="", repr=False)
    public_key_hex: str = ""
    _node: _SecpNode = field(default_factory=_SecpNode, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if key != "_node"}


def parse_extended_key(value: str) -> ParsedExtendedKey:
    try:
        payload = _base58check_decode(value)
    except (HDWalletError, TypeError, ValueError) as exc:
        raise HDWalletError("invalid extended key checksum or encoding") from exc
    if len(payload) != 78:
        raise HDWalletError("extended key payload must be 78 bytes")
    version = payload[:4].hex()
    found = next(((name, fmt, private) for name, fmt in FORMATS.items() for private in (False, True) if version == fmt["private" if private else "public"]), None)
    if found is None:
        raise HDWalletError(f"unknown extended-key version: {version}")
    name, _, is_private = found
    depth = payload[4]
    parent_fingerprint = payload[5:9]
    child_number = int.from_bytes(payload[9:13], "big")
    chain_code = payload[13:45]
    key_data = payload[45:]
    if depth == 0 and (parent_fingerprint != b"\0\0\0\0" or child_number != 0):
        raise HDWalletError("root extended key must have zero parent fingerprint and child number")
    try:
        if is_private:
            if key_data[0] != 0 or not 0 < int.from_bytes(key_data[1:], "big") < SECP256K1_ORDER:
                raise HDWalletError("invalid extended private key material")
            private_key = key_data[1:]
            public_key = PrivateKey(private_key).public_key.format(compressed=True)
        else:
            if key_data[0] not in (2, 3):
                raise HDWalletError("invalid compressed extended public key")
            public_key = PublicKey(key_data).format(compressed=True)
            private_key = None
    except (IndexError, ValueError) as exc:
        raise HDWalletError("invalid extended key material") from exc
    node = _SecpNode(private_key, public_key, chain_code, depth, parent_fingerprint, child_number)
    return ParsedExtendedKey(value, version, name, is_private, depth, child_number, parent_fingerprint.hex(), chain_code.hex(), public_key.hex(), node)


def serialize_extended_key(parsed: ParsedExtendedKey, *, private: bool = False, format: str | None = None) -> str:
    """Serialize a parsed key; private export requires ``private=True``."""
    fmt_name = format or parsed.format
    if fmt_name not in FORMATS:
        raise HDWalletError(f"unsupported extended-key format: {fmt_name}")
    version = bytes.fromhex(FORMATS[fmt_name]["private" if private else "public"])
    return parsed._node.serialize(version, private=private)


def derive_address_from_extended_public_key(extended_public_key: str, *, chain: str, change: int = 0, index: int = 0, script_type: str | None = None) -> dict[str, Any]:
    info = _chain(chain)
    if info["curve"] != "secp256k1":
        raise HDWalletError("extended public derivation is available only for secp256k1 chains")
    parsed = parse_extended_key(extended_public_key)
    if parsed.is_private:
        raise HDWalletError("use an extended public key, not an extended private key")
    change, index = _index(change, "change"), _index(index, "index")
    node = parsed._node.derive(change).derive(index)
    inferred = {"ypub": "p2sh-p2wpkh", "upub": "p2sh-p2wpkh", "Mtub": "p2sh-p2wpkh", "zpub": "p2wpkh", "vpub": "p2wpkh"}.get(parsed.format)
    script = script_type or inferred or info.get("defaultScriptType") or "p2pkh"
    return {"schemaVersion": 1, "chain": chain, "curve": "secp256k1", "path": f"{change}/{index}", "account": 0, "change": change, "index": index, "scriptType": script, "address": _address(node.public_key, chain, script), "publicKeyHex": node.public_key.hex()}


def supported_chains() -> list[dict[str, Any]]:
    return [{"id": chain_id, **info} for chain_id, info in CHAINS.items()]
