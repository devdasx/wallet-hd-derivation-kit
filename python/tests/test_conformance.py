import json
from pathlib import Path

import pytest

from wallet_hd_derivation_kit import (
    HDWalletError,
    derive_account_private_key,
    derive_account_public_key,
    derive_address,
    derive_address_from_extended_public_key,
    derive_addresses,
    derive_node,
    parse_extended_key,
    serialize_extended_key,
    supported_chains,
)

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
SOURCE = {"mnemonic": MNEMONIC}


def test_bitcoin_slip132_and_watch_only():
    account = derive_account_public_key(SOURCE, format="zpub")
    assert account["extendedPublicKey"] == "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
    direct = derive_address(SOURCE)
    watched = derive_address_from_extended_public_key(account["extendedPublicKey"], chain="bitcoin")
    assert direct["address"] == watched["address"] == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"


def test_private_export_is_explicit_and_round_trips():
    secret = derive_account_private_key(SOURCE, format="zpub")
    assert secret["extendedPrivateKey"] == "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE"
    parsed = parse_extended_key(secret["extendedPrivateKey"])
    assert parsed.is_private
    assert serialize_extended_key(parsed, private=True) == secret["extendedPrivateKey"]
    assert "privateKeyHex" not in parsed.to_dict()
    assert secret["extendedPrivateKey"] not in repr(parsed)


@pytest.mark.parametrize(
    ("chain", "expected"),
    [
        ("litecoin", "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez"),
        ("dogecoin", "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC"),
        ("dash", "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5"),
        ("digibyte", "DG1KhhBKpsyWXTakHNezaDQ34focsXjN1i"),
        ("bitcoin-cash", "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6"),
        ("zcash-transparent", "t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F"),
        ("ethereum", "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
        ("ethereum-classic", "0xFA22515E43658ce56A7682B801e9B5456f511420"),
        ("tron", "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"),
        ("solana", "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"),
    ],
)
def test_multichain_vectors(chain, expected):
    assert derive_address(SOURCE, chain=chain)["address"] == expected


def test_bip86_and_node():
    assert derive_address(SOURCE, script_type="p2tr")["address"] == "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    node = derive_node(SOURCE, path="m/0h/1H/2'")
    assert node["depth"] == 3


def test_batches_and_failures():
    batch = derive_addresses(SOURCE, chain="ethereum", start=3, count=4)
    assert [item["index"] for item in batch] == [3, 4, 5, 6]
    assert len(supported_chains()) == 18
    with pytest.raises(HDWalletError):
        derive_address({"mnemonic": "abandon " * 12})
    with pytest.raises(HDWalletError):
        derive_node(b"short")
    with pytest.raises(HDWalletError):
        derive_node(SOURCE, path="relative/0")
    with pytest.raises(Exception):
        derive_address_from_extended_public_key(derive_account_public_key(SOURCE)["extendedPublicKey"], chain="bitcoin", change=0x80000000)


def test_all_public_contract_branches_and_decoder_failures():
    from wallet_hd_derivation_kit.core import _base58check_decode, _base58check_encode

    seed = bytes(range(16))
    assert derive_node(seed)["depth"] == 0
    assert derive_node({"seed": seed})["depth"] == 0
    assert derive_node({"seed": seed.hex()})["depth"] == 0
    assert derive_node({"seedHex": seed.hex()})["depth"] == 0
    assert derive_node(SOURCE, curve="ed25519", path="m/0h")["depth"] == 1
    assert derive_account_private_key(SOURCE, chain="solana")["extendedPrivateKey"] is None
    assert derive_address(SOURCE, script_type="p2pkh", format="xpub")["address"].startswith("1")
    assert derive_address(SOURCE, script_type="p2sh-p2wpkh", format="ypub")["address"].startswith("3")
    assert derive_address(SOURCE, chain="litecoin", script_type="p2wpkh", path="m/84'/2'/0'/0/0")["address"].startswith("ltc1")

    zpub = derive_account_public_key(SOURCE)["extendedPublicKey"]
    parsed_public = parse_extended_key(zpub)
    assert serialize_extended_key(parsed_public, format="xpub").startswith("xpub")

    failures = [
        lambda: derive_node({}),
        lambda: derive_node(SOURCE, curve="p256"),
        lambda: derive_node(SOURCE, path="m/"),
        lambda: derive_node(SOURCE, path="m/abc"),
        lambda: derive_node(SOURCE, path="m/2147483648"),
        lambda: derive_node(SOURCE, curve="ed25519", path="m/0"),
        lambda: derive_address(SOURCE, chain="unknown"),
        lambda: derive_account_public_key(SOURCE, chain="solana"),
        lambda: derive_account_public_key(SOURCE, chain="bitcoin", format="tpub"),
        lambda: derive_address(SOURCE, chain="dogecoin", script_type="p2wpkh"),
        lambda: derive_address(SOURCE, script_type="unknown"),
        lambda: derive_addresses(SOURCE, count=0),
        lambda: parse_extended_key("not-base58!"),
        lambda: parse_extended_key(_base58check_encode(b"short")),
        lambda: serialize_extended_key(parsed_public, private=True),
        lambda: serialize_extended_key(parsed_public, format="unknown"),
        lambda: derive_address_from_extended_public_key(
            derive_account_private_key(SOURCE)["extendedPrivateKey"], chain="bitcoin"
        ),
        lambda: derive_address_from_extended_public_key(zpub, chain="solana"),
    ]
    payload = _base58check_decode(zpub)
    failures.append(lambda: parse_extended_key(_base58check_encode(bytes.fromhex("deadbeef") + payload[4:])))
    for operation in failures:
        with pytest.raises((HDWalletError, ValueError, TypeError)):
            operation()


def test_rejects_every_official_bip32_invalid_extended_key():
    path = Path(__file__).parents[2] / "test-vectors" / "bip32-official.json"
    vectors = json.loads(path.read_text(encoding="utf-8"))
    for invalid in vectors["invalidExtendedKeys"]:
        with pytest.raises(HDWalletError, match="invalid|unknown|root"):
            parse_extended_key(invalid["value"])


def test_matches_every_official_bip32_valid_node():
    path = Path(__file__).parents[2] / "test-vectors" / "bip32-official.json"
    vectors = json.loads(path.read_text(encoding="utf-8"))
    for vector in vectors["vectors"]:
        source = {"seedHex": vector["seedHex"]}
        for expected in vector["nodes"]:
            public = derive_account_public_key(source, format="xpub", path=expected["path"])
            private = derive_account_private_key(source, format="xpub", path=expected["path"])
            assert public["extendedPublicKey"] == expected["extendedPublicKey"]
            assert private["extendedPrivateKey"] == expected["extendedPrivateKey"]
