import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  deriveAccountPrivateKey,
  deriveAccountPublicKey,
  deriveAddress,
  deriveAddresses,
  deriveAddressFromExtendedPublicKey,
  deriveSlip10Ed25519,
  masterFromSeed,
  parseDerivationPath,
  parseExtendedKey,
  supportedChains
} from "../src/index.js";

const bip32Vectors = JSON.parse(readFileSync(new URL("../../test-vectors/bip32-official.json", import.meta.url)));
const slip10Vectors = JSON.parse(readFileSync(new URL("../../test-vectors/slip10-ed25519-official.json", import.meta.url)));

const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const source = { mnemonic };

test("matches SLIP132 Bitcoin account keys and addresses", () => {
  const expected = {
    xpub: ["xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"],
    ypub: ["ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP", "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"],
    zpub: ["zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"]
  };
  for (const [format, [extendedPublicKey, address]] of Object.entries(expected)) {
    const account = deriveAccountPublicKey({ source, chain: "bitcoin", format });
    assert.equal(account.extendedPublicKey, extendedPublicKey);
    assert.equal(deriveAddress({ source, chain: "bitcoin", format }).address, address);
    assert.equal(deriveAddressFromExtendedPublicKey({ chain: "bitcoin", extendedPublicKey }).address, address);
  }
});

test("matches the BIP86 first Taproot address", () => {
  assert.equal(deriveAddress({ source, chain: "bitcoin", scriptType: "p2tr" }).address, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
});

test("derives verified multi-chain addresses", () => {
  const vectors = {
    litecoin: "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez",
    dogecoin: "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC",
    ethereum: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
    solana: "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
  };
  for (const [chain, address] of Object.entries(vectors)) assert.equal(deriveAddress({ source, chain }).address, address);
  assert.match(deriveAddress({ source, chain: "tron" }).address, /^T[1-9A-HJ-NP-Za-km-z]{33}$/);
  assert.match(deriveAddress({ source, chain: "bitcoin-cash" }).address, /^bitcoincash:q/);
});

test("normal APIs exclude private material", () => {
  const value = deriveAddress({ source, chain: "bitcoin" });
  assert.equal("privateKeyHex" in value, false);
  assert.equal("extendedPrivateKey" in value, false);
  assert.match(deriveAccountPrivateKey({ source, chain: "bitcoin" }).extendedPrivateKey, /^zprv/);
});

test("rejects invalid input and hardened public derivation", () => {
  assert.throws(() => deriveAddress({ mnemonic: "abandon abandon", chain: "bitcoin" }), /invalid BIP39/);
  assert.throws(() => parseDerivationPath("m//0"), /invalid path/);
  const xpub = deriveAccountPublicKey({ source, chain: "bitcoin", format: "xpub" }).extendedPublicKey;
  assert.throws(() => parseExtendedKey(xpub).node.derive(0x80000000), /non-hardened/);
  assert.throws(() => deriveAddressFromExtendedPublicKey({ extendedPublicKey: xpub }), /chain is required/);
});

test("derives deterministic batches and lists every supported chain", () => {
  const addresses = deriveAddresses({ source, chain: "bitcoin", count: 3 });
  assert.equal(addresses.length, 3);
  assert.equal(new Set(addresses.map((item) => item.address)).size, 3);
  assert.ok(supportedChains().length >= 18);
});

test("matches every official BIP32 vector and rejects vector 5", () => {
  for (const vector of bip32Vectors.vectors) {
    const root = masterFromSeed(Uint8Array.from(Buffer.from(vector.seedHex, "hex")));
    for (const expected of vector.nodes) {
      const node = root.derivePath(expected.path);
      assert.equal(node.serializePublic("0488b21e"), expected.extendedPublicKey, expected.path);
      assert.equal(node.serializePrivate("0488ade4"), expected.extendedPrivateKey, expected.path);
      assert.equal(parseExtendedKey(expected.extendedPublicKey).format, "xpub");
      assert.equal(parseExtendedKey(expected.extendedPrivateKey).format, "xpub");
    }
  }
  for (const invalid of bip32Vectors.invalidExtendedKeys) {
    assert.throws(() => parseExtendedKey(invalid.value), undefined, invalid.reason);
  }
});

test("matches the official SLIP10 Ed25519 vector", () => {
  const seed = Uint8Array.from(Buffer.from(slip10Vectors.seedHex, "hex"));
  for (const expected of slip10Vectors.nodes) {
    const node = deriveSlip10Ed25519(seed, expected.path);
    assert.equal(Buffer.from(node.chainCode).toString("hex"), expected.chainCodeHex, expected.path);
    assert.equal(Buffer.from(node.privateKey).toString("hex"), expected.privateKeyHex, expected.path);
    assert.equal(Buffer.from(node.publicKey).toString("hex"), expected.publicKeyHex, expected.path);
  }
});
