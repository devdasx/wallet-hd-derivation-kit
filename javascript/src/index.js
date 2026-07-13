// @ts-self-types="./index.d.ts"
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { accountPath, CHAINS, resolveFormat, supportedChains } from "./chains.js";
import { masterFromSeed, parseExtendedKey } from "./bip32.js";
import { deriveSlip10Ed25519 } from "./slip10.js";
import { publicKeyToAddress } from "./address.js";
import { base58Encode, bytesToHex, normalizeSeed } from "./utils.js";

export * from "./address.js";
export * from "./bip32.js";
export * from "./chains.js";
export * from "./slip10.js";

export const API_SCHEMA_VERSION = 1;

export function sourceToSeed(source) {
  if (!source || typeof source !== "object") throw new Error("source is required");
  if (source.seed !== undefined) return normalizeSeed(source.seed);
  if (source.seedHex !== undefined) return normalizeSeed(source.seedHex);
  if (typeof source.mnemonic === "string") {
    if (source.validate !== false && !validateMnemonic(source.mnemonic, wordlist)) throw new Error("invalid BIP39 English mnemonic");
    return mnemonicToSeedSync(source.mnemonic, source.passphrase || "", wordlist);
  }
  throw new Error("source must provide mnemonic, seed, or seedHex");
}

export function deriveNode({ source, curve = "secp256k1", path = "m" }) {
  const seed = sourceToSeed(source);
  if (curve === "ed25519") {
    const node = deriveSlip10Ed25519(seed, path);
    return { schemaVersion: API_SCHEMA_VERSION, curve, path, publicKeyHex: bytesToHex(node.publicKey), chainCodeHex: bytesToHex(node.chainCode), depth: node.depth, childNumber: node.childNumber };
  }
  const node = masterFromSeed(seed).derivePath(path);
  return { schemaVersion: API_SCHEMA_VERSION, curve, path, publicKeyHex: bytesToHex(node.publicKey), chainCodeHex: bytesToHex(node.chainCode), depth: node.depth, childNumber: node.childNumber };
}

export function deriveAccountPublicKey(options = {}) {
  const chainId = options.chain || "bitcoin";
  const chain = requireChain(chainId);
  const path = options.path || accountPath(chainId, options);
  const seed = sourceToSeed(options.source || options);
  if (chain.curve === "ed25519") throw new Error("Solana SLIP10 does not define extended public keys");
  const format = resolveFormat(chainId, options.format, options.scriptType);
  const node = masterFromSeed(seed).derivePath(path);
  return {
    schemaVersion: API_SCHEMA_VERSION,
    chain: chainId,
    curve: chain.curve,
    path,
    format: format?.name || "xpub",
    extendedPublicKey: node.serializePublic(format?.publicVersion || "0488b21e"),
    publicKeyHex: bytesToHex(node.publicKey)
  };
}

export function deriveAccountPrivateKey(options = {}) {
  const chainId = options.chain || "bitcoin";
  const chain = requireChain(chainId);
  const path = options.path || accountPath(chainId, options);
  const seed = sourceToSeed(options.source || options);
  if (chain.curve === "ed25519") {
    const node = deriveSlip10Ed25519(seed, path);
    return { schemaVersion: API_SCHEMA_VERSION, chain: chainId, curve: chain.curve, path, privateKeyHex: bytesToHex(node.privateKey), publicKeyHex: bytesToHex(node.publicKey), extendedPrivateKey: null };
  }
  const format = resolveFormat(chainId, options.format, options.scriptType);
  const node = masterFromSeed(seed).derivePath(path);
  return {
    schemaVersion: API_SCHEMA_VERSION,
    chain: chainId,
    curve: chain.curve,
    path,
    format: format?.name || "xpub",
    extendedPrivateKey: node.serializePrivate(format?.privateVersion || "0488ade4"),
    privateKeyHex: bytesToHex(node.privateKey),
    publicKeyHex: bytesToHex(node.publicKey)
  };
}

export function deriveAddress(options = {}) {
  const chainId = options.chain || "bitcoin";
  const chain = requireChain(chainId);
  const account = integer(options.account, 0, "account");
  const change = integer(options.change, 0, "change");
  const index = integer(options.index, 0, "index");
  const seed = sourceToSeed(options.source || options);
  const scriptType = options.scriptType || chain.defaultScriptType || resolveFormat(chainId, options.format)?.scriptType || "p2pkh";
  let path;
  let publicKey;
  if (chain.curve === "ed25519") {
    path = options.path || `m/44'/${chain.coinType}'/${account}'/${index}'`;
    const node = deriveSlip10Ed25519(seed, path);
    publicKey = node.publicKey;
    return result(chainId, chain, path, account, change, index, scriptType, base58Encode(publicKey), publicKey);
  }
  path = options.path || `${accountPath(chainId, { account, format: options.format, scriptType })}/${change}/${index}`;
  const node = masterFromSeed(seed).derivePath(path);
  publicKey = node.publicKey;
  return result(chainId, chain, path, account, change, index, scriptType, publicKeyToAddress(publicKey, { chain: chainId, scriptType }), publicKey);
}

export function deriveAddresses(options = {}) {
  const start = integer(options.start, 0, "start");
  const count = integer(options.count, 20, "count");
  if (count < 1 || count > 10000) throw new Error("count must be between 1 and 10000");
  return Array.from({ length: count }, (_, offset) => deriveAddress({ ...options, index: start + offset }));
}

export function deriveAddressFromExtendedPublicKey(options = {}) {
  if (!options.extendedPublicKey) throw new Error("extendedPublicKey is required");
  const chainId = options.chain;
  if (!chainId) throw new Error("chain is required because extended-key version bytes do not identify every coin");
  const chain = requireChain(chainId);
  if (chain.curve !== "secp256k1") throw new Error("extended public derivation is available only for secp256k1 chains");
  const parsed = parseExtendedKey(options.extendedPublicKey);
  if (parsed.isPrivate) throw new Error("use an extended public key, not an extended private key");
  const change = integer(options.change, 0, "change");
  const index = integer(options.index, 0, "index");
  const scriptType = options.scriptType || inferScriptType(parsed.versionHex, chain.defaultScriptType);
  const node = parsed.node.derive(change).derive(index);
  return result(chainId, chain, `${change}/${index}`, 0, change, index, scriptType, publicKeyToAddress(node.publicKey, { chain: chainId, scriptType }), node.publicKey);
}

function result(chainId, chain, path, account, change, index, scriptType, address, publicKey) {
  return { schemaVersion: API_SCHEMA_VERSION, chain: chainId, curve: chain.curve, path, account, change, index, scriptType, address, publicKeyHex: bytesToHex(publicKey) };
}

function inferScriptType(versionHex, fallback = "p2pkh") {
  const versions = {
    "049d7cb2": "p2sh-p2wpkh", "044a5262": "p2sh-p2wpkh", "01b26ef6": "p2sh-p2wpkh",
    "04b24746": "p2wpkh", "045f1cf6": "p2wpkh"
  };
  return versions[versionHex] || fallback;
}

function integer(value, fallback, name) {
  const result = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(result) || result < 0 || result >= 0x80000000) throw new Error(`${name} must be between 0 and 2147483647`);
  return result;
}

function requireChain(chainId) {
  const chain = CHAINS[chainId];
  if (!chain) throw new Error(`unsupported chain: ${chainId}`);
  return chain;
}

export { supportedChains };
