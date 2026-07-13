import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { EXTENDED_KEY_FORMATS } from "./chains.js";
import {
  base58CheckDecode,
  base58CheckEncode,
  bytesToHex,
  bytesToNumber,
  concatBytes,
  hash160,
  hexToBytes,
  normalizeSeed,
  numberToBytes32,
  ser32,
  utf8
} from "./utils.js";

export const HARDENED_OFFSET = 0x80000000;
const CURVE_ORDER = secp256k1.Point.Fn.ORDER;

export function parseDerivationPath(path, { absolute = true } = {}) {
  if (typeof path !== "string") throw new Error("derivation path must be a string");
  if (path === "m" || path === "M") return [];
  const parts = path.split("/");
  if (absolute) {
    if (!/^[mM]$/.test(parts.shift() || "")) throw new Error("absolute path must start with m");
  } else if (/^[mM]$/.test(parts[0])) {
    parts.shift();
  }
  if (parts.length > 255) throw new Error("derivation path depth exceeds 255");
  return parts.map((part) => {
    const hardened = /['hH]$/.test(part);
    const raw = hardened ? part.slice(0, -1) : part;
    if (!/^(0|[1-9][0-9]*)$/.test(raw)) throw new Error(`invalid path component: ${part}`);
    const value = Number(raw);
    if (!Number.isSafeInteger(value) || value >= HARDENED_OFFSET) throw new Error(`path index out of range: ${part}`);
    return hardened ? value + HARDENED_OFFSET : value;
  });
}

export class ExtendedPrivateKey {
  constructor({ privateKey, chainCode, depth = 0, parentFingerprint = new Uint8Array(4), childNumber = 0 }) {
    if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) throw new Error("private key must be 32 bytes");
    if (!(chainCode instanceof Uint8Array) || chainCode.length !== 32) throw new Error("chain code must be 32 bytes");
    const scalar = bytesToNumber(privateKey);
    if (scalar === 0n || scalar >= CURVE_ORDER) throw new Error("invalid secp256k1 private key");
    this.privateKey = privateKey;
    this.chainCode = chainCode;
    this.depth = depth;
    this.parentFingerprint = parentFingerprint;
    this.childNumber = childNumber;
  }

  get publicKey() { return secp256k1.getPublicKey(this.privateKey, true); }
  get fingerprint() { return hash160(this.publicKey).slice(0, 4); }

  derive(index) {
    if (!Number.isSafeInteger(index) || index < 0 || index > 0xffffffff) throw new Error("child index out of range");
    const data = index >= HARDENED_OFFSET
      ? concatBytes(new Uint8Array([0]), this.privateKey, ser32(index))
      : concatBytes(this.publicKey, ser32(index));
    const digest = hmac(sha512, this.chainCode, data);
    const tweak = bytesToNumber(digest.slice(0, 32));
    if (tweak >= CURVE_ORDER) throw new Error("invalid BIP32 child tweak");
    const scalar = (tweak + bytesToNumber(this.privateKey)) % CURVE_ORDER;
    if (scalar === 0n) throw new Error("invalid zero BIP32 child key");
    return new ExtendedPrivateKey({
      privateKey: numberToBytes32(scalar),
      chainCode: digest.slice(32),
      depth: this.depth + 1,
      parentFingerprint: this.fingerprint,
      childNumber: index
    });
  }

  derivePath(path) { return parseDerivationPath(path).reduce((node, index) => node.derive(index), this); }
  neuter() {
    return new ExtendedPublicKey({
      publicKey: this.publicKey,
      chainCode: this.chainCode,
      depth: this.depth,
      parentFingerprint: this.parentFingerprint,
      childNumber: this.childNumber
    });
  }
  serializePrivate(version) { return serializeExtendedKey(this, version, true); }
  serializePublic(version) { return serializeExtendedKey(this, version, false); }
}

export class ExtendedPublicKey {
  constructor({ publicKey, chainCode, depth = 0, parentFingerprint = new Uint8Array(4), childNumber = 0 }) {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== 33 || !secp256k1.utils.isValidPublicKey(publicKey)) {
      throw new Error("invalid compressed secp256k1 public key");
    }
    if (!(chainCode instanceof Uint8Array) || chainCode.length !== 32) throw new Error("chain code must be 32 bytes");
    this.publicKey = publicKey;
    this.chainCode = chainCode;
    this.depth = depth;
    this.parentFingerprint = parentFingerprint;
    this.childNumber = childNumber;
  }

  get fingerprint() { return hash160(this.publicKey).slice(0, 4); }
  derive(index) {
    if (!Number.isSafeInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
      throw new Error("extended public keys can derive only non-hardened children");
    }
    const digest = hmac(sha512, this.chainCode, concatBytes(this.publicKey, ser32(index)));
    const tweak = bytesToNumber(digest.slice(0, 32));
    if (tweak >= CURVE_ORDER) throw new Error("invalid BIP32 child tweak");
    const child = secp256k1.Point.BASE.multiply(tweak).add(secp256k1.Point.fromBytes(this.publicKey));
    if (child.equals(secp256k1.Point.ZERO)) throw new Error("invalid zero BIP32 public child");
    return new ExtendedPublicKey({
      publicKey: child.toBytes(true),
      chainCode: digest.slice(32),
      depth: this.depth + 1,
      parentFingerprint: this.fingerprint,
      childNumber: index
    });
  }
  serializePublic(version) { return serializeExtendedKey(this, version, false); }
}

export function masterFromSeed(seed) {
  let material = normalizeSeed(seed);
  for (;;) {
    const digest = hmac(sha512, utf8("Bitcoin seed"), material);
    const scalar = bytesToNumber(digest.slice(0, 32));
    if (scalar > 0n && scalar < CURVE_ORDER) {
      return new ExtendedPrivateKey({ privateKey: digest.slice(0, 32), chainCode: digest.slice(32) });
    }
    material = digest;
  }
}

export function serializeExtendedKey(node, version, privateKey = false) {
  const versionBytes = typeof version === "string" ? hexToBytes(version) : ser32(version);
  if (versionBytes.length !== 4) throw new Error("extended-key version must be four bytes");
  if (privateKey && !(node instanceof ExtendedPrivateKey)) throw new Error("private serialization requires a private node");
  const keyData = privateKey ? concatBytes(new Uint8Array([0]), node.privateKey) : node.publicKey;
  return base58CheckEncode(concatBytes(
    versionBytes,
    new Uint8Array([node.depth]),
    node.parentFingerprint,
    ser32(node.childNumber),
    node.chainCode,
    keyData
  ));
}

export function parseExtendedKey(serialized) {
  const payload = base58CheckDecode(serialized);
  if (payload.length !== 78) throw new Error("extended-key payload must be 78 bytes");
  const version = payload.slice(0, 4);
  const depth = payload[4];
  const parentFingerprint = payload.slice(5, 9);
  const childNumber = new DataView(payload.buffer, payload.byteOffset + 9, 4).getUint32(0, false);
  const chainCode = payload.slice(13, 45);
  const keyData = payload.slice(45);
  const isPrivate = keyData[0] === 0;
  const versionHex = bytesToHex(version);
  const registered = Object.entries(EXTENDED_KEY_FORMATS).find(([, candidate]) =>
    versionHex === (isPrivate ? candidate.privateVersion : candidate.publicVersion)
  );
  if (!registered) throw new Error("unknown or mismatched extended-key version");
  if (depth === 0 && (childNumber !== 0 || parentFingerprint.some((byte) => byte !== 0))) {
    throw new Error("root extended key must have zero parent fingerprint and child number");
  }
  const node = isPrivate
    ? new ExtendedPrivateKey({ privateKey: keyData.slice(1), chainCode, depth, parentFingerprint, childNumber })
    : new ExtendedPublicKey({ publicKey: keyData, chainCode, depth, parentFingerprint, childNumber });
  return { serialized, version, versionHex, format: registered[0], depth, parentFingerprint, childNumber, chainCode, isPrivate, node };
}
