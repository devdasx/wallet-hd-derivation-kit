import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { CHAINS } from "./chains.js";
import {
  base58CheckEncode,
  base58Encode,
  bytesToHex,
  bytesToNumber,
  concatBytes,
  hash160,
  hexToBytes,
  taggedHash,
  toChecksumAddress
} from "./utils.js";

const BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CASHADDR_ALPHABET = BECH32_ALPHABET;
const BECH32_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const CASHADDR_GENERATORS = [
  0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n
];

export function publicKeyToAddress(publicKeyInput, { chain: chainId = "bitcoin", scriptType = "p2pkh" } = {}) {
  const chain = CHAINS[chainId];
  if (!chain) throw new Error(`unsupported chain: ${chainId}`);
  const publicKey = typeof publicKeyInput === "string" ? hexToBytes(publicKeyInput) : publicKeyInput;
  if (chain.addressKind === "evm") return evmAddress(publicKey);
  if (chain.addressKind === "tron") return tronAddress(publicKey);
  if (scriptType === "cashaddr") return cashAddress(chain.cashaddrPrefix, hash160(publicKey));
  if (scriptType === "p2pkh") return base58CheckEncode(concatBytes(hexToBytes(chain.p2pkh), hash160(publicKey)));
  if (scriptType === "p2sh-p2wpkh") {
    const redeemScript = concatBytes(new Uint8Array([0, 20]), hash160(publicKey));
    return base58CheckEncode(concatBytes(hexToBytes(chain.p2sh), hash160(redeemScript)));
  }
  if (scriptType === "p2wpkh") return segwitAddress(chain.hrp, 0, hash160(publicKey));
  if (scriptType === "p2tr") return segwitAddress(chain.hrp, 1, taprootOutputKey(publicKey));
  throw new Error(`unsupported script type: ${scriptType}`);
}
export function evmAddress(publicKey) {
  const uncompressed = publicKey.length === 65 ? publicKey : secp256k1.Point.fromBytes(publicKey).toBytes(false);
  return toChecksumAddress(bytesToHex(keccak_256(uncompressed.slice(1)).slice(-20)));
}

export function tronAddress(publicKey) {
  const uncompressed = publicKey.length === 65 ? publicKey : secp256k1.Point.fromBytes(publicKey).toBytes(false);
  return base58CheckEncode(concatBytes(new Uint8Array([0x41]), keccak_256(uncompressed.slice(1)).slice(-20)));
}

export function taprootOutputKey(publicKey) {
  const compressed = publicKey.length === 33 ? publicKey : secp256k1.Point.fromBytes(publicKey).toBytes(true);
  const xOnly = compressed.slice(1);
  const internal = secp256k1.Point.fromBytes(concatBytes(new Uint8Array([2]), xOnly));
  const tweak = bytesToNumber(taggedHash("TapTweak", xOnly));
  if (tweak >= secp256k1.Point.Fn.ORDER) throw new Error("invalid Taproot tweak");
  return internal.add(secp256k1.Point.BASE.multiply(tweak)).toBytes(true).slice(1);
}

export function segwitAddress(hrp, version, program) {
  if (!hrp) throw new Error("chain does not define a SegWit HRP");
  const words = [version, ...convertBits(program, 8, 5, true)];
  return bech32Encode(hrp, words, version === 0 ? 1 : 0x2bc830a3);
}

export function bech32Encode(hrp, words, constant = 1) {
  const values = [...bech32HrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0];
  const mod = bech32Polymod(values) ^ constant;
  const checksum = Array.from({ length: 6 }, (_, index) => (mod >>> (5 * (5 - index))) & 31);
  return `${hrp}1${[...words, ...checksum].map((word) => BECH32_ALPHABET[word]).join("")}`;
}

function bech32HrpExpand(hrp) {
  return [...Array.from(hrp, (character) => character.charCodeAt(0) >> 5), 0, ...Array.from(hrp, (character) => character.charCodeAt(0) & 31)];
}

function bech32Polymod(values) {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let index = 0; index < 5; index += 1) if ((top >>> index) & 1) checksum ^= BECH32_GENERATORS[index];
  }
  return checksum >>> 0;
}

export function convertBits(data, fromBits, toBits, pad) {
  let accumulator = 0;
  let bits = 0;
  const output = [];
  const mask = (1 << toBits) - 1;
  for (const value of data) {
    if (value < 0 || value >> fromBits) throw new Error("invalid convertBits value");
    accumulator = (accumulator << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      output.push((accumulator >> bits) & mask);
    }
  }
  if (pad && bits) output.push((accumulator << (toBits - bits)) & mask);
  else if (!pad && (bits >= fromBits || ((accumulator << (toBits - bits)) & mask))) throw new Error("invalid incomplete bit group");
  return output;
}

export function cashAddress(prefix, hash) {
  const payload = convertBits(concatBytes(new Uint8Array([0]), hash), 8, 5, true);
  const prefixValues = Array.from(prefix, (character) => character.charCodeAt(0) & 31);
  const values = [...prefixValues, 0, ...payload, 0, 0, 0, 0, 0, 0, 0, 0];
  const mod = cashaddrPolymod(values) ^ 1n;
  const checksum = Array.from({ length: 8 }, (_, index) => Number((mod >> BigInt(5 * (7 - index))) & 31n));
  return `${prefix}:${[...payload, ...checksum].map((value) => CASHADDR_ALPHABET[value]).join("")}`;
}

function cashaddrPolymod(values) {
  let checksum = 1n;
  for (const value of values) {
    const top = checksum >> 35n;
    checksum = ((checksum & 0x07ffffffffn) << 5n) ^ BigInt(value);
    for (let index = 0; index < 5; index += 1) if ((top >> BigInt(index)) & 1n) checksum ^= CASHADDR_GENERATORS[index];
  }
  return checksum;
}
