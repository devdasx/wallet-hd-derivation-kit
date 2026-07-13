import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export const utf8 = utf8ToBytes;

export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
export function hexToBytes(hex) {
  if (typeof hex !== "string") throw new TypeError("hex must be a string");
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) throw new Error("invalid hex string");
  const output = new Uint8Array(clean.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(clean.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

export function concatBytes(...chunks) {
  const output = new Uint8Array(chunks.reduce((length, chunk) => length + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

export function ser32(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) throw new Error("invalid uint32");
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, false);
  return output;
}

export function bytesToNumber(bytes) {
  const hex = bytesToHex(bytes);
  return hex ? BigInt(`0x${hex}`) : 0n;
}

export function numberToBytes32(value) {
  if (value < 0n) throw new Error("cannot encode a negative number");
  const hex = value.toString(16).padStart(64, "0");
  if (hex.length > 64) throw new Error("number does not fit in 32 bytes");
  return hexToBytes(hex);
}

export function hash160(bytes) {
  return ripemd160(sha256(bytes));
}

export function doubleSha256(bytes) {
  return sha256(sha256(bytes));
}

export function base58Encode(bytes) {
  let number = bytesToNumber(bytes);
  let output = "";
  while (number > 0n) {
    output = BASE58_ALPHABET[Number(number % 58n)] + output;
    number /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    output = `1${output}`;
  }
  return output || "1";
}

export function base58Decode(value) {
  if (typeof value !== "string" || value.length === 0) throw new Error("base58 value must not be empty");
  let number = 0n;
  for (const character of value) {
    const digit = BASE58_ALPHABET.indexOf(character);
    if (digit < 0) throw new Error(`invalid base58 character: ${character}`);
    number = number * 58n + BigInt(digit);
  }
  let hex = number.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let bytes = number === 0n ? new Uint8Array() : hexToBytes(hex);
  let leading = 0;
  for (const character of value) {
    if (character !== "1") break;
    leading += 1;
  }
  if (leading) bytes = concatBytes(new Uint8Array(leading), bytes);
  return bytes;
}

export function base58CheckEncode(payload) {
  return base58Encode(concatBytes(payload, doubleSha256(payload).slice(0, 4)));
}

export function base58CheckDecode(value) {
  const decoded = base58Decode(value);
  if (decoded.length < 5) throw new Error("invalid Base58Check length");
  const payload = decoded.slice(0, -4);
  const checksum = decoded.slice(-4);
  const expected = doubleSha256(payload).slice(0, 4);
  if (!checksum.every((byte, index) => byte === expected[index])) throw new Error("invalid Base58Check checksum");
  return payload;
}

export function normalizeSeed(seed) {
  const bytes = typeof seed === "string" ? hexToBytes(seed) : seed;
  if (!(bytes instanceof Uint8Array)) throw new Error("seed must be bytes or hex");
  if (bytes.length < 16 || bytes.length > 64) throw new Error("seed must be between 16 and 64 bytes");
  return bytes;
}

export function toChecksumAddress(address) {
  const clean = address.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{40}$/.test(clean)) throw new Error("EVM address must be 20 bytes");
  const hash = bytesToHex(keccak_256(utf8(clean)));
  let output = "0x";
  for (let index = 0; index < clean.length; index += 1) {
    output += Number.parseInt(hash[index], 16) >= 8 ? clean[index].toUpperCase() : clean[index];
  }
  return output;
}

export function taggedHash(tag, message) {
  const tagHash = sha256(utf8(tag));
  return sha256(concatBytes(tagHash, tagHash, message));
}
