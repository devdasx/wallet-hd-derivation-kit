import { ed25519 } from "@noble/curves/ed25519.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { concatBytes, normalizeSeed, ser32, utf8 } from "./utils.js";
import { HARDENED_OFFSET, parseDerivationPath } from "./bip32.js";

export function deriveSlip10Ed25519(seed, path) {
  let digest = hmac(sha512, utf8("ed25519 seed"), normalizeSeed(seed));
  let privateKey = digest.slice(0, 32);
  let chainCode = digest.slice(32);
  let depth = 0;
  let childNumber = 0;
  for (const index of parseDerivationPath(path)) {
    if (index < HARDENED_OFFSET) throw new Error("SLIP10 Ed25519 supports hardened derivation only");
    digest = hmac(sha512, chainCode, concatBytes(new Uint8Array([0]), privateKey, ser32(index)));
    privateKey = digest.slice(0, 32);
    chainCode = digest.slice(32);
    depth += 1;
    childNumber = index;
  }
  return { privateKey, publicKey: ed25519.getPublicKey(privateKey), chainCode, depth, childNumber };
}
