import { deriveAccountPublicKey, deriveAddress } from "wallet-hd-derivation-kit";

// Public BIP-39 test vector only. Never put a real wallet mnemonic in source code.
const source = { mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" };
console.log(deriveAddress({ source, chain: "bitcoin" }).address);
console.log(deriveAccountPublicKey({ source, chain: "bitcoin" }).extendedPublicKey);
