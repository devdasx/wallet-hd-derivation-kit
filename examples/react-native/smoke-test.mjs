import { deriveAddress } from "../../javascript/src/react-native.js";

const source = { mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" };
const value = deriveAddress({ source, chain: "solana" }).address;
if (value !== "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk") throw new Error("React Native entry-point failed");
console.log(value);
