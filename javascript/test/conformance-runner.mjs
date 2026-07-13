import { deriveAddress, supportedChains } from "../src/index.js";

const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const result = Object.fromEntries(supportedChains().map(({ id }) => [id, deriveAddress({ source: { mnemonic }, chain: id }).address]));
console.log(`WALLETHD_CONFORMANCE=${JSON.stringify(result)}`);
