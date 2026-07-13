export const EXTENDED_KEY_FORMATS = Object.freeze({
  xpub: { publicVersion: "0488b21e", privateVersion: "0488ade4", purpose: 44, scriptType: "p2pkh" },
  ypub: { publicVersion: "049d7cb2", privateVersion: "049d7878", purpose: 49, scriptType: "p2sh-p2wpkh" },
  zpub: { publicVersion: "04b24746", privateVersion: "04b2430c", purpose: 84, scriptType: "p2wpkh" },
  tpub: { publicVersion: "043587cf", privateVersion: "04358394", purpose: 44, scriptType: "p2pkh" },
  upub: { publicVersion: "044a5262", privateVersion: "044a4e28", purpose: 49, scriptType: "p2sh-p2wpkh" },
  vpub: { publicVersion: "045f1cf6", privateVersion: "045f18bc", purpose: 84, scriptType: "p2wpkh" },
  Ltub: { publicVersion: "019da462", privateVersion: "019d9cfe", purpose: 44, scriptType: "p2pkh" },
  Mtub: { publicVersion: "01b26ef6", privateVersion: "01b26792", purpose: 49, scriptType: "p2sh-p2wpkh" }
});

const evm = (name, symbol, coinType = 60) => ({ name, symbol, coinType, curve: "secp256k1", addressKind: "evm", defaultScriptType: "evm" });

export const CHAINS = Object.freeze({
  bitcoin: { name: "Bitcoin", symbol: "BTC", coinType: 0, curve: "secp256k1", defaultFormat: "zpub", formats: ["xpub", "ypub", "zpub"], p2pkh: "00", p2sh: "05", hrp: "bc" },
  "bitcoin-testnet": { name: "Bitcoin Testnet", symbol: "TBTC", coinType: 1, curve: "secp256k1", defaultFormat: "vpub", formats: ["tpub", "upub", "vpub"], p2pkh: "6f", p2sh: "c4", hrp: "tb" },
  litecoin: { name: "Litecoin", symbol: "LTC", coinType: 2, curve: "secp256k1", defaultFormat: "Ltub", formats: ["Ltub", "Mtub"], p2pkh: "30", p2sh: "32", hrp: "ltc" },
  dogecoin: { name: "Dogecoin", symbol: "DOGE", coinType: 3, curve: "secp256k1", defaultFormat: "xpub", formats: ["xpub"], p2pkh: "1e", p2sh: "16" },
  dash: { name: "Dash", symbol: "DASH", coinType: 5, curve: "secp256k1", defaultFormat: "xpub", formats: ["xpub"], p2pkh: "4c", p2sh: "10" },
  digibyte: { name: "DigiByte", symbol: "DGB", coinType: 20, curve: "secp256k1", defaultFormat: "xpub", formats: ["xpub", "ypub", "zpub"], p2pkh: "1e", p2sh: "3f", hrp: "dgb" },
  "bitcoin-cash": { name: "Bitcoin Cash", symbol: "BCH", coinType: 145, curve: "secp256k1", defaultFormat: "xpub", formats: ["xpub"], p2pkh: "00", p2sh: "05", cashaddrPrefix: "bitcoincash", defaultScriptType: "cashaddr" },
  "zcash-transparent": { name: "Zcash Transparent", symbol: "ZEC", coinType: 133, curve: "secp256k1", defaultFormat: "xpub", formats: ["xpub"], p2pkh: "1cb8", p2sh: "1cbd" },
  ethereum: evm("Ethereum", "ETH", 60),
  "ethereum-classic": evm("Ethereum Classic", "ETC", 61),
  polygon: evm("Polygon", "POL"),
  bsc: evm("BNB Smart Chain", "BNB"),
  "avalanche-c": evm("Avalanche C-Chain", "AVAX"),
  arbitrum: evm("Arbitrum", "ARB"),
  optimism: evm("Optimism", "OP"),
  base: evm("Base", "ETH"),
  tron: { name: "TRON", symbol: "TRX", coinType: 195, curve: "secp256k1", addressKind: "tron", defaultScriptType: "tron" },
  solana: { name: "Solana", symbol: "SOL", coinType: 501, curve: "ed25519", addressKind: "solana", defaultScriptType: "solana" }
});

export function supportedChains() {
  return Object.entries(CHAINS).map(([id, chain]) => ({ id, ...chain }));
}
export function resolveFormat(chainId, format, scriptType) {
  const chain = CHAINS[chainId];
  if (!chain) throw new Error(`unsupported chain: ${chainId}`);
  if (!chain.formats) return null;
  const selected = format || (scriptType === "p2tr" ? "xpub" : chain.defaultFormat);
  if (!chain.formats.includes(selected)) throw new Error(`format ${selected} is not registered for ${chainId}`);
  return { name: selected, ...EXTENDED_KEY_FORMATS[selected] };
}

export function accountPath(chainId, { account = 0, format, scriptType } = {}) {
  const chain = CHAINS[chainId];
  if (!chain) throw new Error(`unsupported chain: ${chainId}`);
  if (!Number.isSafeInteger(account) || account < 0 || account >= 0x80000000) throw new Error("account out of range");
  if (chain.curve === "ed25519") return `m/44'/${chain.coinType}'/${account}'`;
  if (chain.addressKind === "evm" || chain.addressKind === "tron") return `m/44'/${chain.coinType}'/${account}'`;
  const purpose = scriptType === "p2tr" ? 86 : resolveFormat(chainId, format, scriptType).purpose;
  return `m/${purpose}'/${chain.coinType}'/${account}'`;
}
