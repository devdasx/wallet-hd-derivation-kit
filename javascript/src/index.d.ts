export type ChainId =
  | "bitcoin" | "bitcoin-testnet" | "litecoin" | "dogecoin" | "dash"
  | "digibyte" | "bitcoin-cash" | "zcash-transparent" | "ethereum"
  | "ethereum-classic" | "polygon" | "bsc" | "avalanche-c" | "arbitrum"
  | "optimism" | "base" | "tron" | "solana";

export type ScriptType =
  | "p2pkh" | "p2sh-p2wpkh" | "p2wpkh" | "p2tr"
  | "cashaddr" | "evm" | "tron" | "solana";

export type Curve = "secp256k1" | "ed25519";
export type ExtendedKeyFormat = "xpub" | "ypub" | "zpub" | "tpub" | "upub" | "vpub" | "Ltub" | "Mtub";

export interface SeedSource {
  mnemonic?: string;
  passphrase?: string;
  validate?: boolean;
  seed?: Uint8Array;
  seedHex?: string;
}

export interface DerivationOptions extends SeedSource {
  source?: SeedSource;
  chain?: ChainId;
  format?: ExtendedKeyFormat;
  scriptType?: ScriptType;
  path?: string;
  account?: number;
  change?: number;
  index?: number;
  start?: number;
  count?: number;
}

export interface NodeResult {
  schemaVersion: 1;
  curve: Curve;
  path: string;
  publicKeyHex: string;
  chainCodeHex: string;
  depth: number;
  childNumber: number;
}

export interface AccountPublicKeyResult {
  schemaVersion: 1;
  chain: ChainId;
  curve: Curve;
  path: string;
  format: ExtendedKeyFormat;
  extendedPublicKey: string;
  publicKeyHex: string;
}

export interface AccountPrivateKeyResult {
  schemaVersion: 1;
  chain: ChainId;
  curve: Curve;
  path: string;
  format: ExtendedKeyFormat | null;
  extendedPrivateKey: string | null;
  privateKeyHex: string;
  publicKeyHex: string;
}

export interface DerivedAddress {
  schemaVersion: 1;
  chain: ChainId;
  curve: Curve;
  path: string;
  account: number;
  change: number;
  index: number;
  scriptType: ScriptType;
  address: string;
  publicKeyHex: string;
}

export interface ChainInfo {
  id: ChainId;
  name: string;
  symbol: string;
  coinType: number;
  curve: Curve;
  addressKind?: ScriptType;
  defaultScriptType?: ScriptType;
  defaultFormat?: ExtendedKeyFormat;
  formats?: ExtendedKeyFormat[];
  p2pkh?: string;
  p2sh?: string;
  hrp?: string;
  cashaddrPrefix?: string;
}

export interface ExtendedKeyNodeFields {
  chainCode: Uint8Array;
  depth?: number;
  parentFingerprint?: Uint8Array;
  childNumber?: number;
}

export class ExtendedPrivateKey {
  constructor(fields: ExtendedKeyNodeFields & { privateKey: Uint8Array });
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly chainCode: Uint8Array;
  readonly depth: number;
  readonly parentFingerprint: Uint8Array;
  readonly childNumber: number;
  readonly fingerprint: Uint8Array;
  derive(index: number): ExtendedPrivateKey;
  derivePath(path: string): ExtendedPrivateKey;
  neuter(): ExtendedPublicKey;
  serializePrivate(version: string | number): string;
  serializePublic(version: string | number): string;
}

export class ExtendedPublicKey {
  constructor(fields: ExtendedKeyNodeFields & { publicKey: Uint8Array });
  readonly publicKey: Uint8Array;
  readonly chainCode: Uint8Array;
  readonly depth: number;
  readonly parentFingerprint: Uint8Array;
  readonly childNumber: number;
  readonly fingerprint: Uint8Array;
  derive(index: number): ExtendedPublicKey;
  serializePublic(version: string | number): string;
}

export interface ParsedExtendedKey {
  serialized: string;
  version: Uint8Array;
  versionHex: string;
  format: ExtendedKeyFormat;
  depth: number;
  parentFingerprint: Uint8Array;
  childNumber: number;
  chainCode: Uint8Array;
  isPrivate: boolean;
  node: ExtendedPrivateKey | ExtendedPublicKey;
}

export interface Slip10Ed25519Node {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  chainCode: Uint8Array;
  depth: number;
  childNumber: number;
}

export declare const API_SCHEMA_VERSION: 1;
export declare const HARDENED_OFFSET: number;
export declare const EXTENDED_KEY_FORMATS: Readonly<Record<ExtendedKeyFormat, Readonly<{
  publicVersion: string;
  privateVersion: string;
  purpose: number;
  scriptType: ScriptType;
}>>>;

export declare function sourceToSeed(source: SeedSource): Uint8Array;
export declare function parseDerivationPath(path: string, options?: { absolute?: boolean }): number[];
export declare function masterFromSeed(seed: Uint8Array | string): ExtendedPrivateKey;
export declare function deriveSlip10Ed25519(seed: Uint8Array | string, path?: string): Slip10Ed25519Node;
export declare function deriveNode(options: { source: SeedSource; curve?: Curve; path?: string }): NodeResult;
export declare function deriveAccountPublicKey(options: DerivationOptions): AccountPublicKeyResult;
export declare function deriveAccountPrivateKey(options: DerivationOptions): AccountPrivateKeyResult;
export declare function deriveAddress(options: DerivationOptions): DerivedAddress;
export declare function deriveAddresses(options: DerivationOptions): DerivedAddress[];
export declare function deriveAddressFromExtendedPublicKey(options: {
  extendedPublicKey: string;
  chain: ChainId;
  change?: number;
  index?: number;
  scriptType?: ScriptType;
}): DerivedAddress;
export declare function parseExtendedKey(serialized: string): ParsedExtendedKey;
export declare function serializeExtendedKey(
  node: ExtendedPrivateKey | ExtendedPublicKey,
  version: string | number,
  privateKey?: boolean,
): string;
export declare function supportedChains(): ChainInfo[];
