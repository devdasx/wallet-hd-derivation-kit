import BIP39MnemonicKit
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import CryptoSwift
import Foundation
#if canImport(P256K)
import P256K
#elseif canImport(secp256k1Wrapper)
import secp256k1Wrapper
#else
#error("WalletHDDerivationKit requires a supported secp256k1 provider")
#endif

public let walletHDSchemaVersion = 1

public enum WalletHDError: Error, Equatable, LocalizedError, Sendable {
    case invalidSource(String)
    case invalidPath(String)
    case invalidKey(String)
    case invalidArgument(String)
    case unsupported(String)

    public var errorDescription: String? {
        switch self {
        case .invalidSource(let value), .invalidPath(let value), .invalidKey(let value),
             .invalidArgument(let value), .unsupported(let value): value
        }
    }
}

public enum HDSource: Sendable {
    case mnemonic(String, passphrase: String = "")
    case seed(Data)
}

public enum HDCurve: String, Codable, Sendable {
    case secp256k1
    case ed25519
}

public enum HDChain: String, CaseIterable, Codable, Sendable {
    case bitcoin
    case bitcoinTestnet = "bitcoin-testnet"
    case litecoin
    case dogecoin
    case dash
    case digibyte
    case bitcoinCash = "bitcoin-cash"
    case zcashTransparent = "zcash-transparent"
    case ethereum
    case ethereumClassic = "ethereum-classic"
    case polygon
    case bsc
    case avalancheC = "avalanche-c"
    case arbitrum
    case optimism
    case base
    case tron
    case solana
}

public enum HDScriptType: String, Codable, Sendable {
    case p2pkh
    case p2shP2wpkh = "p2sh-p2wpkh"
    case p2wpkh
    case p2tr
    case cashaddr
    case evm
    case tron
    case solana
}

public struct SupportedChain: Codable, Equatable, Sendable {
    public let id: HDChain
    public let name: String
    public let symbol: String
    public let coinType: UInt32
    public let curve: HDCurve
    public let defaultScriptType: HDScriptType
}

public struct DerivedNode: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let curve: HDCurve
    public let path: String
    public let publicKeyHex: String
    public let chainCodeHex: String
    public let depth: UInt8
    public let childNumber: UInt32
}

public struct AccountPublicKey: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let chain: HDChain
    public let curve: HDCurve
    public let path: String
    public let format: String
    public let extendedPublicKey: String
    public let publicKeyHex: String
}

/// This result deliberately exists only behind `deriveAccountPrivateKey`.
public struct AccountPrivateKey: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let chain: HDChain
    public let curve: HDCurve
    public let path: String
    public let format: String?
    public let extendedPrivateKey: String?
    public let privateKeyHex: String
    public let publicKeyHex: String
}

public struct DerivedAddress: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let chain: HDChain
    public let curve: HDCurve
    public let path: String
    public let account: UInt32
    public let change: UInt32
    public let index: UInt32
    public let scriptType: HDScriptType
    public let address: String
    public let publicKeyHex: String
}

public struct ParsedExtendedKey: Codable, Equatable, Sendable {
    public let serialized: String
    public let version: UInt32
    public let depth: UInt8
    public let parentFingerprint: UInt32
    public let childNumber: UInt32
    public let chainCodeHex: String
    public let keyDataHex: String
    public let isPrivate: Bool
}

private struct ChainConfiguration: Sendable {
    let name: String
    let symbol: String
    let coinType: UInt32
    let curve: HDCurve
    let defaultFormat: String?
    let formats: [String]
    let p2pkh: [UInt8]?
    let p2sh: [UInt8]?
    let hrp: String?
    let cashaddrPrefix: String?
    let addressKind: HDScriptType
}

private struct ExtendedFormat: Sendable {
    let publicVersion: UInt32
    let privateVersion: UInt32
    let purpose: UInt32
    let scriptType: HDScriptType
}

private let formats: [String: ExtendedFormat] = [
    "xpub": .init(publicVersion: 0x0488b21e, privateVersion: 0x0488ade4, purpose: 44, scriptType: .p2pkh),
    "ypub": .init(publicVersion: 0x049d7cb2, privateVersion: 0x049d7878, purpose: 49, scriptType: .p2shP2wpkh),
    "zpub": .init(publicVersion: 0x04b24746, privateVersion: 0x04b2430c, purpose: 84, scriptType: .p2wpkh),
    "tpub": .init(publicVersion: 0x043587cf, privateVersion: 0x04358394, purpose: 44, scriptType: .p2pkh),
    "upub": .init(publicVersion: 0x044a5262, privateVersion: 0x044a4e28, purpose: 49, scriptType: .p2shP2wpkh),
    "vpub": .init(publicVersion: 0x045f1cf6, privateVersion: 0x045f18bc, purpose: 84, scriptType: .p2wpkh),
    "Ltub": .init(publicVersion: 0x019da462, privateVersion: 0x019d9cfe, purpose: 44, scriptType: .p2pkh),
    "Mtub": .init(publicVersion: 0x01b26ef6, privateVersion: 0x01b26792, purpose: 49, scriptType: .p2shP2wpkh),
]

private let chains: [HDChain: ChainConfiguration] = {
    func evm(_ name: String, _ symbol: String, _ coinType: UInt32 = 60) -> ChainConfiguration {
        .init(name: name, symbol: symbol, coinType: coinType, curve: .secp256k1, defaultFormat: nil,
              formats: [], p2pkh: nil, p2sh: nil, hrp: nil, cashaddrPrefix: nil, addressKind: .evm)
    }
    return [
        .bitcoin: .init(name: "Bitcoin", symbol: "BTC", coinType: 0, curve: .secp256k1, defaultFormat: "zpub", formats: ["xpub", "ypub", "zpub"], p2pkh: [0x00], p2sh: [0x05], hrp: "bc", cashaddrPrefix: nil, addressKind: .p2wpkh),
        .bitcoinTestnet: .init(name: "Bitcoin Testnet", symbol: "TBTC", coinType: 1, curve: .secp256k1, defaultFormat: "vpub", formats: ["tpub", "upub", "vpub"], p2pkh: [0x6f], p2sh: [0xc4], hrp: "tb", cashaddrPrefix: nil, addressKind: .p2wpkh),
        .litecoin: .init(name: "Litecoin", symbol: "LTC", coinType: 2, curve: .secp256k1, defaultFormat: "Ltub", formats: ["Ltub", "Mtub"], p2pkh: [0x30], p2sh: [0x32], hrp: "ltc", cashaddrPrefix: nil, addressKind: .p2pkh),
        .dogecoin: .init(name: "Dogecoin", symbol: "DOGE", coinType: 3, curve: .secp256k1, defaultFormat: "xpub", formats: ["xpub"], p2pkh: [0x1e], p2sh: [0x16], hrp: nil, cashaddrPrefix: nil, addressKind: .p2pkh),
        .dash: .init(name: "Dash", symbol: "DASH", coinType: 5, curve: .secp256k1, defaultFormat: "xpub", formats: ["xpub"], p2pkh: [0x4c], p2sh: [0x10], hrp: nil, cashaddrPrefix: nil, addressKind: .p2pkh),
        .digibyte: .init(name: "DigiByte", symbol: "DGB", coinType: 20, curve: .secp256k1, defaultFormat: "xpub", formats: ["xpub", "ypub", "zpub"], p2pkh: [0x1e], p2sh: [0x3f], hrp: "dgb", cashaddrPrefix: nil, addressKind: .p2pkh),
        .bitcoinCash: .init(name: "Bitcoin Cash", symbol: "BCH", coinType: 145, curve: .secp256k1, defaultFormat: "xpub", formats: ["xpub"], p2pkh: [0x00], p2sh: [0x05], hrp: nil, cashaddrPrefix: "bitcoincash", addressKind: .cashaddr),
        .zcashTransparent: .init(name: "Zcash Transparent", symbol: "ZEC", coinType: 133, curve: .secp256k1, defaultFormat: "xpub", formats: ["xpub"], p2pkh: [0x1c, 0xb8], p2sh: [0x1c, 0xbd], hrp: nil, cashaddrPrefix: nil, addressKind: .p2pkh),
        .ethereum: evm("Ethereum", "ETH"),
        .ethereumClassic: evm("Ethereum Classic", "ETC", 61),
        .polygon: evm("Polygon", "POL"),
        .bsc: evm("BNB Smart Chain", "BNB"),
        .avalancheC: evm("Avalanche C-Chain", "AVAX"),
        .arbitrum: evm("Arbitrum", "ARB"),
        .optimism: evm("Optimism", "OP"),
        .base: evm("Base", "ETH"),
        .tron: .init(name: "TRON", symbol: "TRX", coinType: 195, curve: .secp256k1, defaultFormat: nil, formats: [], p2pkh: nil, p2sh: nil, hrp: nil, cashaddrPrefix: nil, addressKind: .tron),
        .solana: .init(name: "Solana", symbol: "SOL", coinType: 501, curve: .ed25519, defaultFormat: nil, formats: [], p2pkh: nil, p2sh: nil, hrp: nil, cashaddrPrefix: nil, addressKind: .solana),
    ]
}()

private struct PrivateNode: Sendable {
    let privateKey: [UInt8]
    let chainCode: [UInt8]
    let depth: UInt8
    let parentFingerprint: UInt32
    let childNumber: UInt32

    var publicKey: [UInt8] {
        get throws { try secpPublicKey(fromPrivateKey: privateKey) }
    }

    var fingerprint: UInt32 {
        get throws { readUInt32(Array(try hash160(publicKey).prefix(4))) }
    }

    func derive(_ index: UInt32) throws -> PrivateNode {
        guard depth < UInt8.max else { throw WalletHDError.invalidPath("derivation path depth exceeds 255") }
        let data = index >= 0x80000000 ? [0] + privateKey + ser32(index) : try publicKey + ser32(index)
        let digest = try hmacSHA512(key: chainCode, data: data)
        let tweak = Array(digest.prefix(32))
        let childKey: [UInt8]
        do {
            childKey = try secpAddPrivateKey(privateKey, tweak: tweak)
        } catch {
            throw WalletHDError.invalidKey("invalid BIP-32 child tweak or zero child key")
        }
        return PrivateNode(privateKey: childKey, chainCode: Array(digest.suffix(32)),
                           depth: depth + 1, parentFingerprint: try fingerprint, childNumber: index)
    }

    func derive(path: String) throws -> PrivateNode {
        try parsePath(path).reduce(self) { try $0.derive($1) }
    }

    func neuter() throws -> PublicNode {
        PublicNode(publicKey: try publicKey, chainCode: chainCode, depth: depth,
                   parentFingerprint: parentFingerprint, childNumber: childNumber)
    }
}

private struct PublicNode: Sendable {
    let publicKey: [UInt8]
    let chainCode: [UInt8]
    let depth: UInt8
    let parentFingerprint: UInt32
    let childNumber: UInt32

    var fingerprint: UInt32 { readUInt32(Array(hash160(publicKey).prefix(4))) }

    func derive(_ index: UInt32) throws -> PublicNode {
        guard index < 0x80000000 else { throw WalletHDError.invalidPath("extended public keys cannot derive hardened children") }
        guard depth < UInt8.max else { throw WalletHDError.invalidPath("derivation path depth exceeds 255") }
        let digest = try hmacSHA512(key: chainCode, data: publicKey + ser32(index))
        let childPublicKey: [UInt8]
        do {
            childPublicKey = try secpAddPublicKey(publicKey, tweak: Array(digest.prefix(32)))
        } catch {
            throw WalletHDError.invalidKey("invalid BIP-32 public child")
        }
        return PublicNode(publicKey: childPublicKey, chainCode: Array(digest.suffix(32)),
                          depth: depth + 1, parentFingerprint: fingerprint, childNumber: index)
    }
}

public enum WalletHDDerivationKit {
    public static func supportedChains() -> [SupportedChain] {
        HDChain.allCases.compactMap { chain in
            guard let configuration = chains[chain] else { return nil }
            return SupportedChain(id: chain, name: configuration.name, symbol: configuration.symbol,
                                  coinType: configuration.coinType, curve: configuration.curve,
                                  defaultScriptType: configuration.addressKind)
        }
    }

    public static func deriveNode(source: HDSource, curve: HDCurve = .secp256k1, path: String = "m") throws -> DerivedNode {
        let seed = try sourceToSeed(source)
        if curve == .ed25519 {
            let node = try deriveSlip10(seed: seed, path: path)
            return DerivedNode(schemaVersion: walletHDSchemaVersion, curve: curve, path: path,
                               publicKeyHex: hex(node.publicKey), chainCodeHex: hex(node.chainCode),
                               depth: node.depth, childNumber: node.childNumber)
        }
        let node = try master(seed: seed).derive(path: path)
        return DerivedNode(schemaVersion: walletHDSchemaVersion, curve: curve, path: path,
                           publicKeyHex: hex(try node.publicKey), chainCodeHex: hex(node.chainCode),
                           depth: node.depth, childNumber: node.childNumber)
    }

    public static func deriveAccountPublicKey(
        source: HDSource, chain: HDChain = .bitcoin, scriptType: HDScriptType? = nil,
        account: UInt32 = 0, format: String? = nil, path: String? = nil
    ) throws -> AccountPublicKey {
        let configuration = try requireChain(chain)
        guard configuration.curve == .secp256k1 else {
            throw WalletHDError.unsupported("Solana SLIP-0010 does not define extended public keys")
        }
        try validatePublicIndex(account, name: "account")
        let selected = try resolveFormat(chain: chain, format: format, scriptType: scriptType)
        let resolvedPath = try path ?? accountPath(chain: chain, account: account, format: format, scriptType: scriptType)
        let node = try master(seed: sourceToSeed(source)).derive(path: resolvedPath)
        return AccountPublicKey(schemaVersion: walletHDSchemaVersion, chain: chain, curve: configuration.curve,
                                path: resolvedPath, format: selected.name,
                                extendedPublicKey: try serialize(node: node, version: selected.value.publicVersion, privateKey: false),
                                publicKeyHex: hex(try node.publicKey))
    }

    /// Explicit private API. The returned value contains private key material.
    public static func deriveAccountPrivateKey(
        source: HDSource, chain: HDChain = .bitcoin, scriptType: HDScriptType? = nil,
        account: UInt32 = 0, format: String? = nil, path: String? = nil
    ) throws -> AccountPrivateKey {
        let configuration = try requireChain(chain)
        try validatePublicIndex(account, name: "account")
        let resolvedPath = try path ?? accountPath(chain: chain, account: account, format: format, scriptType: scriptType)
        if configuration.curve == .ed25519 {
            let node = try deriveSlip10(seed: sourceToSeed(source), path: resolvedPath)
            return AccountPrivateKey(schemaVersion: walletHDSchemaVersion, chain: chain, curve: configuration.curve,
                                     path: resolvedPath, format: nil, extendedPrivateKey: nil,
                                     privateKeyHex: hex(node.privateKey), publicKeyHex: hex(node.publicKey))
        }
        let selected = try resolveFormat(chain: chain, format: format, scriptType: scriptType)
        let node = try master(seed: sourceToSeed(source)).derive(path: resolvedPath)
        return AccountPrivateKey(schemaVersion: walletHDSchemaVersion, chain: chain, curve: configuration.curve,
                                 path: resolvedPath, format: selected.name,
                                 extendedPrivateKey: try serialize(node: node, version: selected.value.privateVersion, privateKey: true),
                                 privateKeyHex: hex(node.privateKey), publicKeyHex: hex(try node.publicKey))
    }

    public static func deriveAddress(
        source: HDSource, chain: HDChain = .bitcoin, account: UInt32 = 0,
        change: UInt32 = 0, index: UInt32 = 0, scriptType: HDScriptType? = nil,
        format: String? = nil, path: String? = nil
    ) throws -> DerivedAddress {
        try validatePublicIndex(account, name: "account")
        try validatePublicIndex(change, name: "change")
        try validatePublicIndex(index, name: "index")
        let configuration = try requireChain(chain)
        let selectedScript = scriptType ?? configuration.addressKind
        if configuration.curve == .ed25519 {
            let resolvedPath = path ?? "m/44'/\(configuration.coinType)'/\(account)'/\(index)'"
            let node = try deriveSlip10(seed: sourceToSeed(source), path: resolvedPath)
            return addressResult(chain: chain, configuration: configuration, path: resolvedPath, account: account,
                                 change: change, index: index, scriptType: .solana,
                                 address: base58Encode(node.publicKey), publicKey: node.publicKey)
        }
        let resolvedPath = try path ?? "\(accountPath(chain: chain, account: account, format: format, scriptType: scriptType))/\(change)/\(index)"
        let node = try master(seed: sourceToSeed(source)).derive(path: resolvedPath)
        let publicKey = try node.publicKey
        return addressResult(chain: chain, configuration: configuration, path: resolvedPath, account: account,
                             change: change, index: index, scriptType: selectedScript,
                             address: try publicKeyToAddress(publicKey, chain: chain, scriptType: selectedScript),
                             publicKey: publicKey)
    }

    public static func deriveAddresses(
        source: HDSource, chain: HDChain = .bitcoin, account: UInt32 = 0,
        change: UInt32 = 0, start: UInt32 = 0, count: Int = 20,
        scriptType: HDScriptType? = nil, format: String? = nil
    ) throws -> [DerivedAddress] {
        guard (1...10_000).contains(count) else { throw WalletHDError.invalidArgument("count must be between 1 and 10000") }
        guard UInt64(start) + UInt64(count) <= 0x80000000 else { throw WalletHDError.invalidArgument("batch index exceeds 2147483647") }
        return try (0..<count).map {
            try deriveAddress(source: source, chain: chain, account: account, change: change,
                              index: start + UInt32($0), scriptType: scriptType, format: format)
        }
    }

    public static func deriveAddressFromExtendedPublicKey(
        _ extendedPublicKey: String, chain: HDChain, change: UInt32 = 0,
        index: UInt32 = 0, scriptType: HDScriptType? = nil
    ) throws -> DerivedAddress {
        try validatePublicIndex(change, name: "change")
        try validatePublicIndex(index, name: "index")
        let configuration = try requireChain(chain)
        guard configuration.curve == .secp256k1 else { throw WalletHDError.unsupported("extended public derivation is secp256k1-only") }
        let parsed = try parseExtendedKey(extendedPublicKey)
        guard !parsed.isPrivate else { throw WalletHDError.invalidKey("use an extended public key, not an extended private key") }
        let keyData = try parseHex(parsed.keyDataHex)
        let chainCode = try parseHex(parsed.chainCodeHex)
        let root = PublicNode(publicKey: keyData, chainCode: chainCode, depth: parsed.depth,
                              parentFingerprint: parsed.parentFingerprint, childNumber: parsed.childNumber)
        let node = try root.derive(change).derive(index)
        let selectedScript = scriptType ?? inferScriptType(version: parsed.version, fallback: configuration.addressKind)
        return addressResult(chain: chain, configuration: configuration, path: "\(change)/\(index)", account: 0,
                             change: change, index: index, scriptType: selectedScript,
                             address: try publicKeyToAddress(node.publicKey, chain: chain, scriptType: selectedScript),
                             publicKey: node.publicKey)
    }

    public static func parseExtendedKey(_ serialized: String) throws -> ParsedExtendedKey {
        let payload = try base58CheckDecode(serialized)
        guard payload.count == 78 else { throw WalletHDError.invalidKey("extended-key payload must be 78 bytes") }
        let version = readUInt32(Array(payload[0..<4]))
        let depth = payload[4]
        let parentFingerprint = readUInt32(Array(payload[5..<9]))
        let childNumber = readUInt32(Array(payload[9..<13]))
        let chainCode = Array(payload[13..<45])
        let keyData = Array(payload[45..<78])
        let isPrivate = keyData[0] == 0
        let registered = formats.values.contains {
            isPrivate ? $0.privateVersion == version : $0.publicVersion == version
        }
        guard registered else { throw WalletHDError.invalidKey("unknown or mismatched extended-key version") }
        guard depth != 0 || (parentFingerprint == 0 && childNumber == 0) else {
            throw WalletHDError.invalidKey("root extended key must have zero parent fingerprint and child number")
        }
        if isPrivate {
            guard keyData.count == 33 else { throw WalletHDError.invalidKey("invalid extended private key") }
            _ = try validatedPrivateKey(Array(keyData.dropFirst()))
        } else {
            do { try validateSecpPublicKey(keyData) }
            catch { throw WalletHDError.invalidKey("invalid compressed extended public key") }
        }
        return ParsedExtendedKey(serialized: serialized, version: version, depth: depth,
                                 parentFingerprint: parentFingerprint, childNumber: childNumber,
                                 chainCodeHex: hex(chainCode), keyDataHex: hex(keyData), isPrivate: isPrivate)
    }

    public static func serializeExtendedKey(_ key: ParsedExtendedKey, version: UInt32? = nil) throws -> String {
        let chainCode = try parseHex(key.chainCodeHex)
        let keyData = try parseHex(key.keyDataHex)
        guard chainCode.count == 32, keyData.count == 33 else { throw WalletHDError.invalidKey("invalid parsed extended-key fields") }
        let payload = ser32(version ?? key.version) + [key.depth] + ser32(key.parentFingerprint)
            + ser32(key.childNumber) + chainCode + keyData
        return base58CheckEncode(payload)
    }
}

private func addressResult(
    chain: HDChain, configuration: ChainConfiguration, path: String, account: UInt32,
    change: UInt32, index: UInt32, scriptType: HDScriptType, address: String, publicKey: [UInt8]
) -> DerivedAddress {
    DerivedAddress(schemaVersion: walletHDSchemaVersion, chain: chain, curve: configuration.curve,
                   path: path, account: account, change: change, index: index,
                   scriptType: scriptType, address: address, publicKeyHex: hex(publicKey))
}

private func sourceToSeed(_ source: HDSource) throws -> [UInt8] {
    switch source {
    case .mnemonic(let mnemonic, let passphrase):
        do { return Array(try BIP39.seed(from: mnemonic, passphrase: passphrase)) }
        catch { throw WalletHDError.invalidSource("invalid BIP-39 English mnemonic") }
    case .seed(let seed):
        guard (16...64).contains(seed.count) else { throw WalletHDError.invalidSource("seed must contain 16 to 64 bytes") }
        return Array(seed)
    }
}

private func master(seed: [UInt8]) throws -> PrivateNode {
    guard (16...64).contains(seed.count) else { throw WalletHDError.invalidSource("seed must contain 16 to 64 bytes") }
    var material = seed
    while true {
        let digest = try hmacSHA512(key: Array("Bitcoin seed".utf8), data: material)
        let candidate = Array(digest.prefix(32))
        if (try? validatedPrivateKey(candidate)) != nil {
            return PrivateNode(privateKey: candidate, chainCode: Array(digest.suffix(32)), depth: 0,
                               parentFingerprint: 0, childNumber: 0)
        }
        material = digest
    }
}

private struct Slip10Node {
    let privateKey: [UInt8]
    let publicKey: [UInt8]
    let chainCode: [UInt8]
    let depth: UInt8
    let childNumber: UInt32
}

private func deriveSlip10(seed: [UInt8], path: String) throws -> Slip10Node {
    guard (16...64).contains(seed.count) else { throw WalletHDError.invalidSource("seed must contain 16 to 64 bytes") }
    var digest = try hmacSHA512(key: Array("ed25519 seed".utf8), data: seed)
    var privateKey = Array(digest.prefix(32))
    var chainCode = Array(digest.suffix(32))
    var depth: UInt8 = 0
    var childNumber: UInt32 = 0
    for index in try parsePath(path) {
        guard index >= 0x80000000 else { throw WalletHDError.invalidPath("SLIP-0010 Ed25519 supports hardened derivation only") }
        guard depth < UInt8.max else { throw WalletHDError.invalidPath("derivation path depth exceeds 255") }
        digest = try hmacSHA512(key: chainCode, data: [0] + privateKey + ser32(index))
        privateKey = Array(digest.prefix(32))
        chainCode = Array(digest.suffix(32))
        depth += 1
        childNumber = index
    }
    let publicKey = Array(try Curve25519.Signing.PrivateKey(rawRepresentation: Data(privateKey)).publicKey.rawRepresentation)
    return Slip10Node(privateKey: privateKey, publicKey: publicKey, chainCode: chainCode, depth: depth, childNumber: childNumber)
}

private func parsePath(_ path: String) throws -> [UInt32] {
    guard path == "m" || path == "M" || path.hasPrefix("m/") || path.hasPrefix("M/") else {
        throw WalletHDError.invalidPath("absolute derivation path must start with m")
    }
    if path == "m" || path == "M" { return [] }
    let parts = path.split(separator: "/", omittingEmptySubsequences: false).dropFirst()
    guard parts.count <= 255 else { throw WalletHDError.invalidPath("derivation path depth exceeds 255") }
    return try parts.map { component in
        let value = String(component)
        guard !value.isEmpty else { throw WalletHDError.invalidPath("empty derivation path component") }
        let hardened = value.hasSuffix("'") || value.hasSuffix("h") || value.hasSuffix("H")
        let raw = hardened ? String(value.dropLast()) : value
        guard !raw.isEmpty, raw.allSatisfy(\.isNumber), raw == "0" || !raw.hasPrefix("0"),
              let index = UInt32(raw), index < 0x80000000 else {
            throw WalletHDError.invalidPath("invalid path component: \(value)")
        }
        return hardened ? index + 0x80000000 : index
    }
}

private func accountPath(chain: HDChain, account: UInt32, format: String?, scriptType: HDScriptType?) throws -> String {
    try validatePublicIndex(account, name: "account")
    let configuration = try requireChain(chain)
    if configuration.curve == .ed25519 { return "m/44'/\(configuration.coinType)'/\(account)'" }
    if configuration.addressKind == .evm || configuration.addressKind == .tron {
        return "m/44'/\(configuration.coinType)'/\(account)'"
    }
    let purpose = scriptType == .p2tr ? 86 : try resolveFormat(chain: chain, format: format, scriptType: scriptType).value.purpose
    return "m/\(purpose)'/\(configuration.coinType)'/\(account)'"
}

private func resolveFormat(chain: HDChain, format: String?, scriptType: HDScriptType?) throws -> (name: String, value: ExtendedFormat) {
    let configuration = try requireChain(chain)
    guard !configuration.formats.isEmpty else { throw WalletHDError.unsupported("\(chain.rawValue) does not define Bitcoin-style extended-key versions") }
    let selected = format ?? (scriptType == .p2tr ? "xpub" : configuration.defaultFormat!)
    guard configuration.formats.contains(selected), let value = formats[selected] else {
        throw WalletHDError.unsupported("format \(selected) is not registered for \(chain.rawValue)")
    }
    return (selected, value)
}

private func requireChain(_ chain: HDChain) throws -> ChainConfiguration {
    guard let configuration = chains[chain] else { throw WalletHDError.unsupported("unsupported chain: \(chain.rawValue)") }
    return configuration
}

private func validatePublicIndex(_ value: UInt32, name: String) throws {
    guard value < 0x80000000 else { throw WalletHDError.invalidArgument("\(name) must be between 0 and 2147483647") }
}

private func serialize(node: PrivateNode, version: UInt32, privateKey: Bool) throws -> String {
    let keyData = privateKey ? [0] + node.privateKey : try node.publicKey
    let payload = ser32(version) + [node.depth] + ser32(node.parentFingerprint) + ser32(node.childNumber) + node.chainCode + keyData
    return base58CheckEncode(payload)
}

private func publicKeyToAddress(_ publicKey: [UInt8], chain: HDChain, scriptType: HDScriptType) throws -> String {
    let configuration = try requireChain(chain)
    switch scriptType {
    case .evm: return try evmAddress(publicKey)
    case .tron: return base58CheckEncode([0x41] + Array(try keccak(uncompressed(publicKey).dropFirst()).suffix(20)))
    case .cashaddr:
        guard let prefix = configuration.cashaddrPrefix else { throw WalletHDError.unsupported("chain has no CashAddr prefix") }
        return cashAddress(prefix: prefix, hash: hash160(publicKey))
    case .p2pkh:
        guard let prefix = configuration.p2pkh else { throw WalletHDError.unsupported("chain has no P2PKH prefix") }
        return base58CheckEncode(prefix + hash160(publicKey))
    case .p2shP2wpkh:
        guard let prefix = configuration.p2sh else { throw WalletHDError.unsupported("chain has no P2SH prefix") }
        return base58CheckEncode(prefix + hash160([0, 20] + hash160(publicKey)))
    case .p2wpkh:
        guard let hrp = configuration.hrp else { throw WalletHDError.unsupported("chain has no SegWit HRP") }
        return try segwitAddress(hrp: hrp, version: 0, program: hash160(publicKey))
    case .p2tr:
        guard let hrp = configuration.hrp else { throw WalletHDError.unsupported("chain has no SegWit HRP") }
        return try segwitAddress(hrp: hrp, version: 1, program: taprootOutputKey(publicKey))
    case .solana: return base58Encode(publicKey)
    }
}

private func evmAddress(_ publicKey: [UInt8]) throws -> String {
    let raw = hex(Array(try keccak(uncompressed(publicKey).dropFirst()).suffix(20)))
    let checksum = hex(try keccak(Array(raw.utf8)))
    return "0x" + zip(raw.enumerated(), checksum).map { item, check in
        let (_, character) = item
        guard character.isLetter, let nibble = Int(String(check), radix: 16), nibble >= 8 else { return String(character) }
        return String(character).uppercased()
    }.joined()
}

private func uncompressed(_ publicKey: [UInt8]) throws -> [UInt8] {
    do { return try secpUncompressedPublicKey(publicKey) }
    catch { throw WalletHDError.invalidKey("invalid compressed secp256k1 public key") }
}

private func taprootOutputKey(_ publicKey: [UInt8]) throws -> [UInt8] {
    guard publicKey.count == 33 else { throw WalletHDError.invalidKey("Taproot requires a compressed key") }
    let xOnly = Array(publicKey.dropFirst())
    let tweak = taggedHash(tag: "TapTweak", data: xOnly)
    do { return Array(try secpAddPublicKey([0x02] + xOnly, tweak: tweak).dropFirst()) }
    catch { throw WalletHDError.invalidKey("invalid Taproot tweak") }
}

private func inferScriptType(version: UInt32, fallback: HDScriptType) -> HDScriptType {
    switch version {
    case 0x049d7cb2, 0x044a5262, 0x01b26ef6: .p2shP2wpkh
    case 0x04b24746, 0x045f1cf6: .p2wpkh
    default: fallback
    }
}

private let bech32Alphabet = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
private let bech32Generators: [UInt32] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

private func segwitAddress(hrp: String, version: UInt8, program: [UInt8]) throws -> String {
    let words = [version] + convertBits(program, from: 8, to: 5, pad: true)
    return bech32Encode(hrp: hrp, words: words, constant: version == 0 ? 1 : 0x2bc830a3)
}

private func bech32Encode(hrp: String, words: [UInt8], constant: UInt32) -> String {
    let high = hrp.utf8.map { $0 >> 5 }
    let low = hrp.utf8.map { $0 & 31 }
    let mod = bech32Polymod(high + [0] + low + words + [UInt8](repeating: 0, count: 6)) ^ constant
    let checksum = (0..<6).map { UInt8((mod >> UInt32(5 * (5 - $0))) & 31) }
    return hrp + "1" + (words + checksum).map { String(bech32Alphabet[Int($0)]) }.joined()
}

private func bech32Polymod(_ values: [UInt8]) -> UInt32 {
    var checksum: UInt32 = 1
    for value in values {
        let top = checksum >> 25
        checksum = ((checksum & 0x1ffffff) << 5) ^ UInt32(value)
        for index in 0..<5 where ((top >> UInt32(index)) & 1) == 1 { checksum ^= bech32Generators[index] }
    }
    return checksum
}

private let cashGenerators: [UInt64] = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]

private func cashAddress(prefix: String, hash: [UInt8]) -> String {
    let payload = convertBits([0] + hash, from: 8, to: 5, pad: true)
    let prefixValues = prefix.utf8.map { $0 & 31 }
    var checksum: UInt64 = 1
    for value in prefixValues + [0] + payload + [UInt8](repeating: 0, count: 8) {
        let top = checksum >> 35
        checksum = ((checksum & 0x07ffffffff) << 5) ^ UInt64(value)
        for index in 0..<5 where ((top >> UInt64(index)) & 1) == 1 { checksum ^= cashGenerators[index] }
    }
    checksum ^= 1
    let sum = (0..<8).map { UInt8((checksum >> UInt64(5 * (7 - $0))) & 31) }
    return prefix + ":" + (payload + sum).map { String(bech32Alphabet[Int($0)]) }.joined()
}

private func convertBits(_ data: [UInt8], from: Int, to: Int, pad: Bool) -> [UInt8] {
    var accumulator = 0
    var bits = 0
    let mask = (1 << to) - 1
    var output: [UInt8] = []
    for value in data {
        accumulator = (accumulator << from) | Int(value)
        bits += from
        while bits >= to {
            bits -= to
            output.append(UInt8((accumulator >> bits) & mask))
        }
    }
    if pad && bits > 0 { output.append(UInt8((accumulator << (to - bits)) & mask)) }
    return output
}

private let base58Alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

private func base58Encode(_ bytes: [UInt8]) -> String {
    guard !bytes.isEmpty else { return "" }
    var digits = [UInt8](repeating: 0, count: bytes.count * 138 / 100 + 1)
    var length = 0
    for byte in bytes {
        var carry = Int(byte)
        var index = 0
        while index < length || carry != 0 {
            carry += 256 * Int(digits[index])
            digits[index] = UInt8(carry % 58)
            carry /= 58
            index += 1
        }
        length = index
    }
    let zeros = bytes.prefix { $0 == 0 }.count
    return String(repeating: "1", count: zeros) + digits.prefix(length).reversed().map { String(base58Alphabet[Int($0)]) }.joined()
}

private func base58Decode(_ string: String) throws -> [UInt8] {
    guard !string.isEmpty else { return [] }
    let lookup = Dictionary(uniqueKeysWithValues: base58Alphabet.enumerated().map { ($1, $0) })
    var bytes = [UInt8](repeating: 0, count: string.utf8.count)
    var length = 0
    for character in string {
        guard var carry = lookup[character] else { throw WalletHDError.invalidKey("invalid Base58 character") }
        var index = 0
        while index < length || carry != 0 {
            carry += 58 * Int(bytes[index])
            bytes[index] = UInt8(carry & 0xff)
            carry >>= 8
            index += 1
        }
        length = index
    }
    let zeros = string.prefix { $0 == "1" }.count
    return [UInt8](repeating: 0, count: zeros) + bytes.prefix(length).reversed()
}

private func base58CheckEncode(_ payload: [UInt8]) -> String {
    base58Encode(payload + doubleSHA256(payload).prefix(4))
}

private func base58CheckDecode(_ string: String) throws -> [UInt8] {
    let decoded = try base58Decode(string)
    guard decoded.count >= 4 else { throw WalletHDError.invalidKey("Base58Check value is too short") }
    let payload = Array(decoded.dropLast(4))
    guard Array(decoded.suffix(4)) == Array(doubleSHA256(payload).prefix(4)) else {
        throw WalletHDError.invalidKey("invalid Base58Check checksum")
    }
    return payload
}

private func validatedPrivateKey(_ bytes: [UInt8]) throws -> [UInt8] {
    do {
        _ = try secpPublicKey(fromPrivateKey: bytes)
        return bytes
    }
    catch { throw WalletHDError.invalidKey("invalid secp256k1 private key") }
}

private func secpPublicKey(fromPrivateKey privateKey: [UInt8]) throws -> [UInt8] {
#if canImport(P256K)
    let key = try P256K.Signing.PrivateKey(dataRepresentation: Data(privateKey), format: .compressed)
    return Array(key.publicKey.dataRepresentation)
#else
    guard privateKey.count == 32,
          let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)) else {
        throw WalletHDError.invalidKey("invalid secp256k1 private key")
    }
    defer { secp256k1_context_destroy(context) }
    guard secp256k1_ec_seckey_verify(context, privateKey) == 1 else {
        throw WalletHDError.invalidKey("invalid secp256k1 private key")
    }
    var key = secp256k1_pubkey()
    guard secp256k1_ec_pubkey_create(context, &key, privateKey) == 1 else {
        throw WalletHDError.invalidKey("unable to derive secp256k1 public key")
    }
    return try secpSerializePublicKey(key, compressed: true, context: context)
#endif
}

private func secpAddPrivateKey(_ privateKey: [UInt8], tweak: [UInt8]) throws -> [UInt8] {
#if canImport(P256K)
    let key = try P256K.Signing.PrivateKey(dataRepresentation: Data(privateKey), format: .compressed)
    return Array(try key.add(tweak).dataRepresentation)
#else
    guard privateKey.count == 32, tweak.count == 32,
          let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)) else {
        throw WalletHDError.invalidKey("invalid secp256k1 private key or tweak")
    }
    defer { secp256k1_context_destroy(context) }
    var child = privateKey
    guard secp256k1_ec_seckey_tweak_add(context, &child, tweak) == 1 else {
        throw WalletHDError.invalidKey("invalid secp256k1 child tweak")
    }
    return child
#endif
}

private func secpAddPublicKey(_ publicKey: [UInt8], tweak: [UInt8]) throws -> [UInt8] {
#if canImport(P256K)
    let key = try P256K.Signing.PublicKey(dataRepresentation: Data(publicKey), format: .compressed)
    return Array(try key.add(tweak, format: .compressed).dataRepresentation)
#else
    guard publicKey.count == 33, tweak.count == 32,
          let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY)) else {
        throw WalletHDError.invalidKey("invalid secp256k1 public key or tweak")
    }
    defer { secp256k1_context_destroy(context) }
    var key = secp256k1_pubkey()
    guard secp256k1_ec_pubkey_parse(context, &key, publicKey, publicKey.count) == 1,
          secp256k1_ec_pubkey_tweak_add(context, &key, tweak) == 1 else {
        throw WalletHDError.invalidKey("invalid secp256k1 public child")
    }
    return try secpSerializePublicKey(key, compressed: true, context: context)
#endif
}

private func validateSecpPublicKey(_ publicKey: [UInt8]) throws {
#if canImport(P256K)
    _ = try P256K.Signing.PublicKey(dataRepresentation: Data(publicKey), format: .compressed)
#else
    guard publicKey.count == 33,
          let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY)) else {
        throw WalletHDError.invalidKey("invalid secp256k1 public key")
    }
    defer { secp256k1_context_destroy(context) }
    var key = secp256k1_pubkey()
    guard secp256k1_ec_pubkey_parse(context, &key, publicKey, publicKey.count) == 1 else {
        throw WalletHDError.invalidKey("invalid secp256k1 public key")
    }
#endif
}

private func secpUncompressedPublicKey(_ publicKey: [UInt8]) throws -> [UInt8] {
#if canImport(P256K)
    let key = try P256K.Signing.PublicKey(dataRepresentation: Data(publicKey), format: .compressed)
    return Array(key.uncompressedRepresentation)
#else
    guard let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE)) else {
        throw WalletHDError.invalidKey("unable to create secp256k1 context")
    }
    defer { secp256k1_context_destroy(context) }
    var parsed = secp256k1_pubkey()
    guard secp256k1_ec_pubkey_parse(context, &parsed, publicKey, publicKey.count) == 1 else {
        throw WalletHDError.invalidKey("invalid secp256k1 public key")
    }
    return try secpSerializePublicKey(parsed, compressed: false, context: context)
#endif
}

#if canImport(secp256k1Wrapper) && !canImport(P256K)
private func secpSerializePublicKey(
    _ publicKey: secp256k1_pubkey, compressed: Bool, context: OpaquePointer
) throws -> [UInt8] {
    var key = publicKey
    var output = [UInt8](repeating: 0, count: compressed ? 33 : 65)
    var outputCount = output.count
    let flag = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED
    guard secp256k1_ec_pubkey_serialize(context, &output, &outputCount, &key, UInt32(flag)) == 1 else {
        throw WalletHDError.invalidKey("unable to serialize secp256k1 public key")
    }
    return output
}
#endif

private func hmacSHA512(key: [UInt8], data: [UInt8]) throws -> [UInt8] {
    try HMAC(key: key, variant: .sha2(.sha512)).authenticate(data)
}

private func sha256(_ bytes: [UInt8]) -> [UInt8] { bytes.sha256() }
private func doubleSHA256(_ bytes: [UInt8]) -> [UInt8] { sha256(sha256(bytes)) }
private func hash160(_ bytes: [UInt8]) -> [UInt8] { RIPEMD160.hash(sha256(bytes)) }
private func keccak<C: Collection>(_ bytes: C) throws -> [UInt8] where C.Element == UInt8 { Array(bytes).sha3(.keccak256) }

private func taggedHash(tag: String, data: [UInt8]) -> [UInt8] {
    let tagHash = sha256(Array(tag.utf8))
    return sha256(tagHash + tagHash + data)
}

private func ser32(_ value: UInt32) -> [UInt8] {
    [UInt8(value >> 24), UInt8((value >> 16) & 0xff), UInt8((value >> 8) & 0xff), UInt8(value & 0xff)]
}

private func readUInt32(_ bytes: [UInt8]) -> UInt32 {
    bytes.reduce(0) { ($0 << 8) | UInt32($1) }
}

private func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

private func parseHex(_ string: String) throws -> [UInt8] {
    guard string.count.isMultiple(of: 2) else { throw WalletHDError.invalidKey("hex string has odd length") }
    return try stride(from: 0, to: string.count, by: 2).map { offset in
        let start = string.index(string.startIndex, offsetBy: offset)
        let end = string.index(start, offsetBy: 2)
        guard let byte = UInt8(string[start..<end], radix: 16) else { throw WalletHDError.invalidKey("invalid hex string") }
        return byte
    }
}
