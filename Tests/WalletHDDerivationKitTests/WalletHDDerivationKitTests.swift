import Foundation
import Testing
@testable import WalletHDDerivationKit

private let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
private let source = HDSource.mnemonic(mnemonic)

@Test func officialAndCrossChainVectors() throws {
    let vectors: [(HDChain, HDScriptType?, String)] = [
        (.bitcoin, nil, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
        (.bitcoinTestnet, nil, "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"),
        (.litecoin, nil, "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez"),
        (.dogecoin, nil, "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC"),
        (.dash, nil, "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5"),
        (.digibyte, nil, "DG1KhhBKpsyWXTakHNezaDQ34focsXjN1i"),
        (.bitcoinCash, nil, "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6"),
        (.zcashTransparent, nil, "t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F"),
        (.ethereum, nil, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
        (.ethereumClassic, nil, "0xFA22515E43658ce56A7682B801e9B5456f511420"),
        (.tron, nil, "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"),
        (.solana, nil, "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"),
    ]
    for (chain, script, expected) in vectors {
        #expect(try WalletHDDerivationKit.deriveAddress(source: source, chain: chain, scriptType: script).address == expected)
    }
}

@Test func bitcoinFormatsTaprootAndWatchOnly() throws {
    let legacy = try WalletHDDerivationKit.deriveAddress(source: source, chain: .bitcoin, scriptType: .p2pkh, format: "xpub")
    #expect(legacy.address == "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA")
    #expect(try WalletHDDerivationKit.deriveAddress(source: source, chain: .bitcoin, scriptType: .p2shP2wpkh, format: "ypub").address == "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf")
    #expect(try WalletHDDerivationKit.deriveAddress(source: source, chain: .bitcoin, scriptType: .p2tr).address == "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")

    let account = try WalletHDDerivationKit.deriveAccountPublicKey(source: source)
    #expect(account.extendedPublicKey == "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
    let watch = try WalletHDDerivationKit.deriveAddressFromExtendedPublicKey(account.extendedPublicKey, chain: .bitcoin)
    #expect(watch.address == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")

    let privateAccount = try WalletHDDerivationKit.deriveAccountPrivateKey(source: source)
    #expect(privateAccount.extendedPrivateKey == "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE")
}

@Test func serializationAndFailureBoundaries() throws {
    let account = try WalletHDDerivationKit.deriveAccountPublicKey(source: source)
    let parsed = try WalletHDDerivationKit.parseExtendedKey(account.extendedPublicKey)
    #expect(!parsed.isPrivate)
    #expect(try WalletHDDerivationKit.serializeExtendedKey(parsed) == account.extendedPublicKey)
    #expect(throws: WalletHDError.self) { try WalletHDDerivationKit.deriveNode(source: .mnemonic("abandon abandon")) }
    #expect(throws: WalletHDError.self) { try WalletHDDerivationKit.deriveNode(source: source, path: "m/00") }
    #expect(throws: WalletHDError.self) {
        try WalletHDDerivationKit.deriveAddressFromExtendedPublicKey(account.extendedPublicKey, chain: .bitcoin, change: 0x80000000)
    }
}

@Test func hashAndBIP32ReferenceVectors() throws {
    #expect(RIPEMD160.hash(Array("".utf8)).map { String(format: "%02x", $0) }.joined() == "9c1185a5c5e9fc54612808977ee8f548b2258d31")
    let seed = Data((0...15).map(UInt8.init))
    let privateRoot = try WalletHDDerivationKit.deriveAccountPrivateKey(source: .seed(seed), chain: .bitcoin, format: "xpub", path: "m")
    #expect(privateRoot.extendedPrivateKey == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
    // The shared public collection supplies cross-runtime vectors; this test
    // additionally exercises the official BIP-32 root vector on-device.
    #expect(!privateRoot.privateKeyHex.isEmpty)
}

@Test func rejectsEveryOfficialBIP32InvalidExtendedKey() throws {
    let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let data = try Data(contentsOf: root.appendingPathComponent("test-vectors/bip32-official.json"))
    let json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    let invalid = try #require(json["invalidExtendedKeys"] as? [[String: String]])
    #expect(invalid.count == 16)
    for vector in invalid {
        let value = try #require(vector["value"])
        #expect(throws: WalletHDError.self) { try WalletHDDerivationKit.parseExtendedKey(value) }
    }
}
