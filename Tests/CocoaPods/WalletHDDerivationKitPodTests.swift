import XCTest
@testable import WalletHDDerivationKit

final class WalletHDDerivationKitPodTests: XCTestCase {
    private let source = HDSource.mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    )

    func testCocoaPodsCryptoBackendAgainstPublicVectors() throws {
        let taproot = try WalletHDDerivationKit.deriveAddress(
            source: source, chain: .bitcoin, scriptType: .p2tr
        )
        XCTAssertEqual(taproot.address, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")

        let ethereum = try WalletHDDerivationKit.deriveAddress(source: source, chain: .ethereum)
        XCTAssertEqual(ethereum.address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94")

        let account = try WalletHDDerivationKit.deriveAccountPublicKey(source: source)
        let watched = try WalletHDDerivationKit.deriveAddressFromExtendedPublicKey(
            account.extendedPublicKey, chain: .bitcoin
        )
        XCTAssertEqual(watched.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    }
}
