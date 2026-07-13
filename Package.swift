// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "WalletHDDerivationKit",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .tvOS(.v15),
        .watchOS(.v8),
    ],
    products: [
        .library(name: "WalletHDDerivationKit", targets: ["WalletHDDerivationKit"]),
        .executable(name: "WalletHDConformance", targets: ["WalletHDConformance"]),
    ],
    dependencies: [
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", exact: "0.23.2"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", exact: "1.10.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.5.0"),
        .package(url: "https://github.com/devdasx/bip39-mnemonic-kit.git", exact: "2.0.1"),
        .package(url: "https://github.com/swiftlang/swift-docc-plugin.git", exact: "1.5.0"),
    ],
    targets: [
        .target(
            name: "WalletHDDerivationKit",
            dependencies: [
                .product(name: "P256K", package: "secp256k1.swift"),
                .product(name: "CryptoSwift", package: "CryptoSwift"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "BIP39MnemonicKit", package: "bip39-mnemonic-kit"),
            ],
            path: "Sources/WalletHDDerivationKit"
        ),
        .testTarget(
            name: "WalletHDDerivationKitTests",
            dependencies: ["WalletHDDerivationKit"],
            path: "Tests/WalletHDDerivationKitTests"
        ),
        .executableTarget(
            name: "WalletHDConformance",
            dependencies: ["WalletHDDerivationKit"],
            path: "Sources/WalletHDConformance"
        ),
    ],
    swiftLanguageModes: [.v6]
)
