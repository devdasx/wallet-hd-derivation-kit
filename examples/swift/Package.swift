// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "WalletHDExample",
    platforms: [.macOS(.v12)],
    dependencies: [.package(name: "WalletHDDerivationKitPackage", path: "../..")],
    targets: [
        .executableTarget(
            name: "WalletHDExample",
            dependencies: [
                .product(name: "WalletHDDerivationKit", package: "WalletHDDerivationKitPackage")
            ]
        )
    ]
)
