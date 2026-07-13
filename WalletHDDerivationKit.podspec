Pod::Spec.new do |spec|
  spec.name = "WalletHDDerivationKit"
  spec.version = "1.0.1"
  spec.summary = "Offline multi-chain HD wallet derivation for Swift."
  spec.description = <<-DESC
    Native BIP-32, BIP-44/49/84/86, SLIP-0010, SLIP-0132, extended-key,
    Bitcoin, EVM, TRON, Solana, Litecoin, Dogecoin, Dash, DigiByte, BCH,
    and Zcash transparent address derivation. No runtime network calls.
  DESC
  spec.homepage = "https://devdasx.github.io/wallet-hd-derivation-kit/swift/"
  spec.source = { :git => "https://github.com/devdasx/wallet-hd-derivation-kit.git", :tag => "v#{spec.version}" }
  spec.license = { :type => "MIT", :file => "LICENSE" }
  spec.author = { "ROYO STUDIOS" => "devdas98x@gmail.com" }
  spec.social_media_url = "https://github.com/devdasx"
  spec.swift_version = "6.0"
  # The secp256k1 pod ships a statically linked XCFramework. Declaring this
  # pod as a static framework makes that linkage explicit for CocoaPods.
  spec.static_framework = true
  # The mnemonic dependency currently publishes CocoaPods support for iOS and
  # macOS. Swift Package Manager consumers retain the broader platform matrix.
  spec.ios.deployment_target = "15.0"
  spec.osx.deployment_target = "12.0"
  spec.source_files = "Sources/WalletHDDerivationKit/**/*.swift"
  spec.dependency "CryptoSwift", "1.10.0"
  spec.dependency "secp256k1Wrapper", "0.0.5"
  spec.dependency "BIP39MnemonicKit", "2.0.1"
  spec.test_spec "Tests" do |tests|
    tests.source_files = "Tests/CocoaPods/**/*.swift"
  end
end
