import WalletHDDerivationKit

let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
let result = try WalletHDDerivationKit.deriveAddress(source: .mnemonic(words), chain: .bitcoin, scriptType: .p2tr)
print(result.address)
