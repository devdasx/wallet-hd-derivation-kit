import Foundation
import WalletHDDerivationKit

let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
let values = try Dictionary(uniqueKeysWithValues: HDChain.allCases.map { chain in
    (chain.rawValue, try WalletHDDerivationKit.deriveAddress(source: .mnemonic(words), chain: chain).address)
})
let data = try JSONSerialization.data(withJSONObject: values, options: [.sortedKeys])
print("WALLETHD_CONFORMANCE=" + String(decoding: data, as: UTF8.self))
