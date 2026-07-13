from wallet_hd_derivation_kit import derive_account_public_key, derive_address

source = {"mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}
print(derive_address(source, chain="ethereum")["address"])
print(derive_account_public_key(source, chain="bitcoin")["extendedPublicKey"])
