import json

from wallet_hd_derivation_kit import derive_address, supported_chains

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
result = {chain["id"]: derive_address({"mnemonic": MNEMONIC}, chain=chain["id"])["address"] for chain in supported_chains()}
print("WALLETHD_CONFORMANCE=" + json.dumps(result, sort_keys=True, separators=(",", ":")))
