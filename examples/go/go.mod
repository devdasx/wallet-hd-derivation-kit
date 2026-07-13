module example.com/wallethd-example

go 1.25.0

require github.com/devdasx/wallet-hd-derivation-kit v1.0.1

require (
	github.com/btcsuite/btcd/btcec/v2 v2.5.0 // indirect
	github.com/decred/dcrd/crypto/ripemd160 v1.0.2 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/devdasx/bip39-mnemonic-kit/v2 v2.0.1 // indirect
	github.com/filecoin-project/go-keccak v0.1.0 // indirect
	github.com/mr-tron/base58 v1.3.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

replace github.com/devdasx/wallet-hd-derivation-kit => ../..
