module example.com/wallethd-example

go 1.25.0

require github.com/devdasx/wallet-hd-derivation-kit v1.0.0

require (
	github.com/btcsuite/btcd/btcec/v2 v2.5.0 // indirect
	github.com/btcsuite/btcd/btcutil v1.2.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/tyler-smith/go-bip39 v1.1.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

replace github.com/devdasx/wallet-hd-derivation-kit => ../..
