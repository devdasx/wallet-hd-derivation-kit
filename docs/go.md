---
layout: default
title: Go HD wallet derivation
description: Import github.com/devdasx/wallet-hd-derivation-kit for native Go BIP32, SLIP10 and multi-chain address derivation.
permalink: /go/
---

# Go

```sh
go get github.com/devdasx/wallet-hd-derivation-kit@v1.0.1
```

```go
source := wallethd.MnemonicSource(os.Getenv("WALLET_MNEMONIC"), "")
result, err := wallethd.DeriveAddress(source, wallethd.Options{Chain: "dogecoin"})
if err != nil { log.Fatal(err) }
fmt.Println(result.Address)
```

The module is discoverable through pkg.go.dev after the public tag is fetched. [Runnable example](https://github.com/devdasx/wallet-hd-derivation-kit/tree/main/examples/go).
