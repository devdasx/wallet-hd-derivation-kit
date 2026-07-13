package main

import (
	"encoding/json"
	"fmt"

	wallethd "github.com/devdasx/wallet-hd-derivation-kit"
)

func main() {
	words := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	values := map[string]string{}
	for _, chain := range wallethd.SupportedChains() {
		value, err := wallethd.DeriveAddress(wallethd.MnemonicSource(words, ""), wallethd.Options{Chain: chain.ID})
		if err != nil {
			panic(err)
		}
		values[chain.ID] = value.Address
	}
	data, err := json.Marshal(values)
	if err != nil {
		panic(err)
	}
	fmt.Printf("WALLETHD_CONFORMANCE=%s\n", data)
}
