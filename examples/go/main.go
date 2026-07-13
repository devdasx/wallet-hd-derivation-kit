package main

import (
	"fmt"

	wallethd "github.com/devdasx/wallet-hd-derivation-kit"
)

func main() {
	words := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	value, err := wallethd.DeriveAddress(wallethd.MnemonicSource(words, ""), wallethd.Options{Chain: "dogecoin"})
	if err != nil {
		panic(err)
	}
	fmt.Println(value.Address)
}
