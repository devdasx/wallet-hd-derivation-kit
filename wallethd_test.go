package wallethd

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"
)

type officialBIP32Vectors struct {
	InvalidExtendedKeys []struct {
		Value  string `json:"value"`
		Reason string `json:"reason"`
	} `json:"invalidExtendedKeys"`
}

const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

var testSource = MnemonicSource(testMnemonic, "")

func TestBitcoinSLIP132AndWatchOnly(t *testing.T) {
	account, err := DeriveAccountPublicKey(testSource, Options{Format: "zpub"})
	if err != nil {
		t.Fatal(err)
	}
	const zpub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
	if account.ExtendedPublicKey != zpub {
		t.Fatalf("zpub mismatch: %s", account.ExtendedPublicKey)
	}
	direct, err := DeriveAddress(testSource, Options{})
	if err != nil {
		t.Fatal(err)
	}
	watched, err := DeriveAddressFromExtendedPublicKey(zpub, "bitcoin", 0, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if direct.Address != "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" || direct.Address != watched.Address {
		t.Fatalf("watch-only mismatch: %s %s", direct.Address, watched.Address)
	}
}

func TestPrivateAndSerializationRoundTrip(t *testing.T) {
	secret, err := DeriveAccountPrivateKey(testSource, Options{Format: "zpub"})
	if err != nil {
		t.Fatal(err)
	}
	const zprv = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE"
	if secret.ExtendedPrivateKey == nil || *secret.ExtendedPrivateKey != zprv {
		t.Fatal("zprv mismatch")
	}
	parsed, err := ParseExtendedKey(zprv)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := SerializeExtendedKey(parsed, true, "")
	if err != nil || serialized != zprv {
		t.Fatalf("round trip failed: %s %v", serialized, err)
	}
}

func TestRejectsEveryOfficialBIP32InvalidExtendedKey(t *testing.T) {
	data, err := os.ReadFile("test-vectors/bip32-official.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors officialBIP32Vectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range vectors.InvalidExtendedKeys {
		if _, err := ParseExtendedKey(invalid.Value); err == nil {
			t.Errorf("accepted %s", invalid.Reason)
		}
	}
}

func TestBIP39PassphraseUsesNFKD(t *testing.T) {
	composed, err := DeriveAddress(MnemonicSource(testMnemonic, "caf\u00e9"), Options{Chain: "bitcoin"})
	if err != nil {
		t.Fatal(err)
	}
	decomposed, err := DeriveAddress(MnemonicSource(testMnemonic, "cafe\u0301"), Options{Chain: "bitcoin"})
	if err != nil {
		t.Fatal(err)
	}
	if composed.Address != decomposed.Address {
		t.Fatal("canonically equivalent passphrases derived different addresses")
	}
}

func TestMultiChainVectors(t *testing.T) {
	vectors := map[string]string{
		"litecoin":          "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez",
		"dogecoin":          "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC",
		"dash":              "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5",
		"digibyte":          "DG1KhhBKpsyWXTakHNezaDQ34focsXjN1i",
		"bitcoin-cash":      "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6",
		"zcash-transparent": "t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F",
		"ethereum":          "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
		"ethereum-classic":  "0xFA22515E43658ce56A7682B801e9B5456f511420",
		"tron":              "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
		"solana":            "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
	}
	for chainID, expected := range vectors {
		result, err := DeriveAddress(testSource, Options{Chain: chainID})
		if err != nil {
			t.Fatalf("%s: %v", chainID, err)
		}
		if result.Address != expected {
			t.Errorf("%s: got %s want %s", chainID, result.Address, expected)
		}
	}
}

func TestBIP86AndFailures(t *testing.T) {
	result, err := DeriveAddress(testSource, Options{ScriptType: "p2tr"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Address != "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr" {
		t.Fatalf("taproot mismatch: %s", result.Address)
	}
	if _, err := DeriveAddress(MnemonicSource("abandon abandon", ""), Options{}); err == nil {
		t.Fatal("invalid mnemonic accepted")
	}
	if _, err := DeriveNode(SeedSource([]byte("short")), "", ""); err == nil {
		t.Fatal("invalid seed accepted")
	}
	if len(SupportedChains()) != 18 {
		t.Fatal("chain registry mismatch")
	}
}

func TestCompletePublicContractAndErrorBoundaries(t *testing.T) {
	seed := make([]byte, 16)
	for index := range seed {
		seed[index] = byte(index)
	}
	if node, err := DeriveNode(SeedSource(seed), "secp256k1", "m/0h/1H/2'"); err != nil || node.Depth != 3 {
		t.Fatalf("secp256k1 node: %#v %v", node, err)
	}
	if node, err := DeriveNode(testSource, "ed25519", "m/0h"); err != nil || node.Depth != 1 {
		t.Fatalf("ed25519 node: %#v %v", node, err)
	}
	if secret, err := DeriveAccountPrivateKey(testSource, Options{Chain: "solana"}); err != nil || secret.ExtendedPrivateKey != nil {
		t.Fatalf("Solana private result: %#v %v", secret, err)
	}
	if _, err := DeriveAccountPublicKey(testSource, Options{Chain: "solana"}); err == nil {
		t.Fatal("Solana xpub was accepted")
	}

	addresses := []Options{
		{Chain: "bitcoin", Format: "xpub", ScriptType: "p2pkh"},
		{Chain: "bitcoin", Format: "ypub", ScriptType: "p2sh-p2wpkh"},
		{Chain: "bitcoin", Format: "zpub", ScriptType: "p2wpkh"},
		{Chain: "bitcoin", ScriptType: "p2tr"},
		{Chain: "bitcoin-cash", ScriptType: "cashaddr"},
		{Chain: "ethereum", ScriptType: "evm"},
		{Chain: "tron", ScriptType: "tron"},
	}
	for _, options := range addresses {
		if value, err := DeriveAddress(testSource, options); err != nil || value.Address == "" {
			t.Fatalf("address options %#v: %#v %v", options, value, err)
		}
	}
	if batch, err := DeriveAddresses(testSource, Options{Chain: "ethereum"}, 3, 4); err != nil || len(batch) != 4 || batch[0].Index != 3 {
		t.Fatalf("batch: %#v %v", batch, err)
	}

	account, err := DeriveAccountPublicKey(testSource, Options{Format: "ypub"})
	if err != nil {
		t.Fatal(err)
	}
	parsedPublic, err := ParseExtendedKey(account.ExtendedPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if converted, err := SerializeExtendedKey(parsedPublic, false, "xpub"); err != nil || converted[:4] != "xpub" {
		t.Fatalf("public conversion: %s %v", converted, err)
	}
	if _, err := SerializeExtendedKey(parsedPublic, true, ""); err == nil {
		t.Fatal("private serialization from xpub was accepted")
	}

	secret, err := DeriveAccountPrivateKey(testSource, Options{Format: "xpub"})
	if err != nil {
		t.Fatal(err)
	}
	parsedPrivate, err := ParseExtendedKey(*secret.ExtendedPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if public, err := SerializeExtendedKey(parsedPrivate, false, "xpub"); err != nil || public[:4] != "xpub" {
		t.Fatalf("neuter serialization: %s %v", public, err)
	}

	failures := []func() error{
		func() error { _, err := DeriveNode(testSource, "p256", "m"); return err },
		func() error { _, err := DeriveNode(testSource, "secp256k1", "relative/0"); return err },
		func() error { _, err := DeriveNode(testSource, "ed25519", "m/0"); return err },
		func() error { _, err := DeriveAddress(testSource, Options{Chain: "unknown"}); return err },
		func() error {
			_, err := DeriveAddress(testSource, Options{Chain: "bitcoin", Format: "tpub"})
			return err
		},
		func() error {
			_, err := DeriveAddress(testSource, Options{Chain: "dogecoin", ScriptType: "p2wpkh"})
			return err
		},
		func() error {
			_, err := DeriveAddress(testSource, Options{Chain: "bitcoin", ScriptType: "unknown"})
			return err
		},
		func() error { _, err := DeriveAddresses(testSource, Options{}, 0, 0); return err },
		func() error { _, err := DeriveAddresses(testSource, Options{}, HardenedOffset-1, 2); return err },
		func() error { _, err := ParseExtendedKey("not-base58!"); return err },
		func() error { _, err := SerializeExtendedKey(parsedPublic, false, "unknown"); return err },
		func() error {
			_, err := DeriveAddressFromExtendedPublicKey(*secret.ExtendedPrivateKey, "bitcoin", 0, 0, "")
			return err
		},
		func() error {
			_, err := DeriveAddressFromExtendedPublicKey(account.ExtendedPublicKey, "solana", 0, 0, "")
			return err
		},
		func() error {
			_, err := DeriveAddressFromExtendedPublicKey(account.ExtendedPublicKey, "bitcoin", HardenedOffset, 0, "")
			return err
		},
	}
	for index, operation := range failures {
		if err := operation(); err == nil {
			t.Errorf("failure case %d was accepted", index)
		}
	}

	decoded := base58DecodeForTest(account.ExtendedPublicKey)
	binary.BigEndian.PutUint32(decoded[:4], 0xdeadbeef)
	if _, err := ParseExtendedKey(base58Check(decoded)); err == nil {
		t.Fatal("unknown extended key version accepted")
	}
	if _, err := parsePath("m/00", false); err == nil {
		t.Fatal("ambiguous path accepted")
	}
}

func base58DecodeForTest(value string) []byte {
	decoded := base58.Decode(value)
	return append([]byte(nil), decoded[:78]...)
}

func FuzzDerivationPath(f *testing.F) {
	for _, value := range []string{"m", "m/0", "m/0'", "m/00", "m/-1", "m//0"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = parsePath(value, false)
		_, _ = parsePath(value, true)
	})
}

func FuzzExtendedKeyParser(f *testing.F) {
	account, _ := DeriveAccountPublicKey(testSource, Options{})
	f.Add(account.ExtendedPublicKey)
	f.Add("not-a-key")
	f.Fuzz(func(t *testing.T, value string) { _, _ = ParseExtendedKey(value) })
}
