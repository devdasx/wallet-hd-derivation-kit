// Package wallethd derives standards-compliant HD-wallet keys and addresses.
//
// It is offline-only: no API in this package performs network I/O. Private
// material is available only through explicitly named private-key functions.
package wallethd

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/crypto/ripemd160"
	bip39 "github.com/devdasx/bip39-mnemonic-kit/v2/go/bip39"
	keccak "github.com/filecoin-project/go-keccak"
	"github.com/mr-tron/base58/base58"
	"golang.org/x/text/unicode/norm"
)

const (
	APISchemaVersion = 1
	HardenedOffset   = uint32(0x80000000)
)

var (
	ErrInvalidMnemonic = errors.New("invalid BIP39 English mnemonic")
	ErrInvalidSeed     = errors.New("seed must be between 16 and 64 bytes")
	ErrHardenedPublic  = errors.New("extended public keys can derive only non-hardened children")
	ErrInvalidKey      = errors.New("invalid BIP32 key material")
	ErrInvalidExtended = errors.New("invalid extended key")
)

// Source holds exactly one validated BIP39 mnemonic or a 16-64 byte seed.
type Source struct {
	Mnemonic   string
	Passphrase string
	Seed       []byte
}

func MnemonicSource(words, passphrase string) Source {
	return Source{Mnemonic: words, Passphrase: passphrase}
}

func SeedSource(seed []byte) Source {
	return Source{Seed: append([]byte(nil), seed...)}
}

func (s Source) seedBytes() ([]byte, error) {
	if s.Mnemonic != "" {
		words := norm.NFKD.String(strings.Join(strings.Fields(s.Mnemonic), " "))
		if !bip39.Validate(words) {
			return nil, ErrInvalidMnemonic
		}
		seed, err := bip39.Seed(words, norm.NFKD.String(s.Passphrase))
		if err != nil {
			return nil, ErrInvalidMnemonic
		}
		return seed, nil
	}
	if len(s.Seed) < 16 || len(s.Seed) > 64 {
		return nil, ErrInvalidSeed
	}
	return append([]byte(nil), s.Seed...), nil
}

type Format struct {
	Name, ScriptType              string
	PublicVersion, PrivateVersion uint32
	Purpose                       uint32
}

var formats = map[string]Format{
	"xpub": {"xpub", "p2pkh", 0x0488b21e, 0x0488ade4, 44},
	"ypub": {"ypub", "p2sh-p2wpkh", 0x049d7cb2, 0x049d7878, 49},
	"zpub": {"zpub", "p2wpkh", 0x04b24746, 0x04b2430c, 84},
	"tpub": {"tpub", "p2pkh", 0x043587cf, 0x04358394, 44},
	"upub": {"upub", "p2sh-p2wpkh", 0x044a5262, 0x044a4e28, 49},
	"vpub": {"vpub", "p2wpkh", 0x045f1cf6, 0x045f18bc, 84},
	"Ltub": {"Ltub", "p2pkh", 0x019da462, 0x019d9cfe, 44},
	"Mtub": {"Mtub", "p2sh-p2wpkh", 0x01b26ef6, 0x01b26792, 49},
}

type Chain struct {
	ID, Name, Symbol, Curve, DefaultFormat, DefaultScriptType string
	CoinType                                                  uint32
	P2PKH, P2SH                                               []byte
	HRP                                                       string
}

var chainList = []Chain{
	{"bitcoin", "Bitcoin", "BTC", "secp256k1", "zpub", "p2wpkh", 0, []byte{0x00}, []byte{0x05}, "bc"},
	{"bitcoin-testnet", "Bitcoin Testnet", "TBTC", "secp256k1", "vpub", "p2wpkh", 1, []byte{0x6f}, []byte{0xc4}, "tb"},
	{"litecoin", "Litecoin", "LTC", "secp256k1", "Ltub", "p2pkh", 2, []byte{0x30}, []byte{0x32}, "ltc"},
	{"dogecoin", "Dogecoin", "DOGE", "secp256k1", "xpub", "p2pkh", 3, []byte{0x1e}, []byte{0x16}, ""},
	{"dash", "Dash", "DASH", "secp256k1", "xpub", "p2pkh", 5, []byte{0x4c}, []byte{0x10}, ""},
	{"digibyte", "DigiByte", "DGB", "secp256k1", "xpub", "p2pkh", 20, []byte{0x1e}, []byte{0x3f}, "dgb"},
	{"bitcoin-cash", "Bitcoin Cash", "BCH", "secp256k1", "xpub", "cashaddr", 145, []byte{0x00}, []byte{0x05}, ""},
	{"zcash-transparent", "Zcash Transparent", "ZEC", "secp256k1", "xpub", "p2pkh", 133, []byte{0x1c, 0xb8}, []byte{0x1c, 0xbd}, ""},
	{"ethereum", "Ethereum", "ETH", "secp256k1", "", "evm", 60, nil, nil, ""},
	{"ethereum-classic", "Ethereum Classic", "ETC", "secp256k1", "", "evm", 61, nil, nil, ""},
	{"polygon", "Polygon", "POL", "secp256k1", "", "evm", 60, nil, nil, ""},
	{"bsc", "BNB Smart Chain", "BNB", "secp256k1", "", "evm", 60, nil, nil, ""},
	{"avalanche-c", "Avalanche C-Chain", "AVAX", "secp256k1", "", "evm", 60, nil, nil, ""},
	{"arbitrum", "Arbitrum", "ARB", "secp256k1", "", "evm", 60, nil, nil, ""},
	{"optimism", "Optimism", "OP", "secp256k1", "", "evm", 60, nil, nil, ""},
	{"base", "Base", "ETH", "secp256k1", "", "evm", 60, nil, nil, ""},
	{"tron", "TRON", "TRX", "secp256k1", "", "tron", 195, nil, nil, ""},
	{"solana", "Solana", "SOL", "ed25519", "", "solana", 501, nil, nil, ""},
}

func SupportedChains() []Chain {
	return append([]Chain(nil), chainList...)
}

func chain(id string) (Chain, error) {
	if id == "" {
		id = "bitcoin"
	}
	for _, item := range chainList {
		if item.ID == id {
			return item, nil
		}
	}
	return Chain{}, fmt.Errorf("unsupported chain: %s", id)
}

type extendedPrivate struct {
	key, chainCode [32]byte
	depth          byte
	parent         [4]byte
	child          uint32
}

type extendedPublic struct {
	key       [33]byte
	chainCode [32]byte
	depth     byte
	parent    [4]byte
	child     uint32
}

func master(seed []byte) (*extendedPrivate, error) {
	if len(seed) < 16 || len(seed) > 64 {
		return nil, ErrInvalidSeed
	}
	material := append([]byte(nil), seed...)
	for {
		digest := hmac512([]byte("Bitcoin seed"), material)
		var scalar btcec.ModNScalar
		if !scalar.SetByteSlice(digest[:32]) && !scalar.IsZero() {
			n := &extendedPrivate{}
			copy(n.key[:], digest[:32])
			copy(n.chainCode[:], digest[32:])
			return n, nil
		}
		material = digest
	}
}

func (n *extendedPrivate) publicBytes() [33]byte {
	_, pub := btcec.PrivKeyFromBytes(n.key[:])
	var result [33]byte
	copy(result[:], pub.SerializeCompressed())
	return result
}

func fingerprint(public []byte) [4]byte {
	var result [4]byte
	copy(result[:], hash160(public)[:4])
	return result
}

func (n *extendedPrivate) derive(index uint32) (*extendedPrivate, error) {
	data := make([]byte, 0, 37)
	if index >= HardenedOffset {
		data = append(data, 0)
		data = append(data, n.key[:]...)
	} else {
		pub := n.publicBytes()
		data = append(data, pub[:]...)
	}
	data = binary.BigEndian.AppendUint32(data, index)
	digest := hmac512(n.chainCode[:], data)
	var tweak, parent, child btcec.ModNScalar
	if tweak.SetByteSlice(digest[:32]) || tweak.IsZero() {
		return nil, ErrInvalidKey
	}
	if parent.SetByteSlice(n.key[:]) || parent.IsZero() {
		return nil, ErrInvalidKey
	}
	child.Add2(&parent, &tweak)
	if child.IsZero() || n.depth == 255 {
		return nil, ErrInvalidKey
	}
	parentPublic := n.publicBytes()
	result := &extendedPrivate{depth: n.depth + 1, parent: fingerprint(parentPublic[:]), child: index}
	key := child.Bytes()
	copy(result.key[:], key[:])
	copy(result.chainCode[:], digest[32:])
	return result, nil
}

func (n *extendedPrivate) neuter() *extendedPublic {
	return &extendedPublic{key: n.publicBytes(), chainCode: n.chainCode, depth: n.depth, parent: n.parent, child: n.child}
}

func (n *extendedPublic) derive(index uint32) (*extendedPublic, error) {
	if index >= HardenedOffset {
		return nil, ErrHardenedPublic
	}
	data := binary.BigEndian.AppendUint32(append([]byte(nil), n.key[:]...), index)
	digest := hmac512(n.chainCode[:], data)
	var tweak btcec.ModNScalar
	if tweak.SetByteSlice(digest[:32]) || tweak.IsZero() {
		return nil, ErrInvalidKey
	}
	pub, err := btcec.ParsePubKey(n.key[:])
	if err != nil {
		return nil, ErrInvalidKey
	}
	var original, delta, sum btcec.JacobianPoint
	pub.AsJacobian(&original)
	btcec.ScalarBaseMultNonConst(&tweak, &delta)
	btcec.AddNonConst(&original, &delta, &sum)
	if sum.Z.IsZero() || n.depth == 255 {
		return nil, ErrInvalidKey
	}
	sum.ToAffine()
	serialized := btcec.NewPublicKey(&sum.X, &sum.Y).SerializeCompressed()
	result := &extendedPublic{depth: n.depth + 1, parent: fingerprint(n.key[:]), child: index}
	copy(result.key[:], serialized)
	copy(result.chainCode[:], digest[32:])
	return result, nil
}

func parsePath(path string, ed25519 bool) ([]uint32, error) {
	if path == "m" || path == "M" {
		return nil, nil
	}
	parts := strings.Split(path, "/")
	if len(parts) < 2 || len(parts) > 256 || (parts[0] != "m" && parts[0] != "M") {
		return nil, fmt.Errorf("invalid derivation path: %s", path)
	}
	result := make([]uint32, 0, len(parts)-1)
	for _, part := range parts[1:] {
		hardened := strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") || strings.HasSuffix(part, "H")
		if hardened {
			part = part[:len(part)-1]
		}
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return nil, fmt.Errorf("invalid derivation path: %s", path)
		}
		var value uint64
		for _, r := range part {
			if !unicode.IsDigit(r) || r > '9' {
				return nil, fmt.Errorf("invalid derivation path: %s", path)
			}
			value = value*10 + uint64(r-'0')
			if value >= uint64(HardenedOffset) {
				return nil, fmt.Errorf("invalid derivation path: %s", path)
			}
		}
		if ed25519 && !hardened {
			return nil, errors.New("SLIP-0010 Ed25519 supports hardened children only")
		}
		index := uint32(value)
		if hardened {
			index += HardenedOffset
		}
		result = append(result, index)
	}
	return result, nil
}

func derivePrivatePath(node *extendedPrivate, path string) (*extendedPrivate, error) {
	indexes, err := parsePath(path, false)
	if err != nil {
		return nil, err
	}
	for _, index := range indexes {
		node, err = node.derive(index)
		if err != nil {
			return nil, err
		}
	}
	return node, nil
}

type Options struct {
	Chain, Format, ScriptType, Path string
	Account, Change, Index          uint32
}

type NodeResult struct {
	SchemaVersion int    `json:"schemaVersion"`
	Curve         string `json:"curve"`
	Path          string `json:"path"`
	PublicKeyHex  string `json:"publicKeyHex"`
	ChainCodeHex  string `json:"chainCodeHex"`
	Depth         byte   `json:"depth"`
	ChildNumber   uint32 `json:"childNumber"`
}

type AccountPublicKey struct {
	SchemaVersion              int `json:"schemaVersion"`
	Chain, Curve, Path, Format string
	ExtendedPublicKey          string `json:"extendedPublicKey"`
	PublicKeyHex               string `json:"publicKeyHex"`
}

type AccountPrivateKey struct {
	SchemaVersion      int `json:"schemaVersion"`
	Chain, Curve, Path string
	Format             *string `json:"format"`
	ExtendedPrivateKey *string `json:"extendedPrivateKey"`
	PrivateKeyHex      string  `json:"privateKeyHex"`
	PublicKeyHex       string  `json:"publicKeyHex"`
}

type DerivedAddress struct {
	SchemaVersion int    `json:"schemaVersion"`
	Chain         string `json:"chain"`
	Curve         string `json:"curve"`
	Path          string `json:"path"`
	Account       uint32 `json:"account"`
	Change        uint32 `json:"change"`
	Index         uint32 `json:"index"`
	ScriptType    string `json:"scriptType"`
	Address       string `json:"address"`
	PublicKeyHex  string `json:"publicKeyHex"`
}

func DeriveNode(source Source, curve, path string) (NodeResult, error) {
	if curve == "" {
		curve = "secp256k1"
	}
	if path == "" {
		path = "m"
	}
	seed, err := source.seedBytes()
	if err != nil {
		return NodeResult{}, err
	}
	if curve == "ed25519" {
		node, err := slip10(seed, path)
		if err != nil {
			return NodeResult{}, err
		}
		return NodeResult{1, curve, path, hex.EncodeToString(node.public[:]), hex.EncodeToString(node.chainCode[:]), node.depth, node.child}, nil
	}
	if curve != "secp256k1" {
		return NodeResult{}, fmt.Errorf("unsupported curve: %s", curve)
	}
	node, err := master(seed)
	if err == nil {
		node, err = derivePrivatePath(node, path)
	}
	if err != nil {
		return NodeResult{}, err
	}
	pub := node.publicBytes()
	return NodeResult{1, curve, path, hex.EncodeToString(pub[:]), hex.EncodeToString(node.chainCode[:]), node.depth, node.child}, nil
}

func resolveFormat(c Chain, requested, script string) (Format, error) {
	name := requested
	if name == "" {
		if script == "p2tr" {
			name = "xpub"
		} else if c.DefaultFormat != "" {
			name = c.DefaultFormat
		} else {
			name = "xpub"
		}
	}
	f, ok := formats[name]
	if !ok {
		return Format{}, fmt.Errorf("unsupported extended-key format: %s", name)
	}
	allowed := map[string][]string{"bitcoin": {"xpub", "ypub", "zpub"}, "bitcoin-testnet": {"tpub", "upub", "vpub"}, "litecoin": {"Ltub", "Mtub"}}
	list := allowed[c.ID]
	if len(list) == 0 {
		list = []string{"xpub"}
	}
	for _, item := range list {
		if item == name {
			return f, nil
		}
	}
	return Format{}, fmt.Errorf("format %s is not registered for %s", name, c.ID)
}

func accountPath(c Chain, account uint32, script string, format Format) string {
	purpose := format.Purpose
	if script == "p2tr" {
		purpose = 86
	}
	return fmt.Sprintf("m/%d'/%d'/%d'", purpose, c.CoinType, account)
}

func DeriveAccountPublicKey(source Source, options Options) (AccountPublicKey, error) {
	c, err := chain(options.Chain)
	if err != nil {
		return AccountPublicKey{}, err
	}
	if c.Curve == "ed25519" {
		return AccountPublicKey{}, errors.New("Solana SLIP-0010 does not define extended public keys")
	}
	f, err := resolveFormat(c, options.Format, options.ScriptType)
	if err != nil {
		return AccountPublicKey{}, err
	}
	path := options.Path
	if path == "" {
		path = accountPath(c, options.Account, options.ScriptType, f)
	}
	seed, err := source.seedBytes()
	if err != nil {
		return AccountPublicKey{}, err
	}
	node, err := master(seed)
	if err == nil {
		node, err = derivePrivatePath(node, path)
	}
	if err != nil {
		return AccountPublicKey{}, err
	}
	pub := node.publicBytes()
	return AccountPublicKey{1, c.ID, c.Curve, path, f.Name, node.neuter().serialize(f.PublicVersion), hex.EncodeToString(pub[:])}, nil
}

func DeriveAccountPrivateKey(source Source, options Options) (AccountPrivateKey, error) {
	c, err := chain(options.Chain)
	if err != nil {
		return AccountPrivateKey{}, err
	}
	seed, err := source.seedBytes()
	if err != nil {
		return AccountPrivateKey{}, err
	}
	if c.Curve == "ed25519" {
		path := options.Path
		if path == "" {
			path = fmt.Sprintf("m/44'/%d'/%d'", c.CoinType, options.Account)
		}
		node, err := slip10(seed, path)
		if err != nil {
			return AccountPrivateKey{}, err
		}
		return AccountPrivateKey{1, c.ID, c.Curve, path, nil, nil, hex.EncodeToString(node.private[:]), hex.EncodeToString(node.public[:])}, nil
	}
	f, err := resolveFormat(c, options.Format, options.ScriptType)
	if err != nil {
		return AccountPrivateKey{}, err
	}
	path := options.Path
	if path == "" {
		path = accountPath(c, options.Account, options.ScriptType, f)
	}
	node, err := master(seed)
	if err == nil {
		node, err = derivePrivatePath(node, path)
	}
	if err != nil {
		return AccountPrivateKey{}, err
	}
	pub := node.publicBytes()
	private := node.serializePrivate(f.PrivateVersion)
	name := f.Name
	return AccountPrivateKey{1, c.ID, c.Curve, path, &name, &private, hex.EncodeToString(node.key[:]), hex.EncodeToString(pub[:])}, nil
}

func DeriveAddress(source Source, options Options) (DerivedAddress, error) {
	c, err := chain(options.Chain)
	if err != nil {
		return DerivedAddress{}, err
	}
	script := options.ScriptType
	if script == "" {
		script = c.DefaultScriptType
	}
	seed, err := source.seedBytes()
	if err != nil {
		return DerivedAddress{}, err
	}
	if c.Curve == "ed25519" {
		path := options.Path
		if path == "" {
			path = fmt.Sprintf("m/44'/%d'/%d'/%d'", c.CoinType, options.Account, options.Index)
		}
		node, err := slip10(seed, path)
		if err != nil {
			return DerivedAddress{}, err
		}
		return addressResult(c, options, path, script, base58.Encode(node.public[:]), node.public[:]), nil
	}
	f, err := resolveFormat(c, options.Format, script)
	if err != nil && c.DefaultFormat != "" {
		return DerivedAddress{}, err
	}
	if c.DefaultFormat == "" {
		f = formats["xpub"]
	}
	path := options.Path
	if path == "" {
		path = fmt.Sprintf("%s/%d/%d", accountPath(c, options.Account, script, f), options.Change, options.Index)
	}
	node, err := master(seed)
	if err == nil {
		node, err = derivePrivatePath(node, path)
	}
	if err != nil {
		return DerivedAddress{}, err
	}
	pub := node.publicBytes()
	address, err := publicKeyAddress(pub[:], c, script)
	if err != nil {
		return DerivedAddress{}, err
	}
	return addressResult(c, options, path, script, address, pub[:]), nil
}

func DeriveAddresses(source Source, options Options, start, count uint32) ([]DerivedAddress, error) {
	if count == 0 || count > 10000 || start > HardenedOffset-count {
		return nil, errors.New("count must be between 1 and 10000 and stay within the index range")
	}
	result := make([]DerivedAddress, 0, count)
	for offset := uint32(0); offset < count; offset++ {
		options.Index = start + offset
		item, err := DeriveAddress(source, options)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, nil
}

func addressResult(c Chain, options Options, path, script, address string, public []byte) DerivedAddress {
	return DerivedAddress{1, c.ID, c.Curve, path, options.Account, options.Change, options.Index, script, address, hex.EncodeToString(public)}
}

type ParsedExtendedKey struct {
	Value                string `json:"value"`
	VersionHex, Format   string
	IsPrivate            bool   `json:"isPrivate"`
	Depth                byte   `json:"depth"`
	ChildNumber          uint32 `json:"childNumber"`
	ParentFingerprintHex string `json:"parentFingerprintHex"`
	ChainCodeHex         string `json:"chainCodeHex"`
	PublicKeyHex         string `json:"publicKeyHex"`
	privateNode          *extendedPrivate
	publicNode           *extendedPublic
}

func ParseExtendedKey(value string) (ParsedExtendedKey, error) {
	decoded, err := base58.Decode(value)
	if err != nil || len(decoded) != 82 || !hmac.Equal(decoded[78:], doubleSHA(decoded[:78])[:4]) {
		return ParsedExtendedKey{}, ErrInvalidExtended
	}
	payload := decoded[:78]
	version := binary.BigEndian.Uint32(payload[:4])
	var f Format
	found := false
	isPrivate := payload[45] == 0
	for _, candidate := range formats {
		if (!isPrivate && candidate.PublicVersion == version) || (isPrivate && candidate.PrivateVersion == version) {
			f, found = candidate, true
			break
		}
	}
	if !found {
		return ParsedExtendedKey{}, ErrInvalidExtended
	}
	if payload[4] == 0 && (binary.BigEndian.Uint32(payload[5:9]) != 0 || binary.BigEndian.Uint32(payload[9:13]) != 0) {
		return ParsedExtendedKey{}, ErrInvalidExtended
	}
	parsed := ParsedExtendedKey{Value: value, VersionHex: fmt.Sprintf("%08x", version), Format: f.Name, IsPrivate: isPrivate, Depth: payload[4], ChildNumber: binary.BigEndian.Uint32(payload[9:13]), ParentFingerprintHex: hex.EncodeToString(payload[5:9]), ChainCodeHex: hex.EncodeToString(payload[13:45])}
	var parent [4]byte
	copy(parent[:], payload[5:9])
	var cc [32]byte
	copy(cc[:], payload[13:45])
	if isPrivate {
		if payload[45] != 0 {
			return ParsedExtendedKey{}, ErrInvalidExtended
		}
		n := &extendedPrivate{depth: payload[4], parent: parent, child: parsed.ChildNumber, chainCode: cc}
		copy(n.key[:], payload[46:78])
		var scalar btcec.ModNScalar
		if scalar.SetByteSlice(n.key[:]) || scalar.IsZero() {
			return ParsedExtendedKey{}, ErrInvalidExtended
		}
		parsed.privateNode = n
		pub := n.publicBytes()
		parsed.PublicKeyHex = hex.EncodeToString(pub[:])
	} else {
		if _, err := btcec.ParsePubKey(payload[45:78]); err != nil {
			return ParsedExtendedKey{}, ErrInvalidExtended
		}
		n := &extendedPublic{depth: payload[4], parent: parent, child: parsed.ChildNumber, chainCode: cc}
		copy(n.key[:], payload[45:78])
		parsed.publicNode = n
		parsed.PublicKeyHex = hex.EncodeToString(n.key[:])
	}
	return parsed, nil
}

func SerializeExtendedKey(parsed ParsedExtendedKey, private bool, formatName string) (string, error) {
	if formatName == "" {
		formatName = parsed.Format
	}
	f, ok := formats[formatName]
	if !ok {
		return "", fmt.Errorf("unsupported extended-key format: %s", formatName)
	}
	if private {
		if parsed.privateNode == nil {
			return "", errors.New("private material is not available from an extended public key")
		}
		return parsed.privateNode.serializePrivate(f.PrivateVersion), nil
	}
	if parsed.publicNode != nil {
		return parsed.publicNode.serialize(f.PublicVersion), nil
	}
	return parsed.privateNode.neuter().serialize(f.PublicVersion), nil
}

func DeriveAddressFromExtendedPublicKey(value, chainID string, change, index uint32, script string) (DerivedAddress, error) {
	c, err := chain(chainID)
	if err != nil {
		return DerivedAddress{}, err
	}
	if c.Curve != "secp256k1" {
		return DerivedAddress{}, errors.New("extended public derivation is available only for secp256k1 chains")
	}
	parsed, err := ParseExtendedKey(value)
	if err != nil || parsed.IsPrivate {
		return DerivedAddress{}, errors.New("use a valid extended public key")
	}
	node, err := parsed.publicNode.derive(change)
	if err == nil {
		node, err = node.derive(index)
	}
	if err != nil {
		return DerivedAddress{}, err
	}
	if script == "" {
		switch parsed.Format {
		case "ypub", "upub", "Mtub":
			script = "p2sh-p2wpkh"
		case "zpub", "vpub":
			script = "p2wpkh"
		default:
			script = c.DefaultScriptType
		}
	}
	address, err := publicKeyAddress(node.key[:], c, script)
	if err != nil {
		return DerivedAddress{}, err
	}
	return addressResult(c, Options{Change: change, Index: index}, fmt.Sprintf("%d/%d", change, index), script, address, node.key[:]), nil
}

func (n *extendedPrivate) serializePrivate(version uint32) string {
	key := make([]byte, 33)
	copy(key[1:], n.key[:])
	return serializeKey(version, n.depth, n.parent, n.child, n.chainCode, key)
}

func (n *extendedPublic) serialize(version uint32) string {
	return serializeKey(version, n.depth, n.parent, n.child, n.chainCode, n.key[:])
}

func serializeKey(version uint32, depth byte, parent [4]byte, child uint32, cc [32]byte, key []byte) string {
	payload := make([]byte, 0, 78)
	payload = binary.BigEndian.AppendUint32(payload, version)
	payload = append(payload, depth)
	payload = append(payload, parent[:]...)
	payload = binary.BigEndian.AppendUint32(payload, child)
	payload = append(payload, cc[:]...)
	payload = append(payload, key...)
	return base58Check(payload)
}

type slip10Node struct {
	private, chainCode, public [32]byte
	depth                      byte
	child                      uint32
}

func slip10(seed []byte, path string) (*slip10Node, error) {
	indexes, err := parsePath(path, true)
	if err != nil {
		return nil, err
	}
	digest := hmac512([]byte("ed25519 seed"), seed)
	node := &slip10Node{}
	copy(node.private[:], digest[:32])
	copy(node.chainCode[:], digest[32:])
	for _, index := range indexes {
		data := []byte{0}
		data = append(data, node.private[:]...)
		data = binary.BigEndian.AppendUint32(data, index)
		digest = hmac512(node.chainCode[:], data)
		copy(node.private[:], digest[:32])
		copy(node.chainCode[:], digest[32:])
		node.depth++
		node.child = index
	}
	key := ed25519.NewKeyFromSeed(node.private[:])
	copy(node.public[:], key[32:])
	return node, nil
}

func publicKeyAddress(public []byte, c Chain, script string) (string, error) {
	switch script {
	case "p2pkh":
		return base58Check(append(append([]byte(nil), c.P2PKH...), hash160(public)...)), nil
	case "p2sh-p2wpkh":
		redeem := append([]byte{0, 20}, hash160(public)...)
		return base58Check(append(append([]byte(nil), c.P2SH...), hash160(redeem)...)), nil
	case "p2wpkh":
		if c.HRP == "" {
			return "", fmt.Errorf("native SegWit is not registered for %s", c.ID)
		}
		return segwitAddress(c.HRP, 0, hash160(public)), nil
	case "p2tr":
		if c.HRP == "" {
			return "", fmt.Errorf("Taproot is not registered for %s", c.ID)
		}
		output, err := taprootOutputKey(public)
		if err != nil {
			return "", err
		}
		return segwitAddress(c.HRP, 1, output), nil
	case "cashaddr":
		return cashAddress("bitcoincash", hash160(public)), nil
	case "evm":
		return evmAddress(public)
	case "tron":
		address, err := rawEVMAddress(public)
		if err != nil {
			return "", err
		}
		return base58Check(append([]byte{0x41}, address...)), nil
	default:
		return "", fmt.Errorf("unsupported script type: %s", script)
	}
}

func rawEVMAddress(public []byte) ([]byte, error) {
	pub, err := btcec.ParsePubKey(public)
	if err != nil {
		return nil, ErrInvalidKey
	}
	uncompressed := pub.SerializeUncompressed()
	hash := keccak.NewLegacyKeccak256()
	hash.Write(uncompressed[1:])
	return hash.Sum(nil)[12:], nil
}

func evmAddress(public []byte) (string, error) {
	raw, err := rawEVMAddress(public)
	if err != nil {
		return "", err
	}
	lower := hex.EncodeToString(raw)
	hash := keccak.NewLegacyKeccak256()
	hash.Write([]byte(lower))
	checksum := hex.EncodeToString(hash.Sum(nil))
	result := []byte("0x" + lower)
	for i := 0; i < len(lower); i++ {
		if lower[i] >= 'a' && lower[i] <= 'f' && checksum[i] >= '8' {
			result[i+2] -= 32
		}
	}
	return string(result), nil
}

func taprootOutputKey(public []byte) ([]byte, error) {
	if len(public) != 33 {
		return nil, ErrInvalidKey
	}
	even := append([]byte{2}, public[1:]...)
	pub, err := btcec.ParsePubKey(even)
	if err != nil {
		return nil, ErrInvalidKey
	}
	tweakBytes := taggedHash("TapTweak", public[1:])
	var tweak btcec.ModNScalar
	if tweak.SetByteSlice(tweakBytes) {
		return nil, ErrInvalidKey
	}
	var original, delta, sum btcec.JacobianPoint
	pub.AsJacobian(&original)
	btcec.ScalarBaseMultNonConst(&tweak, &delta)
	btcec.AddNonConst(&original, &delta, &sum)
	if sum.Z.IsZero() {
		return nil, ErrInvalidKey
	}
	sum.ToAffine()
	compressed := btcec.NewPublicKey(&sum.X, &sum.Y).SerializeCompressed()
	return compressed[1:], nil
}

func hmac512(key, data []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	return ripemd.Sum(nil)
}

func doubleSHA(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

func base58Check(payload []byte) string {
	return base58.Encode(append(append([]byte(nil), payload...), doubleSHA(payload)[:4]...))
}

func taggedHash(tag string, message []byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(message)
	return h.Sum(nil)
}

const bech32Alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func segwitAddress(hrp string, version byte, program []byte) string {
	words := []byte{version}
	words = append(words, convertBits(program, 8, 5, true)...)
	constant := uint32(1)
	if version != 0 {
		constant = 0x2bc830a3
	}
	return bech32Encode(hrp, words, constant)
}

func bech32Encode(hrp string, words []byte, constant uint32) string {
	values := make([]byte, 0, len(hrp)*2+1+len(words)+6)
	for _, c := range []byte(hrp) {
		values = append(values, c>>5)
	}
	values = append(values, 0)
	for _, c := range []byte(hrp) {
		values = append(values, c&31)
	}
	values = append(values, words...)
	values = append(values, make([]byte, 6)...)
	polymod := bech32Polymod(values) ^ constant
	result := hrp + "1"
	for _, word := range words {
		result += string(bech32Alphabet[word])
	}
	for i := 0; i < 6; i++ {
		value := byte((polymod >> uint(5*(5-i))) & 31)
		result += string(bech32Alphabet[value])
	}
	return result
}

func bech32Polymod(values []byte) uint32 {
	generators := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	checksum := uint32(1)
	for _, value := range values {
		top := checksum >> 25
		checksum = (checksum&0x1ffffff)<<5 ^ uint32(value)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 != 0 {
				checksum ^= generators[i]
			}
		}
	}
	return checksum
}

func convertBits(data []byte, from, to uint, pad bool) []byte {
	var accumulator uint32
	var bits uint
	maxValue := uint32((1 << to) - 1)
	result := make([]byte, 0, (len(data)*int(from)+int(to)-1)/int(to))
	for _, value := range data {
		accumulator = (accumulator << from) | uint32(value)
		bits += from
		for bits >= to {
			bits -= to
			result = append(result, byte((accumulator>>bits)&maxValue))
		}
	}
	if pad && bits > 0 {
		result = append(result, byte((accumulator<<(to-bits))&maxValue))
	}
	return result
}

func cashAddress(prefix string, hash []byte) string {
	data := convertBits(append([]byte{0}, hash...), 8, 5, true)
	values := make([]byte, 0, len(prefix)+1+len(data)+8)
	for _, c := range []byte(prefix) {
		values = append(values, c&31)
	}
	values = append(values, 0)
	values = append(values, data...)
	values = append(values, make([]byte, 8)...)
	polymod := cashPolymod(values) ^ 1
	result := prefix + ":"
	for _, value := range data {
		result += string(bech32Alphabet[value])
	}
	for i := 0; i < 8; i++ {
		result += string(bech32Alphabet[(polymod>>uint(5*(7-i)))&31])
	}
	return result
}

func cashPolymod(values []byte) uint64 {
	generators := [5]uint64{0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470}
	checksum := uint64(1)
	for _, value := range values {
		top := checksum >> 35
		checksum = (checksum&0x07ffffffff)<<5 ^ uint64(value)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 != 0 {
				checksum ^= generators[i]
			}
		}
	}
	return checksum
}

// compile-time guard for accidental removal of big integer support used by
// Base58's maintained dependency on platforms without assembly acceleration.
var _ = big.NewInt
