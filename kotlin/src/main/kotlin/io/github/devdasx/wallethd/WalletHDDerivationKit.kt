package io.github.devdasx.wallethd

import org.bitcoinj.crypto.MnemonicCode
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.digests.KeccakDigest
import org.bouncycastle.crypto.digests.RIPEMD160Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.math.BigInteger
import java.text.Normalizer

const val API_SCHEMA_VERSION: Int = 1
const val HARDENED_OFFSET: Long = 0x80000000L

class WalletHDDerivationException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

sealed interface Source {
    data class Mnemonic(val words: String, val passphrase: String = "") : Source
    data class Seed(val bytes: ByteArray) : Source {
        override fun equals(other: Any?): Boolean = other is Seed && bytes.contentEquals(other.bytes)
        override fun hashCode(): Int = bytes.contentHashCode()
    }
}

data class DeriveOptions(
    val chain: String = "bitcoin",
    val format: String? = null,
    val scriptType: String? = null,
    val path: String? = null,
    val account: Int = 0,
    val change: Int = 0,
    val index: Int = 0,
)

data class NodeResult(
    val schemaVersion: Int,
    val curve: String,
    val path: String,
    val publicKeyHex: String,
    val chainCodeHex: String,
    val depth: Int,
    val childNumber: Long,
)

data class AccountPublicKey(
    val schemaVersion: Int,
    val chain: String,
    val curve: String,
    val path: String,
    val format: String,
    val extendedPublicKey: String,
    val publicKeyHex: String,
)

data class AccountPrivateKey(
    val schemaVersion: Int,
    val chain: String,
    val curve: String,
    val path: String,
    val format: String?,
    val extendedPrivateKey: String?,
    val privateKeyHex: String,
    val publicKeyHex: String,
)

data class DerivedAddress(
    val schemaVersion: Int,
    val chain: String,
    val curve: String,
    val path: String,
    val account: Int,
    val change: Int,
    val index: Int,
    val scriptType: String,
    val address: String,
    val publicKeyHex: String,
)

data class ChainInfo(
    val id: String,
    val name: String,
    val symbol: String,
    val coinType: Int,
    val curve: String,
    val defaultFormat: String?,
    val defaultScriptType: String,
    val p2pkh: ByteArray = byteArrayOf(),
    val p2sh: ByteArray = byteArrayOf(),
    val hrp: String? = null,
) {
    override fun equals(other: Any?): Boolean =
        other is ChainInfo && id == other.id && p2pkh.contentEquals(other.p2pkh) && p2sh.contentEquals(other.p2sh)

    override fun hashCode(): Int = 31 * id.hashCode() + p2pkh.contentHashCode()
}

private data class Format(
    val name: String,
    val publicVersion: Long,
    val privateVersion: Long,
    val purpose: Int,
    val scriptType: String,
)

private val formats = mapOf(
    "xpub" to Format("xpub", 0x0488b21e, 0x0488ade4, 44, "p2pkh"),
    "ypub" to Format("ypub", 0x049d7cb2, 0x049d7878, 49, "p2sh-p2wpkh"),
    "zpub" to Format("zpub", 0x04b24746, 0x04b2430c, 84, "p2wpkh"),
    "tpub" to Format("tpub", 0x043587cf, 0x04358394, 44, "p2pkh"),
    "upub" to Format("upub", 0x044a5262, 0x044a4e28, 49, "p2sh-p2wpkh"),
    "vpub" to Format("vpub", 0x045f1cf6, 0x045f18bc, 84, "p2wpkh"),
    "Ltub" to Format("Ltub", 0x019da462, 0x019d9cfe, 44, "p2pkh"),
    "Mtub" to Format("Mtub", 0x01b26ef6, 0x01b26792, 49, "p2sh-p2wpkh"),
)

private val chains = listOf(
    ChainInfo("bitcoin", "Bitcoin", "BTC", 0, "secp256k1", "zpub", "p2wpkh", byteArrayOf(0), byteArrayOf(5), "bc"),
    ChainInfo("bitcoin-testnet", "Bitcoin Testnet", "TBTC", 1, "secp256k1", "vpub", "p2wpkh", byteArrayOf(0x6f), byteArrayOf(0xc4.toByte()), "tb"),
    ChainInfo("litecoin", "Litecoin", "LTC", 2, "secp256k1", "Ltub", "p2pkh", byteArrayOf(0x30), byteArrayOf(0x32), "ltc"),
    ChainInfo("dogecoin", "Dogecoin", "DOGE", 3, "secp256k1", "xpub", "p2pkh", byteArrayOf(0x1e), byteArrayOf(0x16)),
    ChainInfo("dash", "Dash", "DASH", 5, "secp256k1", "xpub", "p2pkh", byteArrayOf(0x4c), byteArrayOf(0x10)),
    ChainInfo("digibyte", "DigiByte", "DGB", 20, "secp256k1", "xpub", "p2pkh", byteArrayOf(0x1e), byteArrayOf(0x3f), "dgb"),
    ChainInfo("bitcoin-cash", "Bitcoin Cash", "BCH", 145, "secp256k1", "xpub", "cashaddr", byteArrayOf(0), byteArrayOf(5)),
    ChainInfo("zcash-transparent", "Zcash Transparent", "ZEC", 133, "secp256k1", "xpub", "p2pkh", byteArrayOf(0x1c, 0xb8.toByte()), byteArrayOf(0x1c, 0xbd.toByte())),
    ChainInfo("ethereum", "Ethereum", "ETH", 60, "secp256k1", null, "evm"),
    ChainInfo("ethereum-classic", "Ethereum Classic", "ETC", 61, "secp256k1", null, "evm"),
    ChainInfo("polygon", "Polygon", "POL", 60, "secp256k1", null, "evm"),
    ChainInfo("bsc", "BNB Smart Chain", "BNB", 60, "secp256k1", null, "evm"),
    ChainInfo("avalanche-c", "Avalanche C-Chain", "AVAX", 60, "secp256k1", null, "evm"),
    ChainInfo("arbitrum", "Arbitrum", "ARB", 60, "secp256k1", null, "evm"),
    ChainInfo("optimism", "Optimism", "OP", 60, "secp256k1", null, "evm"),
    ChainInfo("base", "Base", "ETH", 60, "secp256k1", null, "evm"),
    ChainInfo("tron", "TRON", "TRX", 195, "secp256k1", null, "tron"),
    ChainInfo("solana", "Solana", "SOL", 501, "ed25519", null, "solana"),
)

fun supportedChains(): List<ChainInfo> = chains.toList()

private fun requireChain(id: String): ChainInfo =
    chains.firstOrNull { it.id == id } ?: throw WalletHDDerivationException("unsupported chain: $id")

private val curve = SECNamedCurves.getByName("secp256k1")
private val curveOrder: BigInteger = curve.n

internal data class ExtendedPrivate(
    val privateKey: ByteArray,
    val chainCode: ByteArray,
    val depth: Int = 0,
    val parentFingerprint: ByteArray = byteArrayOf(0, 0, 0, 0),
    val childNumber: Long = 0,
) {
    fun publicKey(): ByteArray = curve.g.multiply(BigInteger(1, privateKey)).normalize().getEncoded(true)

    fun derive(index: Long): ExtendedPrivate {
        require(index in 0..0xffffffffL) { "child index is out of range" }
        val data = if (index >= HARDENED_OFFSET) {
            byteArrayOf(0) + privateKey + uint32(index)
        } else {
            publicKey() + uint32(index)
        }
        val digest = hmacSha512(chainCode, data)
        val tweak = BigInteger(1, digest.copyOfRange(0, 32))
        if (tweak == BigInteger.ZERO || tweak >= curveOrder) throw WalletHDDerivationException("invalid BIP32 child tweak")
        val child = (BigInteger(1, privateKey) + tweak).mod(curveOrder)
        if (child == BigInteger.ZERO || depth == 255) throw WalletHDDerivationException("invalid BIP32 child key")
        return ExtendedPrivate(
            privateKey = child.toFixedBytes(32),
            chainCode = digest.copyOfRange(32, 64),
            depth = depth + 1,
            parentFingerprint = hash160(publicKey()).copyOfRange(0, 4),
            childNumber = index,
        )
    }

    fun derivePath(path: String): ExtendedPrivate =
        parsePath(path).fold(this) { node, index -> node.derive(index) }

    fun neuter(): ExtendedPublic = ExtendedPublic(publicKey(), chainCode, depth, parentFingerprint, childNumber)

    fun serializePrivate(version: Long): String =
        serializeKey(version, depth, parentFingerprint, childNumber, chainCode, byteArrayOf(0) + privateKey)
}

internal data class ExtendedPublic(
    val publicKey: ByteArray,
    val chainCode: ByteArray,
    val depth: Int,
    val parentFingerprint: ByteArray,
    val childNumber: Long,
) {
    fun derive(index: Long): ExtendedPublic {
        if (index >= HARDENED_OFFSET) throw WalletHDDerivationException("extended public keys cannot derive hardened children")
        val digest = hmacSha512(chainCode, publicKey + uint32(index))
        val tweak = BigInteger(1, digest.copyOfRange(0, 32))
        if (tweak == BigInteger.ZERO || tweak >= curveOrder) throw WalletHDDerivationException("invalid BIP32 child tweak")
        val point = curve.curve.decodePoint(publicKey).add(curve.g.multiply(tweak)).normalize()
        if (point.isInfinity || depth == 255) throw WalletHDDerivationException("invalid BIP32 child key")
        return ExtendedPublic(
            point.getEncoded(true),
            digest.copyOfRange(32, 64),
            depth + 1,
            hash160(publicKey).copyOfRange(0, 4),
            index,
        )
    }

    fun serialize(version: Long): String =
        serializeKey(version, depth, parentFingerprint, childNumber, chainCode, publicKey)
}

private fun master(seed: ByteArray): ExtendedPrivate {
    if (seed.size !in 16..64) throw WalletHDDerivationException("seed must be between 16 and 64 bytes")
    var material = seed
    while (true) {
        val digest = hmacSha512("Bitcoin seed".toByteArray(), material)
        val key = BigInteger(1, digest.copyOfRange(0, 32))
        if (key > BigInteger.ZERO && key < curveOrder) {
            return ExtendedPrivate(digest.copyOfRange(0, 32), digest.copyOfRange(32, 64))
        }
        material = digest
    }
}

private fun sourceSeed(source: Source): ByteArray = when (source) {
    is Source.Seed -> source.bytes.copyOf().also {
        if (it.size !in 16..64) throw WalletHDDerivationException("seed must be between 16 and 64 bytes")
    }
    is Source.Mnemonic -> try {
        val normalized = Normalizer.normalize(source.words.trim().split(Regex("\\s+")).joinToString(" "), Normalizer.Form.NFKD)
        val words = normalized.split(" ")
        MnemonicCode.INSTANCE.check(words)
        MnemonicCode.toSeed(words, Normalizer.normalize(source.passphrase, Normalizer.Form.NFKD))
    } catch (error: Exception) {
        throw WalletHDDerivationException("invalid BIP39 English mnemonic", error)
    }
}

private fun parsePath(path: String, ed25519: Boolean = false): List<Long> {
    if (path == "m" || path == "M") return emptyList()
    val parts = path.split('/')
    if (parts.size !in 2..256 || parts.first() !in setOf("m", "M")) {
        throw WalletHDDerivationException("path must be absolute and start with m")
    }
    return parts.drop(1).map { original ->
        val hardened = original.endsWith("'") || original.endsWith("h") || original.endsWith("H")
        val digits = if (hardened) original.dropLast(1) else original
        if (!digits.matches(Regex("0|[1-9][0-9]*"))) throw WalletHDDerivationException("invalid path component: $original")
        val value = digits.toLongOrNull() ?: throw WalletHDDerivationException("invalid path component: $original")
        if (value !in 0 until HARDENED_OFFSET) throw WalletHDDerivationException("path index is out of range")
        if (ed25519 && !hardened) throw WalletHDDerivationException("SLIP-0010 Ed25519 supports hardened children only")
        if (hardened) value + HARDENED_OFFSET else value
    }
}

private fun resolveFormat(chain: ChainInfo, requested: String?, script: String?): Format {
    val name = requested ?: if (script == "p2tr") "xpub" else chain.defaultFormat ?: "xpub"
    val format = formats[name] ?: throw WalletHDDerivationException("unsupported extended-key format: $name")
    val allowed = when (chain.id) {
        "bitcoin" -> setOf("xpub", "ypub", "zpub")
        "bitcoin-testnet" -> setOf("tpub", "upub", "vpub")
        "litecoin" -> setOf("Ltub", "Mtub")
        else -> setOf("xpub")
    }
    if (name !in allowed) throw WalletHDDerivationException("format $name is not registered for ${chain.id}")
    return format
}

private fun accountPath(chain: ChainInfo, account: Int, script: String?, format: Format): String {
    validateIndex(account, "account")
    val purpose = if (script == "p2tr") 86 else format.purpose
    return "m/$purpose'/${chain.coinType}'/$account'"
}

private fun validateIndex(value: Int, name: String): Int {
    if (value < 0) throw WalletHDDerivationException("$name must be between 0 and 2147483647")
    return value
}

fun deriveNode(source: Source, curveName: String = "secp256k1", path: String = "m"): NodeResult {
    val seed = sourceSeed(source)
    if (curveName == "ed25519") {
        val node = slip10(seed, path)
        return NodeResult(1, curveName, path, node.publicKey.hex(), node.chainCode.hex(), node.depth, node.childNumber)
    }
    if (curveName != "secp256k1") throw WalletHDDerivationException("unsupported curve: $curveName")
    val node = master(seed).derivePath(normalizePath(path))
    return NodeResult(1, curveName, path, node.publicKey().hex(), node.chainCode.hex(), node.depth, node.childNumber)
}

fun deriveAccountPublicKey(source: Source, options: DeriveOptions = DeriveOptions()): AccountPublicKey {
    val chain = requireChain(options.chain)
    if (chain.curve == "ed25519") throw WalletHDDerivationException("Solana SLIP-0010 does not define extended public keys")
    val format = resolveFormat(chain, options.format, options.scriptType)
    val path = normalizePath(options.path ?: accountPath(chain, options.account, options.scriptType, format))
    val node = master(sourceSeed(source)).derivePath(path)
    val public = node.publicKey()
    return AccountPublicKey(1, chain.id, chain.curve, path, format.name, node.neuter().serialize(format.publicVersion), public.hex())
}

fun deriveAccountPrivateKey(source: Source, options: DeriveOptions = DeriveOptions()): AccountPrivateKey {
    val chain = requireChain(options.chain)
    if (chain.curve == "ed25519") {
        val path = normalizePath(options.path ?: "m/44'/${chain.coinType}'/${options.account}'", true)
        val node = slip10(sourceSeed(source), path)
        return AccountPrivateKey(1, chain.id, chain.curve, path, null, null, node.privateKey.hex(), node.publicKey.hex())
    }
    val format = resolveFormat(chain, options.format, options.scriptType)
    val path = normalizePath(options.path ?: accountPath(chain, options.account, options.scriptType, format))
    val node = master(sourceSeed(source)).derivePath(path)
    return AccountPrivateKey(1, chain.id, chain.curve, path, format.name, node.serializePrivate(format.privateVersion), node.privateKey.hex(), node.publicKey().hex())
}

fun deriveAddress(source: Source, options: DeriveOptions = DeriveOptions()): DerivedAddress {
    val chain = requireChain(options.chain)
    validateIndex(options.account, "account")
    validateIndex(options.change, "change")
    validateIndex(options.index, "index")
    val script = options.scriptType ?: chain.defaultScriptType
    if (chain.curve == "ed25519") {
        val path = normalizePath(options.path ?: "m/44'/${chain.coinType}'/${options.account}'/${options.index}'", true)
        val node = slip10(sourceSeed(source), path)
        return addressResult(chain, options, path, script, base58Encode(node.publicKey), node.publicKey)
    }
    val format = resolveFormat(chain, options.format, script)
    val path = normalizePath(options.path ?: "${accountPath(chain, options.account, script, format)}/${options.change}/${options.index}")
    val node = master(sourceSeed(source)).derivePath(path)
    val public = node.publicKey()
    return addressResult(chain, options, path, script, publicKeyAddress(public, chain, script), public)
}

fun deriveAddresses(source: Source, options: DeriveOptions = DeriveOptions(), start: Int = 0, count: Int = 20): List<DerivedAddress> {
    validateIndex(start, "start")
    if (count !in 1..10_000 || start.toLong() + count > HARDENED_OFFSET) {
        throw WalletHDDerivationException("count must be between 1 and 10000 and stay within the index range")
    }
    return (start until start + count).map { deriveAddress(source, options.copy(index = it)) }
}

private fun addressResult(chain: ChainInfo, options: DeriveOptions, path: String, script: String, address: String, public: ByteArray) =
    DerivedAddress(1, chain.id, chain.curve, path, options.account, options.change, options.index, script, address, public.hex())

class ParsedExtendedKey internal constructor(
    val value: String,
    val versionHex: String,
    val format: String,
    val isPrivate: Boolean,
    val depth: Int,
    val childNumber: Long,
    val parentFingerprintHex: String,
    val chainCodeHex: String,
    val publicKeyHex: String,
    internal val privateNode: ExtendedPrivate?,
    internal val publicNode: ExtendedPublic?,
)

fun parseExtendedKey(value: String): ParsedExtendedKey {
    val decoded = try { base58Decode(value) } catch (error: Exception) {
        throw WalletHDDerivationException("invalid extended key", error)
    }
    if (decoded.size != 82 || !decoded.copyOfRange(78, 82).contentEquals(doubleSha256(decoded.copyOfRange(0, 78)).copyOfRange(0, 4))) {
        throw WalletHDDerivationException("invalid extended key checksum")
    }
    val payload = decoded.copyOfRange(0, 78)
    val version = readUint32(payload, 0)
    val isPrivate = payload[45] == 0.toByte()
    val entry = formats.entries.firstOrNull {
        (isPrivate && it.value.privateVersion == version) || (!isPrivate && it.value.publicVersion == version)
    } ?: throw WalletHDDerivationException("unknown extended-key version")
    val depth = payload[4].toInt() and 0xff
    val parent = payload.copyOfRange(5, 9)
    val child = readUint32(payload, 9)
    if (depth == 0 && (parent.any { it != 0.toByte() } || child != 0L)) {
        throw WalletHDDerivationException("root extended key must have zero parent fingerprint and child number")
    }
    val chainCode = payload.copyOfRange(13, 45)
    val privateNode: ExtendedPrivate?
    val publicNode: ExtendedPublic?
    val public: ByteArray
    if (isPrivate) {
        val key = payload.copyOfRange(46, 78)
        val scalar = BigInteger(1, key)
        if (scalar == BigInteger.ZERO || scalar >= curveOrder) throw WalletHDDerivationException("invalid extended private key")
        privateNode = ExtendedPrivate(key, chainCode, depth, parent, child)
        publicNode = null
        public = privateNode.publicKey()
    } else {
        val key = payload.copyOfRange(45, 78)
        try { curve.curve.decodePoint(key) } catch (error: Exception) {
            throw WalletHDDerivationException("invalid extended public key", error)
        }
        privateNode = null
        publicNode = ExtendedPublic(key, chainCode, depth, parent, child)
        public = key
    }
    return ParsedExtendedKey(value, "%08x".format(version), entry.key, isPrivate, depth, child, parent.hex(), chainCode.hex(), public.hex(), privateNode, publicNode)
}

fun serializeExtendedKey(parsed: ParsedExtendedKey, private: Boolean = false, format: String = parsed.format): String {
    val selected = formats[format] ?: throw WalletHDDerivationException("unsupported extended-key format: $format")
    if (private) {
        return parsed.privateNode?.serializePrivate(selected.privateVersion)
            ?: throw WalletHDDerivationException("private material is not available from an extended public key")
    }
    return (parsed.publicNode ?: parsed.privateNode!!.neuter()).serialize(selected.publicVersion)
}

fun deriveAddressFromExtendedPublicKey(
    extendedPublicKey: String,
    chainId: String,
    change: Int = 0,
    index: Int = 0,
    scriptType: String? = null,
): DerivedAddress {
    val chain = requireChain(chainId)
    if (chain.curve != "secp256k1") throw WalletHDDerivationException("extended public derivation is available only for secp256k1 chains")
    val parsed = parseExtendedKey(extendedPublicKey)
    if (parsed.isPrivate) throw WalletHDDerivationException("use an extended public key, not an extended private key")
    validateIndex(change, "change")
    validateIndex(index, "index")
    val node = parsed.publicNode!!.derive(change.toLong()).derive(index.toLong())
    val script = scriptType ?: when (parsed.format) {
        "ypub", "upub", "Mtub" -> "p2sh-p2wpkh"
        "zpub", "vpub" -> "p2wpkh"
        else -> chain.defaultScriptType
    }
    return addressResult(chain, DeriveOptions(change = change, index = index), "$change/$index", script, publicKeyAddress(node.publicKey, chain, script), node.publicKey)
}

private data class Slip10Node(
    val privateKey: ByteArray,
    val publicKey: ByteArray,
    val chainCode: ByteArray,
    val depth: Int,
    val childNumber: Long,
)

private fun slip10(seed: ByteArray, path: String): Slip10Node {
    var digest = hmacSha512("ed25519 seed".toByteArray(), seed)
    var privateKey = digest.copyOfRange(0, 32)
    var chainCode = digest.copyOfRange(32, 64)
    var depth = 0
    var child = 0L
    for (index in parsePath(path, true)) {
        digest = hmacSha512(chainCode, byteArrayOf(0) + privateKey + uint32(index))
        privateKey = digest.copyOfRange(0, 32)
        chainCode = digest.copyOfRange(32, 64)
        depth++
        child = index
    }
    val public = Ed25519PrivateKeyParameters(privateKey, 0).generatePublicKey().encoded
    return Slip10Node(privateKey, public, chainCode, depth, child)
}

private fun normalizePath(path: String, ed25519: Boolean = false): String {
    val values = parsePath(path, ed25519)
    if (values.isEmpty()) return "m"
    return "m/" + values.joinToString("/") { index ->
        if (index >= HARDENED_OFFSET) "${index - HARDENED_OFFSET}'" else index.toString()
    }
}

private fun publicKeyAddress(public: ByteArray, chain: ChainInfo, script: String): String = when (script) {
    "p2pkh" -> base58Check(chain.p2pkh + hash160(public))
    "p2sh-p2wpkh" -> base58Check(chain.p2sh + hash160(byteArrayOf(0, 20) + hash160(public)))
    "p2wpkh" -> segwitAddress(chain.hrp ?: throw WalletHDDerivationException("native SegWit is not registered for ${chain.id}"), 0, hash160(public))
    "p2tr" -> segwitAddress(chain.hrp ?: throw WalletHDDerivationException("Taproot is not registered for ${chain.id}"), 1, taprootOutputKey(public))
    "cashaddr" -> cashAddress("bitcoincash", hash160(public))
    "evm" -> evmAddress(public)
    "tron" -> base58Check(byteArrayOf(0x41) + rawEvmAddress(public))
    else -> throw WalletHDDerivationException("unsupported script type: $script")
}

private fun rawEvmAddress(public: ByteArray): ByteArray {
    val point = curve.curve.decodePoint(public).normalize()
    return keccak256(point.getEncoded(false).copyOfRange(1, 65)).copyOfRange(12, 32)
}

private fun evmAddress(public: ByteArray): String {
    val lower = rawEvmAddress(public).hex()
    val checksum = keccak256(lower.toByteArray()).hex()
    return "0x" + lower.mapIndexed { index, character ->
        if (character in 'a'..'f' && checksum[index].digitToInt(16) >= 8) character.uppercaseChar() else character
    }.joinToString("")
}

private fun taprootOutputKey(public: ByteArray): ByteArray {
    val xOnly = public.copyOfRange(1, 33)
    val internal = curve.curve.decodePoint(byteArrayOf(2) + xOnly)
    val tweak = BigInteger(1, taggedHash("TapTweak", xOnly))
    if (tweak >= curveOrder) throw WalletHDDerivationException("invalid Taproot tweak")
    val output = internal.add(curve.g.multiply(tweak)).normalize()
    if (output.isInfinity) throw WalletHDDerivationException("invalid Taproot output key")
    return output.getEncoded(true).copyOfRange(1, 33)
}

private fun serializeKey(version: Long, depth: Int, parent: ByteArray, child: Long, chainCode: ByteArray, key: ByteArray): String =
    base58Check(uint32(version) + byteArrayOf(depth.toByte()) + parent + uint32(child) + chainCode + key)

private fun uint32(value: Long): ByteArray = byteArrayOf(
    (value ushr 24).toByte(),
    (value ushr 16).toByte(),
    (value ushr 8).toByte(),
    value.toByte(),
)

private fun readUint32(bytes: ByteArray, offset: Int): Long =
    ((bytes[offset].toLong() and 0xff) shl 24) or
        ((bytes[offset + 1].toLong() and 0xff) shl 16) or
        ((bytes[offset + 2].toLong() and 0xff) shl 8) or
        (bytes[offset + 3].toLong() and 0xff)

private fun BigInteger.toFixedBytes(size: Int): ByteArray {
    val raw = toByteArray().let { if (it.size > size) it.copyOfRange(it.size - size, it.size) else it }
    return ByteArray(size - raw.size) + raw
}

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

private fun hmacSha512(key: ByteArray, data: ByteArray): ByteArray {
    val mac = HMac(SHA512Digest())
    mac.init(KeyParameter(key))
    mac.update(data, 0, data.size)
    return ByteArray(64).also { mac.doFinal(it, 0) }
}

private fun sha256(data: ByteArray): ByteArray {
    val digest = SHA256Digest()
    digest.update(data, 0, data.size)
    return ByteArray(32).also { digest.doFinal(it, 0) }
}

private fun doubleSha256(data: ByteArray): ByteArray = sha256(sha256(data))

private fun hash160(data: ByteArray): ByteArray {
    val first = sha256(data)
    val digest = RIPEMD160Digest()
    digest.update(first, 0, first.size)
    return ByteArray(20).also { digest.doFinal(it, 0) }
}

private fun keccak256(data: ByteArray): ByteArray {
    val digest = KeccakDigest(256)
    digest.update(data, 0, data.size)
    return ByteArray(32).also { digest.doFinal(it, 0) }
}

private fun taggedHash(tag: String, message: ByteArray): ByteArray {
    val tagHash = sha256(tag.toByteArray())
    return sha256(tagHash + tagHash + message)
}

private const val BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

private fun base58Check(payload: ByteArray): String = base58Encode(payload + doubleSha256(payload).copyOfRange(0, 4))

private fun base58Encode(bytes: ByteArray): String {
    if (bytes.isEmpty()) return ""
    var number = BigInteger(1, bytes)
    val result = StringBuilder()
    while (number > BigInteger.ZERO) {
        val division = number.divideAndRemainder(BigInteger.valueOf(58))
        result.append(BASE58_ALPHABET[division[1].toInt()])
        number = division[0]
    }
    bytes.takeWhile { it == 0.toByte() }.forEach { _ -> result.append('1') }
    return result.reverse().toString()
}

private fun base58Decode(value: String): ByteArray {
    var number = BigInteger.ZERO
    value.forEach { character ->
        val digit = BASE58_ALPHABET.indexOf(character)
        if (digit < 0) throw WalletHDDerivationException("invalid Base58 character")
        number = number.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(digit.toLong()))
    }
    var raw = number.toByteArray()
    if (raw.isNotEmpty() && raw[0] == 0.toByte()) raw = raw.copyOfRange(1, raw.size)
    return ByteArray(value.takeWhile { it == '1' }.length) + raw
}

private const val BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

private fun segwitAddress(hrp: String, version: Int, program: ByteArray): String {
    val words = listOf(version) + convertBits(program.map { it.toInt() and 0xff }, 8, 5, true)
    return bech32Encode(hrp, words, if (version == 0) 1 else 0x2bc830a3)
}

private fun bech32Encode(hrp: String, words: List<Int>, constant: Int): String {
    val values = hrp.map { it.code ushr 5 } + listOf(0) + hrp.map { it.code and 31 } + words + List(6) { 0 }
    val polymod = bech32Polymod(values) xor constant
    val checksum = (0 until 6).map { (polymod ushr (5 * (5 - it))) and 31 }
    return hrp + "1" + (words + checksum).joinToString("") { BECH32_ALPHABET[it].toString() }
}

private fun bech32Polymod(values: List<Int>): Int {
    val generators = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    var checksum = 1
    values.forEach { value ->
        val top = checksum ushr 25
        checksum = ((checksum and 0x1ffffff) shl 5) xor value
        for (index in generators.indices) if ((top ushr index) and 1 != 0) checksum = checksum xor generators[index]
    }
    return checksum
}

private fun convertBits(data: List<Int>, from: Int, to: Int, pad: Boolean): List<Int> {
    var accumulator = 0
    var bits = 0
    val mask = (1 shl to) - 1
    val output = mutableListOf<Int>()
    data.forEach { value ->
        if (value < 0 || value ushr from != 0) throw WalletHDDerivationException("invalid bit-group value")
        accumulator = (accumulator shl from) or value
        bits += from
        while (bits >= to) {
            bits -= to
            output += (accumulator ushr bits) and mask
        }
    }
    if (pad && bits > 0) output += (accumulator shl (to - bits)) and mask
    return output
}

private fun cashAddress(prefix: String, hash: ByteArray): String {
    val payload = convertBits((byteArrayOf(0) + hash).map { it.toInt() and 0xff }, 8, 5, true)
    val values = prefix.map { it.code and 31 } + listOf(0) + payload + List(8) { 0 }
    val polymod = cashPolymod(values) xor 1L
    val checksum = (0 until 8).map { ((polymod ushr (5 * (7 - it))) and 31).toInt() }
    return "$prefix:" + (payload + checksum).joinToString("") { BECH32_ALPHABET[it].toString() }
}

private fun cashPolymod(values: List<Int>): Long {
    val generators = longArrayOf(0x98f2bc8e61L, 0x79b76d99e2L, 0xf33e5fb3c4L, 0xae2eabe2a8L, 0x1e4f43e470L)
    var checksum = 1L
    values.forEach { value ->
        val top = checksum ushr 35
        checksum = ((checksum and 0x07ffffffffL) shl 5) xor value.toLong()
        for (index in generators.indices) if ((top ushr index) and 1L != 0L) checksum = checksum xor generators[index]
    }
    return checksum
}
