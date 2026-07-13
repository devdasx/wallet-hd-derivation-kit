package io.github.devdasx.wallethd

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class WalletHDDerivationKitTest {
    private val source = Source.Mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

    @Test
    fun slip132AndWatchOnlyMatch() {
        val account = deriveAccountPublicKey(source, DeriveOptions(format = "zpub"))
        val zpub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
        assertEquals(zpub, account.extendedPublicKey)
        val direct = deriveAddress(source)
        val watched = deriveAddressFromExtendedPublicKey(zpub, "bitcoin")
        assertEquals("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", direct.address)
        assertEquals(direct.address, watched.address)
    }

    @Test
    fun explicitPrivateExportRoundTrips() {
        val secret = deriveAccountPrivateKey(source, DeriveOptions(format = "zpub"))
        val zprv = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE"
        assertEquals(zprv, secret.extendedPrivateKey)
        assertEquals(zprv, serializeExtendedKey(parseExtendedKey(zprv), private = true))
    }

    @Test
    fun chainFamilyVectorsMatch() {
        val vectors = mapOf(
            "litecoin" to "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez",
            "dogecoin" to "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC",
            "dash" to "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5",
            "digibyte" to "DG1KhhBKpsyWXTakHNezaDQ34focsXjN1i",
            "bitcoin-cash" to "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6",
            "zcash-transparent" to "t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F",
            "ethereum" to "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "ethereum-classic" to "0xFA22515E43658ce56A7682B801e9B5456f511420",
            "tron" to "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
            "solana" to "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
        )
        vectors.forEach { (chain, expected) ->
            assertEquals(expected, deriveAddress(source, DeriveOptions(chain = chain)).address, chain)
        }
    }

    @Test
    fun bip86AndBoundariesMatch() {
        assertEquals(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            deriveAddress(source, DeriveOptions(scriptType = "p2tr")).address,
        )
        assertEquals(18, supportedChains().size)
        assertFailsWith<WalletHDDerivationException> { deriveAddress(Source.Mnemonic("abandon abandon")) }
        assertFailsWith<WalletHDDerivationException> { deriveNode(Source.Seed(byteArrayOf(1, 2, 3))) }
        assertEquals(listOf(3, 4, 5, 6), deriveAddresses(source, DeriveOptions(chain = "ethereum"), 3, 4).map { it.index })
    }

    @Test
    fun rejectsEveryOfficialBip32InvalidExtendedKey() {
        val json = File("test-vectors/bip32-official.json").readText()
        val invalidSection = json.substringAfter("\"invalidExtendedKeys\"")
        val invalidValues = Regex("\"value\"\\s*:\\s*\"([^\"]+)\"")
            .findAll(invalidSection)
            .map { it.groupValues[1] }
            .toList()
        assertEquals(16, invalidValues.size)
        invalidValues.forEach { value ->
            assertFailsWith<WalletHDDerivationException> { parseExtendedKey(value) }
        }
    }
}
