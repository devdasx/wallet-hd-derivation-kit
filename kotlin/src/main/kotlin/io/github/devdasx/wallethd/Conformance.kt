package io.github.devdasx.wallethd

fun main() {
    val words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    val body = supportedChains().joinToString(prefix = "{", postfix = "}", separator = ",") { chain ->
        val address = deriveAddress(Source.Mnemonic(words), DeriveOptions(chain = chain.id)).address
        "\"${chain.id}\":\"$address\""
    }
    println("WALLETHD_CONFORMANCE=$body")
}
