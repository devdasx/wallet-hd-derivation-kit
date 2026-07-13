package example

import io.github.devdasx.wallethd.DeriveOptions
import io.github.devdasx.wallethd.Source
import io.github.devdasx.wallethd.deriveAddress

fun main() {
    val words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    println(deriveAddress(Source.Mnemonic(words), DeriveOptions(chain = "ethereum")).address)
}
