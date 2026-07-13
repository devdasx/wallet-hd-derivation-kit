---
layout: default
title: Kotlin Android HD wallet derivation
description: Add io.github.devdasx wallet-hd-derivation-kit from Maven Central for JVM and Android derivation.
permalink: /kotlin/
---

# Kotlin / JVM / Android

```kotlin
implementation("io.github.devdasx:wallet-hd-derivation-kit:1.0.0")
```

```kotlin
val source = Source.Mnemonic(System.getenv("WALLET_MNEMONIC"))
val result = deriveAddress(source, DeriveOptions(chain = "ethereum"))
println(result.address)
```

JVM 11+ is supported. The artifact is also addressable through JitPack as `com.github.devdasx:wallet-hd-derivation-kit:v1.0.0`. [Runnable example](https://github.com/devdasx/wallet-hd-derivation-kit/tree/main/examples/kotlin).
