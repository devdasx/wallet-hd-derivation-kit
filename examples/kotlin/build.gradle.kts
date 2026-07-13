plugins { kotlin("jvm") version "2.3.21"; application }
dependencies { implementation("io.github.devdasx:wallet-hd-derivation-kit:1.0.1") }
application { mainClass.set("example.MainKt") }
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11) } }
java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}
