plugins {
    kotlin("jvm") version "2.3.21"
    `java-library`
    id("org.jetbrains.dokka") version "2.1.0"
    id("com.vanniktech.maven.publish") version "0.37.0"
    jacoco
}

group = "io.github.devdasx"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    api("org.bouncycastle:bcprov-jdk18on:1.84")
    implementation("org.bitcoinj:bitcoinj-core:0.17.1") {
        exclude(group = "org.bouncycastle", module = "bcprov-jdk15to18")
    }
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.14.3")
}

kotlin {
    sourceSets {
        main {
            kotlin.srcDir("kotlin/src/main/kotlin")
        }
        test {
            kotlin.srcDir("kotlin/src/test/kotlin")
        }
    }
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
        allWarningsAsErrors.set(true)
        freeCompilerArgs.add("-Xjsr305=strict")
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
    withSourcesJar()
}

tasks.test {
    useJUnitPlatform()
    finalizedBy(tasks.jacocoTestReport)
}

jacoco {
    toolVersion = "0.8.15"
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}

tasks.jacocoTestCoverageVerification {
    dependsOn(tasks.test)
    violationRules {
        rule {
            limit {
                counter = "LINE"
                value = "COVEREDRATIO"
                minimum = "0.90".toBigDecimal()
            }
        }
    }
}

tasks.register<JavaExec>("conformance") {
    dependsOn(tasks.classes)
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("io.github.devdasx.wallethd.ConformanceKt")
}

tasks.register<Copy>("prepareOfflineConformance") {
    dependsOn(tasks.classes)
    from(configurations.runtimeClasspath)
    into(layout.buildDirectory.dir("offline-conformance/lib"))
}

tasks.matching { it.name == "generateMetadataFileForMavenPublication" }.configureEach {
    dependsOn("dokkaJavadocJar")
}

mavenPublishing {
    publishToMavenCentral()
    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        signAllPublications()
    }
    coordinates(group.toString(), "wallet-hd-derivation-kit", version.toString())
    pom {
        name.set("Wallet HD Derivation Kit")
        description.set("Offline multi-chain HD wallet derivation for Kotlin, JVM, and Android")
        url.set("https://github.com/devdasx/wallet-hd-derivation-kit")
        inceptionYear.set("2026")
        licenses {
            license {
                name.set("MIT License")
                url.set("https://opensource.org/licenses/MIT")
                distribution.set("https://opensource.org/licenses/MIT")
            }
        }
        developers {
            developer {
                id.set("devdasx")
                name.set("ROYO STUDIOS")
                email.set("royostudios13@gmail.com")
            }
        }
        scm {
            connection.set("scm:git:git://github.com/devdasx/wallet-hd-derivation-kit.git")
            developerConnection.set("scm:git:ssh://github.com/devdasx/wallet-hd-derivation-kit.git")
            url.set("https://github.com/devdasx/wallet-hd-derivation-kit")
        }
    }
}
