plugins {
    id("com.github.johnrengelman.shadow") version ("5.2.0")
    kotlin("jvm") version "1.3.61"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))
    implementation("com.github.spullara.cli-parser", "cli-parser", "1.1.2")
    implementation("org.bouncycastle", "bcprov-jdk15on", "1.64")
}

tasks {
    compileKotlin {
        kotlinOptions.jvmTarget = "1.8"
    }
    compileTestKotlin {
        kotlinOptions.jvmTarget = "1.8"
    }
    jar {
        manifest {
            attributes(mapOf("Main-Class" to "org.jetbrains.zip.signer.ZipSigningTool"))
        }
    }
}
