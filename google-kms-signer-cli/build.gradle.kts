plugins {
    kotlin("jvm")
    id("com.github.johnrengelman.shadow") version "7.1.1"
}

dependencies {
    implementation(platform("com.google.cloud:libraries-bom:24.0.0"))
    implementation("com.google.cloud:google-cloud-kms")
    implementation("com.github.spullara.cli-parser:cli-parser:1.1.5")
    implementation(project(":lib"))
}

tasks {
    jar {
        manifest {
            attributes("Main-Class" to "org.jetbrains.zip.signer.GoogleCloudSignerCli")
        }
    }
}