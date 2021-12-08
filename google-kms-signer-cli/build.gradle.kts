plugins {
    kotlin("jvm")
    id("com.github.johnrengelman.shadow") version "7.0.0"
}

dependencies {
    implementation(platform("com.google.cloud:libraries-bom:24.1.0"))
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