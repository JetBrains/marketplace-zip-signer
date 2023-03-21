plugins {
    kotlin("jvm")
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

dependencies {
    implementation(platform("com.google.cloud:libraries-bom:26.10.0"))
    implementation("com.google.cloud:google-cloud-kms")
    implementation("com.github.spullara.cli-parser:cli-parser:1.1.6")
    implementation(project(":lib"))
}

tasks {
    jar {
        manifest {
            attributes("Main-Class" to "org.jetbrains.zip.signer.GoogleCloudSignerCli")
        }
    }
}