plugins {
    id("com.gradleup.shadow") version "8.3.6"
}

dependencies {
    implementation(platform("com.google.cloud:libraries-bom:26.61.0"))
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