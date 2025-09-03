plugins {
    id("com.gradleup.shadow") version "9.1.0"
}

dependencies {
    implementation(platform("com.google.cloud:libraries-bom:26.67.0"))
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