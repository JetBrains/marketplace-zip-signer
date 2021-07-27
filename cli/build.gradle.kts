plugins {
    kotlin("jvm")
    id("com.github.johnrengelman.shadow") version "7.0.0"
}

dependencies {
    implementation("com.github.spullara.cli-parser:cli-parser:1.1.5")
    implementation(project(":lib"))
}

tasks {
    jar {
        manifest {
            attributes("Main-Class" to "org.jetbrains.zip.signer.ZipSigningTool")
        }
    }
    shadowJar {
        archiveName = "zip-signer.jar"
    }
}