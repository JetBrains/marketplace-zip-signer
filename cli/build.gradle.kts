plugins {
    id("com.github.johnrengelman.shadow") version ("5.2.0")
    kotlin("jvm")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))
    implementation("com.github.spullara.cli-parser", "cli-parser", "1.1.2")
    implementation(project(":lib"))
}

tasks {
    jar {
        manifest {
            attributes(mapOf("Main-Class" to "org.jetbrains.zip.signer.ZipSigningTool"))
        }
    }
    shadowJar {
        archiveName = "zip-signer.jar"
    }
}