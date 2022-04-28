fun properties(key: String) = project.findProperty(key)?.toString()

plugins {
    kotlin("jvm")
    id("com.github.johnrengelman.shadow") version "7.1.2"
    id("org.jetbrains.changelog") version "1.3.1"
    id("com.github.breadmoirai.github-release") version "2.3.12"
}

dependencies {
    implementation("com.github.spullara.cli-parser:cli-parser:1.1.6")
    implementation(project(":lib"))
}

tasks {
    jar {
        manifest {
            attributes("Main-Class" to "org.jetbrains.zip.signer.ZipSigningTool")
        }
    }
    shadowJar {
        archiveFileName.set("marketplace-zip-signer-cli.jar")
    }
}

changelog {
    unreleasedTerm.set("next")
    path.set(projectDir.parentFile.resolve("CHANGELOG.md").canonicalPath)
}

githubRelease {
    val version = "${project.version}"
    val releaseNote = changelog.getOrNull(version)?.toText() ?: ""

    setToken(properties("githubToken"))
    owner.set("jetbrains")
    repo.set("marketplace-zip-signer")
    body.set(releaseNote)
    releaseAssets.setFrom(tasks.named("shadowJar"))
    tagName.set(version)
}
