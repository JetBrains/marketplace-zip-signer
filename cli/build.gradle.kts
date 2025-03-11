fun properties(key: String) = project.findProperty(key)?.toString()

plugins {
    id("org.jetbrains.changelog") version "2.2.1"
    id("com.github.breadmoirai.github-release") version "2.5.2"
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
    targetCommitish.set("master")
    owner.set("jetbrains")
    repo.set("marketplace-zip-signer")
    body.set(releaseNote)
    releaseAssets.setFrom(tasks.named("shadowJar"))
    tagName.set(version)
}
