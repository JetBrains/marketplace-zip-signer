plugins {
    id("com.google.protobuf") version "0.9.4"
    id("idea")
    id("com.github.johnrengelman.shadow") version "7.1.2"
}

dependencies {
    api("org.bouncycastle:bcpkix-jdk18on:1.77")
    implementation("com.google.protobuf:protobuf-java:3.25.1")

    testImplementation("junit:junit:4.13.2")
}

idea {
    module {
        sourceDirs.add(file("${projectDir}/src/generated/main/java"))
    }
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:3.25.2"
    }
    generatedFilesBaseDir = "$projectDir/src/generated"
}

tasks {
    test {
        maxParallelForks = Runtime.getRuntime().availableProcessors()

        val tmpDir = "${project.buildDir}/tmp"

        systemProperties = mapOf(
            "project.tempDir" to tmpDir
        )

        finalizedBy("clearTmpDir")
    }
    shadowJar {
        archiveBaseName.set("zip-signer")
        relocate("com.google.protobuf", "thirdparty.protobuf")
        relocate("kotlin", "thirdparty.kotlin")
        relocate("org.bouncycastle", "thirdparty.bouncycastle")
        relocate("org.intellij", "thirdparty.intellij")
    }
}

task("clearTmpDir", type = Delete::class) {
    delete("${project.buildDir}/tmp")
}
