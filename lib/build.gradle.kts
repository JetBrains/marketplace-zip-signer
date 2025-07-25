plugins {
    id("com.google.protobuf") version "0.9.4"
    id("idea")
    id("com.gradleup.shadow") version "8.3.6"
}

dependencies {
    api("org.bouncycastle:bcpkix-jdk18on:1.80")
    implementation("com.google.protobuf:protobuf-java:4.31.1")

    testImplementation("junit:junit:4.13.2")
}

val protobufGeneratedDir = project.layout.buildDirectory.dir("src/generated")
val tmpDir = project.layout.buildDirectory.dir("tmp")

idea {
    module {
        sourceDirs.add(protobufGeneratedDir.get().dir("main/java").asFile)
    }
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:4.31.1"
    }
    generatedFilesBaseDir = protobufGeneratedDir.get().asFile.absolutePath
}

tasks {
    test {
        maxParallelForks = Runtime.getRuntime().availableProcessors()

        val tmpDir = tmpDir

        systemProperties = mapOf(
            "project.tempDir" to tmpDir.get().asFile.absolutePath
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
    delete(tmpDir)
}
