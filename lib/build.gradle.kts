import com.google.protobuf.gradle.protoc

plugins {
    kotlin("jvm")
    id("com.google.protobuf") version "0.8.13"
    id("idea")
    id("maven-publish")
    id("com.jfrog.bintray") version "1.8.5"
    id("com.github.johnrengelman.shadow") version "5.2.0"
}

dependencies {
    implementation("org.bouncycastle:bcpkix-jdk15on:1.64")
    implementation("com.google.protobuf:protobuf-java:3.11.4")
    implementation("org.slf4j:slf4j-api:1.7.30")

    testImplementation("junit:junit:4.12")
}

idea {
    module {
        sourceDirs.add(file("${projectDir}/src/generated/main/java"))
    }
}

project.version = if (hasProperty("projectVersion")) findProperty("projectVersion").toString() else "DEV"

java {
    withSourcesJar()

    sourceCompatibility = JavaVersion.VERSION_1_7
    targetCompatibility = JavaVersion.VERSION_1_7
}

tasks {
    compileKotlin {
        targetCompatibility = JavaVersion.VERSION_1_7.toString()
        sourceCompatibility = JavaVersion.VERSION_1_7.toString()
    }
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:3.11.4"
    }
    generatedFilesBaseDir = "$projectDir/src/generated"
}

publishing {
    publications {
        create<MavenPublication>("zip-signer-maven") {
            groupId = "org.jetbrains"
            artifactId = "marketplace-zip-signer"
            version = project.version.toString()
            from(components["java"])
        }
        create<MavenPublication>("zip-signer-maven-all") {
            groupId = "org.jetbrains"
            artifactId = "marketplace-zip-signer-all"
            version = project.version.toString()
            project.shadow.component(this@create)
        }
    }
}

if (hasProperty("bintrayUser")) {
    bintray {
        user = project.findProperty("bintrayUser").toString()
        key = project.findProperty("bintrayApiKey").toString()
        publish = true
        setPublications("zip-signer-maven", "zip-signer-maven-all")
        pkg.apply {
            userOrg = "jetbrains"
            repo = "intellij-plugin-service"
            name = "zip-signer"
            setLicenses("Apache-2.0")
            vcsUrl = "git"
            version.apply {
                name = project.version.toString()
            }
        }
    }
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
}

task("clearTmpDir", type = Delete::class) {
    delete("${project.buildDir}/tmp")
}

tasks {
    shadowJar {
        archiveBaseName.set("zip-signer")
        relocate("com.google.protobuf", "thirdparty.protobuf")
        relocate("kotlin", "thirdparty.kotlin")
        relocate("org.slf4j", "thirdparty.slf4j")
        relocate("org.bouncycastle", "thirdparty.bouncycastle")
        relocate("org.intellij", "thirdparty.intellij")
    }
}