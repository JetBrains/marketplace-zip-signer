import com.google.protobuf.gradle.*

plugins {
    kotlin("jvm")
    id("com.google.protobuf") version "0.8.18"
    id("idea")
    id("maven-publish")
    id("signing")
    id("com.github.johnrengelman.shadow") version "7.0.0"
}

dependencies {
    api("org.bouncycastle:bcpkix-jdk15on:1.69")
    implementation("com.google.protobuf:protobuf-java:3.19.1")

    testImplementation("junit:junit:4.13.2")
}

idea {
    module {
        sourceDirs.add(file("${projectDir}/src/generated/main/java"))
    }
}

java {
    withSourcesJar()
    withJavadocJar()

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
        artifact = "com.google.protobuf:protoc:3.19.1"
    }
    generatedFilesBaseDir = "$projectDir/src/generated"
}

publishing {
    publications {
        fun MavenPublication.configurePom() {
            pom {
                name.set("JetBrains Marketplace ZIP Signer")
                description.set("The main goal of the JetBrains Marketplace ZIP Signer is to sign and verify JetBrains plugins, but it can be applied to any other ZIP archive. The general concept of the used ZIP archive signature scheme is similar to APK Signature Scheme V2.")
                url.set("https://github.com/JetBrains/marketplace-zip-signer")
                licenses {
                    license {
                        name.set("The Apache Software License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("satamas")
                        name.set("Semyon Atamas")
                        organization.set("JetBrains")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/JetBrains/marketplace-zip-signer.git")
                    developerConnection.set("scm:git:ssh://github.com/JetBrains/marketplace-zip-signer.git")
                    url.set("https://github.com/JetBrains/marketplace-zip-signer")
                }
            }
        }

        create<MavenPublication>("zip-signer-maven") {
            groupId = "org.jetbrains"
            artifactId = "marketplace-zip-signer"
            version = project.version.toString()
            from(components["java"])
            configurePom()
        }
        create<MavenPublication>("zip-signer-maven-all") {
            groupId = "org.jetbrains"
            artifactId = "marketplace-zip-signer-all"
            version = project.version.toString()
            project.shadow.component(this@create)
            configurePom()
        }
    }

    repositories {
        maven {
            url = uri("https://oss.sonatype.org/service/local/staging/deploy/maven2")

            val mavenCentralUsername: String? by project
            val mavenCentralPassword: String? by project

            credentials {
                username = mavenCentralUsername
                password = mavenCentralPassword
            }
        }
    }
}

signing {
    isRequired = project.version != "DEV"

    val signingKey: String? by project
    val signingPassword: String? by project

    useInMemoryPgpKeys(signingKey, signingPassword)
    sign(publishing.publications["zip-signer-maven"])
    sign(publishing.publications["zip-signer-maven-all"])
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
        relocate("org.bouncycastle", "thirdparty.bouncycastle")
        relocate("org.intellij", "thirdparty.intellij")
    }
}
