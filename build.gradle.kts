import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "2.1.21"
    id("maven-publish")
    id("signing")
    id("com.gradleup.shadow") version "8.3.6"
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
}

allprojects {
    project.version = if (hasProperty("projectVersion")) findProperty("projectVersion").toString() else "DEV"

    repositories {
        mavenCentral()
    }
}

subprojects {
    layout.buildDirectory.set(rootProject.layout.buildDirectory.dir(project.name))
    apply(plugin = "org.jetbrains.kotlin.jvm")
    apply(plugin = "com.gradleup.shadow")

    java {
        withSourcesJar()
        withJavadocJar()

        toolchain {
            languageVersion.set(JavaLanguageVersion.of(8))
        }
    }

    tasks {
        withType(KotlinCompile::class.java).all {
            kotlinOptions {
                jvmTarget = "1.8"
            }
        }
    }
}

dependencies {
    implementation(project(":lib"))
    implementation(project(":cli"))
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

        create<MavenPublication>("zip-signer-cli-maven") {
            groupId = "org.jetbrains"
            artifactId = "marketplace-zip-signer-cli"
            version = project.version.toString()
            artifact(project(":cli").tasks.shadowJar) {
                classifier = ""
            }
            artifact(project(":cli").tasks.kotlinSourcesJar)
            artifact(project(":cli").tasks.named("javadocJar"))
            configurePom()
        }
        create<MavenPublication>("zip-signer-maven") {
            groupId = "org.jetbrains"
            artifactId = "marketplace-zip-signer"
            version = project.version.toString()
            from(project(":lib").components["java"])
            artifact(project(":cli").tasks.shadowJar) {
                classifier = "cli"
            }
            configurePom()
        }
        create<MavenPublication>("zip-signer-maven-all") {
            groupId = "org.jetbrains"
            artifactId = "marketplace-zip-signer-all"
            version = project.version.toString()
            project(":lib").shadow.component(this@create)
            configurePom()
        }
    }
}

nexusPublishing {
    packageGroup.set("org.jetbrains")
    repositories {
        val mavenCentralOssrhUsername: String? by project
        val mavenCentralOssrhToken: String? by project

        sonatype {
            username.set(mavenCentralOssrhUsername)
            password.set(mavenCentralOssrhToken)
        }
    }
}

signing {
    isRequired = project.version != "DEV"

    val signingKey: String? by project
    val signingPassword: String? by project

    useInMemoryPgpKeys(signingKey, signingPassword)
    sign(publishing.publications["zip-signer-maven"])
    sign(publishing.publications["zip-signer-cli-maven"])
    sign(publishing.publications["zip-signer-maven-all"])
}

tasks {
    // Workaround for Gradle warning about publish tasks using signing task outputs without explicit dependencies
    // https://github.com/gradle/gradle/issues/26091
    val signingTasks = withType<Sign>()
    withType<AbstractPublishToMaven>().configureEach {
        mustRunAfter(signingTasks)
    }
}