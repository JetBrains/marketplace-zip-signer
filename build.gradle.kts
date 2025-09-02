import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import java.util.Base64
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.asRequestBody
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.2.10"
    id("maven-publish")
    id("signing")
    id("com.gradleup.shadow") version "8.3.6"
}

buildscript {
    dependencies {
        classpath("com.squareup.okhttp3:okhttp:4.12.0")
    }
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
            compilerOptions {
                jvmTarget = JvmTarget.JVM_1_8
            }
        }
    }
}

dependencies {
    implementation(project(":lib"))
    implementation(project(":cli"))
}

publishing {
    repositories {
        maven {
            name = "artifacts"
            url = uri(layout.buildDirectory.dir("artifacts/maven"))
        }
    }

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

    val packSonatypeCentralBundle by registering(Zip::class) {
        group = "publishing"

        dependsOn(":publishAllPublicationsToArtifactsRepository")

        from(layout.buildDirectory.dir("artifacts/maven"))
        archiveFileName.set("bundle.zip")
        destinationDirectory.set(layout.buildDirectory)
    }

    val publishMavenToCentralPortal by registering {
        group = "publishing"

        dependsOn(packSonatypeCentralBundle)

        doLast {
            val uriBase = "https://central.sonatype.com/api/v1/publisher/upload"
            val publishingType = "USER_MANAGED"
            val deploymentName = "${project.name}-$version"
            val uri = "$uriBase?name=$deploymentName&publishingType=$publishingType"

            val centralPortalUserName: String? by project
            val centralPortalToken: String? by project

            val base64Auth = Base64
                .getEncoder()
                .encode("$centralPortalUserName:$centralPortalToken".toByteArray())
                .toString(Charsets.UTF_8)
            val bundleFile = packSonatypeCentralBundle.get().archiveFile.get().asFile

            println("Sending request to $uri...")

            val client = OkHttpClient()
            val request = Request.Builder()
                .url(uri)
                .header("Authorization", "Bearer $base64Auth")
                .post(
                    MultipartBody.Builder()
                        .setType(MultipartBody.FORM)
                        .addFormDataPart("bundle", bundleFile.name, bundleFile.asRequestBody())
                        .build()
                )
                .build()
            client.newCall(request).execute().use { response ->
                val statusCode = response.code
                println("Upload status code: $statusCode")
                println("Upload result: ${response.body!!.string()}")
                if (statusCode != 201) {
                    error("Upload error to Central repository. Status code $statusCode.")
                }
            }
        }
    }
}