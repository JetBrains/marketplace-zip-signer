plugins {
    kotlin("jvm") version "1.9.21"
}

allprojects {
    project.version = if (hasProperty("projectVersion")) findProperty("projectVersion").toString() else "DEV"

    repositories {
        mavenCentral()
    }
}

subprojects {
    buildDir = rootProject.buildDir.resolve(project.name)
    apply(plugin = "org.jetbrains.kotlin.jvm")

    java {
        withSourcesJar()
        withJavadocJar()

        toolchain {
            languageVersion.set(JavaLanguageVersion.of(11))
        }
    }
}
