plugins {
    kotlin("jvm") version "1.6.20"
}

allprojects {
    project.version = if (hasProperty("projectVersion")) findProperty("projectVersion").toString() else "DEV"

    repositories {
        mavenCentral()
    }
}
