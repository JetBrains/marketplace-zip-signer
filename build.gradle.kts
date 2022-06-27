plugins {
    kotlin("jvm") version "1.7.0"
}

allprojects {
    project.version = if (hasProperty("projectVersion")) findProperty("projectVersion").toString() else "DEV"

    repositories {
        mavenCentral()
    }
}
