plugins {
    kotlin("jvm") version "1.4.21"
    id("io.github.gradle-nexus.publish-plugin") version "1.1.0"
}

nexusPublishing {
    repositories {
        sonatype {
            val mavenCentralUsername: String? by project
            val mavenCentralPassword: String? by project

            username.set(mavenCentralUsername)
            password.set(mavenCentralPassword)
        }
    }
}

allprojects {
    repositories {
        mavenCentral()
    }
}