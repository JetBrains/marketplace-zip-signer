plugins {
    kotlin("jvm")
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))
    api("org.bouncycastle", "bcprov-jdk15on", "1.64")
}