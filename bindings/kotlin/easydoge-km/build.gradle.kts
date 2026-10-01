plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    namespace = "io.easydoge.km"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation("net.java.dev.jna:jna:5.19.1")
    implementation("androidx.biometric:biometric:1.1.0")
    testImplementation(kotlin("test"))
    testImplementation("junit:junit:4.13.2")
}
