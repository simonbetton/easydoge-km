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
    implementation("net.java.dev.jna:jna:5.18.1")
}
