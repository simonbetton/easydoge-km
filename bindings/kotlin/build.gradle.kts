buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        // Keep AGP's built-in Kotlin compiler aligned with our Kotlin libraries.
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.21")
    }
}

plugins {
    id("com.android.library") version "9.5.1" apply false
}
