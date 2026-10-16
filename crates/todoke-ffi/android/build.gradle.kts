plugins {
    id("com.android.library") version "9.4.1"
}

// BoltFFI's output (boltffi pack android): Kotlin sources and jniLibs.
val packed = providers.gradleProperty("todoke.android").get()

android {
    namespace = "org.todoke.ffi"
    compileSdk = 37

    defaultConfig {
        // Android 13: nearby Wi-Fi devices without location, and every radio API todoke uses (ADR 0019).
        minSdk = 33
        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets {
        getByName("main") {
            // Kotlin sources: AGP's built-in Kotlin compiles only `kotlin`
            // source directories (a `java` one with .kt files yields an
            // empty classes.jar).
            kotlin.srcDirs("$packed/kotlin", "../kotlin/src/main/kotlin")
            jniLibs.srcDirs("$packed/jniLibs")
        }
    }
}

dependencies {
    // Part of the API (Guarded.callSuspending, the events Flow): apps
    // compile against it too.
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
}
