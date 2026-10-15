plugins {
    id("com.android.library") version "9.4.1"
}

// BoltFFI's output (boltffi pack android): Kotlin sources and jniLibs.
val packed = providers.gradleProperty("todoke.android").get()

android {
    namespace = "org.todoke.ffi"
    compileSdk = 36

    defaultConfig {
        // Android 7 (P16's minimum).
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets {
        getByName("main") {
            java.srcDirs("$packed/kotlin", "../kotlin/src/main/kotlin")
            jniLibs.srcDirs("$packed/jniLibs")
        }
    }
}

dependencies {
    // Part of the API (Guarded.callSuspending, the events Flow): apps
    // compile against it too.
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
}
