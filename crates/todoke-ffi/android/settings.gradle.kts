// The Android AAR of the bindings: BoltFFI's Kotlin and JNI libraries
// (boltffi pack android), with Guarded.kt. scripts/ci/ffi-android.sh builds
// it.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "todoke-ffi-android"
