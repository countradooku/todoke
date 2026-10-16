// The Kotlin bindings' smoke tests on a desktop JVM, and the Guarded helper
// the Android app uses (scripts/ci/ffi-kotlin.sh runs them).
// The Kotlin plugin from Maven Central, where JetBrains publishes it, the
// plugin portal only as a fallback (its mirror has missed the plugin's BOM).
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "todoke-ffi-kotlin"
