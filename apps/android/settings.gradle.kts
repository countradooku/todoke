// The todoke Android app (P16): Jetpack Compose on the BoltFFI bindings.
// The bindings come from crates/todoke-ffi/android, an included build: pass
// its packed libraries with -Ptodoke.android=<boltffi pack android output>.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "todoke-android"
include(":app")
include(":baselineprofile")

includeBuild("../../crates/todoke-ffi/android") {
    dependencySubstitution {
        substitute(module("org.todoke:todoke-ffi-android")).using(project(":"))
    }
}
