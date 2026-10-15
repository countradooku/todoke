// Startup for the app (P16): the Baseline Profile generator, which walks
// every screen once, and the cold-start benchmark, with and without the
// profile. Both drive a release build of :app on a connected device:
//
//   gradle :app:generateBaselineProfile -Ptodoke.android=…
//   gradle :baselineprofile:connectedPlayBenchmarkReleaseAndroidTest -Ptodoke.android=…
plugins {
    alias(libs.plugins.android.test)
    alias(libs.plugins.baselineprofile)
}

android {
    namespace = "org.todoke.android.baselineprofile"
    compileSdk = 37

    defaultConfig {
        // Macrobenchmark needs Android 9.
        minSdk = 28
        targetSdk = 37
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    targetProjectPath = ":app"

    flavorDimensions += "store"
    productFlavors {
        create("play") {
            dimension = "store"
        }
        create("fdroid") {
            dimension = "store"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

baselineProfile {
    useConnectedDevices = true
}

dependencies {
    implementation(libs.androidx.test.junit)
    implementation(libs.uiautomator)
    implementation(libs.benchmark.macro)
}
