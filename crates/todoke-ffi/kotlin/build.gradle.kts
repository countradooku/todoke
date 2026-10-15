// Generated Kotlin (boltffi generate kotlin) is compiled with Guarded.kt;
// the JNI library (the generated C glue linked with todoke-ffi) is found
// on java.library.path. Both come from the properties below.
plugins {
    kotlin("jvm") version "2.4.21"
}

repositories {
    mavenCentral()
}

val generated = providers.gradleProperty("todoke.generated")
val natives = providers.gradleProperty("todoke.natives")

kotlin {
    jvmToolchain(21)
    sourceSets {
        main {
            kotlin.srcDir(generated)
        }
    }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:6.1.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:6.1.3")
}

tasks.test {
    useJUnitPlatform()
    systemProperty("java.library.path", natives.get())
    testLogging {
        events("passed", "failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
