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

rootProject.name = "genadb-android"

// Pure-Kotlin bridge to the genadb agent (command line + event stream).
// Builds and tests on any JVM, no Android SDK needed.
include(":agent-protocol")

// The Android app needs an Android SDK (ANDROID_HOME or local.properties).
val hasSdk = System.getenv("ANDROID_HOME") != null ||
    System.getenv("ANDROID_SDK_ROOT") != null ||
    file("local.properties").let { it.exists() && it.readText().contains("sdk.dir") }
if (hasSdk) {
    include(":app")
} else {
    logger.lifecycle("No Android SDK found: building :agent-protocol only (set ANDROID_HOME to build :app)")
}
