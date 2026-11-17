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

// Platform-neutral half of the Android SDK (models, agent supervision, audit
// chain). Builds and tests on any JVM, no Android SDK needed.
include(":agent-protocol")

// The Android app needs an Android SDK (ANDROID_HOME or local.properties).
val hasSdk = System.getenv("ANDROID_HOME") != null ||
    System.getenv("ANDROID_SDK_ROOT") != null ||
    file("local.properties").let { it.exists() && it.readText().contains("sdk.dir") }
if (hasSdk) {
    include(":genadb-android") // the SDK (AAR)
    include(":app")            // companion app built on the SDK
} else {
    logger.lifecycle("No Android SDK found: building :agent-protocol only (set ANDROID_HOME to build :genadb-android and :app)")
}
