plugins {
    // All plugin versions live here so they share one classloader: the Kotlin
    // plugin must see AGP's classes. Resolving AGP needs no Android SDK; :app is
    // only included when an SDK is present (settings.gradle.kts).
    kotlin("jvm") version "2.1.21" apply false
    kotlin("android") version "2.1.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.1.21" apply false
    id("com.android.application") version "8.9.3" apply false
}
