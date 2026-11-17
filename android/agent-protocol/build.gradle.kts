import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// Platform-neutral half of the Android SDK (dev.genadb.sdk): models, agent
// supervision, hash-chained audit log. Compiled into :genadb-android and also
// built here as a plain JVM module so it can be tested without an Android SDK.
plugins {
    kotlin("jvm")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
kotlin {
    explicitApi()
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

dependencies {
    implementation("org.json:json:20250517") // part of the Android platform
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}

tasks.test { useJUnitPlatform() }
