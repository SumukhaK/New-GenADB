plugins {
    // versions: root build.gradle.kts
    id("com.android.application")
    kotlin("android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "dev.genadb.companion"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.genadb.companion"
        minSdk = 29 // Android 10: legacy tcpip; Wireless debugging (TLS) needs 30+
        targetSdk = 35
        versionCode = 2
        versionName = "1.0.1"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }
    buildFeatures { compose = true }
    packaging { jniLibs { useLegacyPackaging = true } } // libgenadb.so must be extracted to be exec'd
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation(project(":genadb-android"))
    implementation(platform("androidx.compose:compose-bom:2025.05.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.lifecycle:lifecycle-service:2.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.0")
}
