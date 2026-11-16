plugins {
    // versions live here so the SDK-less build (agent-protocol only) never resolves AGP
    id("com.android.application") version "8.9.3"
    kotlin("android") version "2.1.21"
    id("org.jetbrains.kotlin.plugin.compose") version "2.1.21"
}

android {
    namespace = "dev.genadb.companion"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.genadb.companion"
        minSdk = 29 // Android 10: legacy tcpip; Wireless debugging (TLS) needs 30+
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
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
    implementation(project(":agent-protocol"))
    implementation(platform("androidx.compose:compose-bom:2025.05.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.lifecycle:lifecycle-service:2.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}

// Cross-compile the Go connectivity core (../../core) into the APK as an
// executable "library" so the service can run it from nativeLibraryDir.
val goCore = rootProject.projectDir.resolve("../core")
val jniOut = layout.projectDirectory.dir("src/main/jniLibs")
val goTargets = mapOf(
    "arm64-v8a" to listOf("GOOS=android", "GOARCH=arm64"),
    "x86_64" to listOf("GOOS=linux", "GOARCH=amd64"), // emulator; android/amd64 needs cgo
)
val buildGenadb by tasks.registering {
    group = "build"
    description = "Builds libgenadb.so for each ABI from the Go core"
    inputs.dir(goCore.resolve("cmd"))
    outputs.dir(jniOut)
    doLast {
        goTargets.forEach { (abi, env) ->
            val out = jniOut.dir(abi).file("libgenadb.so").asFile
            out.parentFile.mkdirs()
            val pb = ProcessBuilder("go", "build", "-trimpath", "-ldflags=-s -w", "-o", out.absolutePath, "./cmd/genadb")
                .directory(goCore).inheritIO()
            pb.environment().apply {
                env.forEach { kv -> val (k, v) = kv.split("="); put(k, v) }
                put("CGO_ENABLED", "0")
            }
            check(pb.start().waitFor() == 0) { "go build failed for $abi" }
        }
    }
}
tasks.named("preBuild") { dependsOn(buildGenadb) }
