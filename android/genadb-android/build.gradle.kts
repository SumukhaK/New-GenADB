// genadb-android: the Android SDK (AAR). Public API: dev.genadb.sdk.GenAdbManager
// and the models / interfaces it exposes. Build: ./gradlew :genadb-android:assembleRelease
// -> genadb-android/build/outputs/aar/genadb-android.aar
plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    namespace = "dev.genadb.sdk"
    compileSdk = 35
    defaultConfig {
        minSdk = 29
        consumerProguardFiles("consumer-rules.pro")
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }
    // Platform-neutral sources (models, agent supervision, audit chain) are
    // shared with the JVM-tested :agent-protocol module.
    sourceSets["main"].kotlin.srcDir("../agent-protocol/src/main/kotlin")
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

kotlin { explicitApi() }

dependencies {
    // org.json is part of the Android platform.
    api("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}

// Cross-compile the Go connectivity core (../../core) into the AAR as an
// executable "library"; GenAdbManager runs it from nativeLibraryDir.
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
    inputs.dir(goCore.resolve("internal"))
    inputs.dir(goCore.resolve("pkg"))
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

// Publish the release AAR under a stable name.
val namedAar by tasks.registering(Copy::class) {
    from(layout.buildDirectory.file("outputs/aar/genadb-android-release.aar"))
    into(layout.buildDirectory.dir("outputs/aar"))
    rename { "genadb-android.aar" }
}
tasks.matching { it.name == "assembleRelease" }.configureEach { finalizedBy(namedAar) }
