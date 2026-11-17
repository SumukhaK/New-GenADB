// setu-android: the Setu Android SDK (AAR). Public API: dev.genadb.sdk.SetuManager
// and the models / interfaces it exposes. Build: ./gradlew :genadb-android:assembleRelease
// -> genadb-android/build/outputs/aar/setu-android-<version>.aar
// (The Gradle module keeps its pre-rename path so existing builds keep working.)
plugins {
    id("com.android.library")
    kotlin("android")
}

val setuVersion = "1.0.1"

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

// Licence notices travel inside the AAR (issue #6): LICENSE, NOTICE and
// THIRD_PARTY_NOTICES.txt (full licence texts of what libgenadb.so links)
// are packaged as assets/setu-sdk/*, so apps that embed the SDK ship them.
val repoRoot = rootProject.projectDir.resolve("..")
val noticesDir = layout.buildDirectory.dir("generated/setu-notices")
val copyNotices by tasks.registering(Sync::class) {
    group = "build"
    description = "Copies LICENSE, NOTICE and THIRD_PARTY_NOTICES.txt into the AAR's assets"
    from(repoRoot) { include("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.txt") }
    into(noticesDir.map { it.dir("setu-sdk") })
    doLast {
        listOf("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.txt").forEach {
            check(noticesDir.get().dir("setu-sdk").file(it).asFile.isFile) { "$it is missing from the repository root" }
        }
    }
}
android.sourceSets["main"].assets.srcDir(noticesDir)
tasks.named("preBuild") { dependsOn(copyNotices) }

// Publish the release AAR as setu-android-<version>.aar, after checking that
// it carries the notices and both agent ABIs.
val releaseAar = layout.buildDirectory.file("outputs/aar/genadb-android-release.aar")
val namedAar by tasks.registering(Copy::class) {
    from(releaseAar)
    into(layout.buildDirectory.dir("outputs/aar"))
    rename { "setu-android-$setuVersion.aar" }
    doFirst {
        val entries = java.util.zip.ZipFile(releaseAar.get().asFile).use { z -> z.entries().toList().map { it.name }.toSet() }
        val required = listOf("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.txt").map { "assets/setu-sdk/$it" } +
            goTargets.keys.map { "jni/$it/libgenadb.so" }
        val missing = required.filterNot(entries::contains)
        check(missing.isEmpty()) { "release AAR is missing $missing" }
    }
}
tasks.matching { it.name == "assembleRelease" }.configureEach { finalizedBy(namedAar) }
