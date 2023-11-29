@Suppress("DSL_SCOPE_VIOLATION") // TODO: Remove once KTIJ-19369 is fixed
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

kotlin {
    jvmToolchain (11)
}

android {
    namespace = "de.tomcory.heimdall.core.export"

    defaultConfig {
        compileSdk = 34
    }
}

dependencies {
    implementation (libs.lifecycle.runtime.ktx)

    // Kotlin serialisation
    implementation (libs.kotlinx.serialization.json)

    implementation (project(":core:database"))
}