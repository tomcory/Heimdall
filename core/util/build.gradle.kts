@Suppress("DSL_SCOPE_VIOLATION") // TODO: Remove once KTIJ-19369 is fixed
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

kotlin {
    jvmToolchain (11)
}

android {
    namespace = "de.tomcory.heimdall.core.util"

    defaultConfig {
        minSdk = 24
        compileSdk = 36
    }
}

dependencies {
    implementation (libs.androidx.legacy.support.v4)
    implementation (libs.lifecycle.runtime.ktx)

    // Timber
    implementation (libs.timber)
}