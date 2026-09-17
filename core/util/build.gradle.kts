@Suppress("DSL_SCOPE_VIOLATION") // TODO: Remove once KTIJ-19369 is fixed
plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "de.tomcory.heimdall.core.util"

    defaultConfig {
        minSdk = 24
        compileSdk = 36
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    implementation (libs.androidx.legacy.support.v4)
    implementation (libs.lifecycle.runtime.ktx)

    // Timber
    implementation (libs.timber)
}