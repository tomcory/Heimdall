@Suppress("DSL_SCOPE_VIOLATION") // TODO: Remove once KTIJ-19369 is fixed
plugins {
    alias(libs.plugins.android.library)
    alias (libs.plugins.ksp)
    alias (libs.plugins.kotlin.serialization)
}

android {
    namespace = "de.tomcory.heimdall.core.database"

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
    // Kotlin serialisation
    implementation (libs.kotlinx.serialization.json)

    // Room dependencies
    implementation (libs.androidx.room.runtime)
    implementation (libs.androidx.room.ktx)
    implementation (libs.hilt.android)
    ksp (libs.androidx.room.compiler)
    ksp (libs.dagger.compiler)
    ksp (libs.hilt.compiler)
}