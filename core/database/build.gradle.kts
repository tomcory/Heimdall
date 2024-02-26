@Suppress("DSL_SCOPE_VIOLATION") // TODO: Remove once KTIJ-19369 is fixed
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias (libs.plugins.ksp)
    alias (libs.plugins.kotlin.serialization)
}

kotlin {
    jvmToolchain (11)
}

android {
    namespace = "de.tomcory.heimdall.core.database"

    defaultConfig {
        compileSdk = 34
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