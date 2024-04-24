@Suppress("DSL_SCOPE_VIOLATION") // TODO: Remove once KTIJ-19369 is fixed
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias (libs.plugins.ksp)
}

kotlin {
    jvmToolchain (11)
}

android {
    namespace = "de.tomcory.heimdall.core.datastore"

    defaultConfig {
        compileSdk = 34
        minSdk = 24
    }
}

dependencies {
    api (project(":core:datastore-proto"))
    implementation (libs.androidx.datastore)
    implementation (libs.protobuf.kotlin.lite)
    implementation (libs.hilt.android)
    ksp (libs.dagger.compiler)
    ksp (libs.hilt.compiler)
}
