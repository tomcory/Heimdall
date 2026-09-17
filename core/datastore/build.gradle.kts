@Suppress("DSL_SCOPE_VIOLATION") // TODO: Remove once KTIJ-19369 is fixed
plugins {
    alias(libs.plugins.android.library)
    alias (libs.plugins.ksp)
}

android {
    namespace = "de.tomcory.heimdall.core.datastore"

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
    api (project(":core:datastore-proto"))
    implementation (libs.androidx.datastore)
    implementation (libs.protobuf.kotlin.lite)
    implementation (libs.hilt.android)
    ksp (libs.dagger.compiler)
    ksp (libs.hilt.compiler)
}
