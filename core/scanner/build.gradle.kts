@Suppress("DSL_SCOPE_VIOLATION") // TODO: Remove once KTIJ-19369 is fixed
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias (libs.plugins.ksp)
    alias (libs.plugins.hilt)
}

kotlin {
    jvmToolchain (11)
}

android {
    namespace = "de.tomcory.heimdall.core.scanner"

    defaultConfig {
        minSdk = 24
        compileSdk = 36
    }
}

dependencies {
    // Timber
    implementation (libs.timber)

    // Dex analyser used to detect tracker libraries in apps
    implementation (libs.multidexlib2)
    implementation (libs.apk.parser)

    // Retrofit
    implementation (libs.retrofit)
    implementation (libs.retrofit.converter.moshi)

    // Room dependencies
    implementation (libs.androidx.room.runtime)
    implementation (libs.androidx.room.ktx)

    implementation (libs.androidx.datastore)
    implementation (libs.protobuf.javalite)

    implementation (libs.hilt.android)
    ksp (libs.dagger.compiler)
    ksp (libs.hilt.compiler)

    implementation (project(":core:database"))
    implementation (project(":core:datastore"))
    implementation (project(":core:util"))
}