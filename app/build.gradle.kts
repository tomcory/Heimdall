@Suppress("DSL_SCOPE_VIOLATION") // TODO: Remove once KTIJ-19369 is fixed
plugins {
    id ("com.android.application")
    id ("org.jetbrains.kotlin.android")
    alias (libs.plugins.protobuf)
    alias (libs.plugins.ksp)
    alias (libs.plugins.kotlin.serialization)
    alias (libs.plugins.hilt)
}

kotlin {
    jvmToolchain (11)
}

android {
    namespace = "de.tomcory.heimdall"

    defaultConfig {
        applicationId = "de.tomcory.heimdall"
        minSdk = 24
        compileSdk = 34
        targetSdk = 34

        versionCode = 1
        versionName = "0.1"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        vectorDrawables {
            useSupportLibrary = true
        }

        /* val secureProps = Properties()
           val securePropsFile = file("../secure.properties")
           if (securePropsFile.exists()) {
               secureProps.load(securePropsFile.inputStream())
           }
           resValue("string", "maps_api_key", secureProps.getProperty("EXAMPLE", "")) */
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = "11"
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    composeOptions {
        kotlinCompilerExtensionVersion = libs.versions.compose.compiler.get()
    }

    ndkVersion = "21.0.6113669"
}

dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar"))))

    // AndroidX compatibility library
    implementation (libs.androidx.legacy.support.v4)
    implementation (libs.androidx.appcompat)
    implementation (libs.androidx.constraintlayout)
    implementation (libs.androidx.preference.ktx)
    implementation (libs.androidx.palette.ktx)

    // AndroidX Lifecycle Components
    implementation (libs.lifecycle.livedata.ktx)
    implementation (libs.lifecycle.viewmodel.ktx)
    implementation (libs.lifecycle.runtime.ktx)
    implementation (libs.lifecycle.common.java8)
    implementation (libs.lifecycle.runtime.compose)

    // Jetpack Compose Base
    implementation (libs.activity.compose)
    implementation (libs.androidx.ui)
    implementation (libs.androidx.ui.tooling.preview)
    debugImplementation (libs.androidx.ui.tooling)
    debugImplementation (libs.ui.test.manifest)
    androidTestImplementation (libs.ui.test.junit4)

    // Jetpack Compose Material 3
    implementation (libs.androidx.compose.material3)
    implementation (libs.androidx.compose.material3.windowsizeclass)

    // Jetpack Compose Addons
    implementation (libs.accompanist.drawablepainter)
    implementation (libs.accompanist.systemuicontroller)

    // Jetpack DataStore TODO: REFACTOR ACCESS TO ENABLE DEPENDENCY REMOVAL
    implementation (libs.androidx.datastore)
    implementation (libs.protobuf.javalite)

    // Hilt dependency injection
    implementation (libs.hilt.android)
    ksp (libs.dagger.compiler)
    ksp (libs.hilt.compiler)
    implementation (libs.androidx.hilt.navigation.compose)

    // Vico Charts for Jetpack Compose https://github.com/patrykandpatrick/vico
    implementation (libs.vico.compose)
    implementation (libs.vico.composem3)
    implementation (libs.vico.core)

    // Kotlin serialisation
    implementation (libs.kotlinx.serialization.json)

    // Room dependencies
    implementation (libs.androidx.room.runtime)
    implementation (libs.androidx.room.ktx)
    ksp (libs.androidx.room.compiler)

    // Navigation
    implementation (libs.androidx.navigation.fragment.ktx)
    implementation (libs.androidx.navigation.ui.ktx)
    implementation (libs.androidx.navigation.compose)

    // Dex analyser used to detect tracker libraries in apps
    implementation (libs.multidexlib2)
    implementation (libs.apk.parser)

    // Dependencies for the evaluator
    implementation (libs.jsoup)
    implementation (libs.okhttp)
    implementation (libs.gson)

    // various UI libraries
    implementation (libs.mpAndroidChart)

    // Timber
    implementation (libs.timber)

    // test stuff
    testImplementation (libs.junit)
    androidTestImplementation (libs.androidx.test.junit)
    androidTestImplementation (libs.androidx.test.core)
    androidTestImplementation (libs.androidx.test.runner)
    androidTestImplementation (libs.androidx.test.rules)
    androidTestImplementation (libs.androidx.espresso.core)
    testImplementation (libs.robolectric)

    // project modules
    implementation (project(":core:database"))
    implementation (project(":core:datastore"))
    implementation (project(":core:export"))
    implementation (project(":core:proxy"))
    implementation (project(":core:scanner"))
    implementation (project(":core:util"))
    implementation (project(":core:vpn"))
}