import com.google.protobuf.gradle.proto

@Suppress("DSL_SCOPE_VIOLATION") // TODO: Remove once KTIJ-19369 is fixed

plugins {
    id ("com.android.library")
    id ("org.jetbrains.kotlin.android")
    alias (libs.plugins.protobuf)
}

kotlin {
    jvmToolchain (11)
}

android {
    namespace = "de.tomcory.heimdall.core.datastore.proto"

    defaultConfig {
        compileSdk = 34
    }

    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/proto")
        }
    }
}

// Setup protobuf configuration, generating lite Java and Kotlin classes
protobuf {
    protoc {
        artifact = libs.protobuf.protoc.get().toString()
    }

    generateProtoTasks {
        all().forEach { task ->
            task.builtins {
                register("java") {
                    option("lite")
                }
                register("kotlin") {
                    option("lite")
                }
            }
        }
    }
}

dependencies {
    implementation(libs.protobuf.kotlin.lite)
}