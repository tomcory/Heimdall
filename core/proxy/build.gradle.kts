@Suppress("DSL_SCOPE_VIOLATION") // TODO: Remove once KTIJ-19369 is fixed
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

kotlin {
    jvmToolchain (11)
}

android {
    namespace = "de.tomcory.heimdall.core.proxy"

    defaultConfig {
        minSdk = 24
        compileSdk = 36
    }

    ndkVersion = "21.0.6113669"

    packaging {
        resources {
            excludes.add("META-INF/INDEX.LIST")
            excludes.add("META-INF/io.netty.versions.properties")
        }
    }

    configurations.configureEach {
        resolutionStrategy {
            force("io.netty:netty-all:${libs.versions.netty.get()}")
        }
    }
}

dependencies {
    // BouncyCastle and Littleshoot
    implementation (libs.bouncycastle.bcprov.jdk15on)
    implementation (libs.bouncycastle.bcpkix.jdk15on)
    implementation (libs.dnssec4j)
    implementation (libs.commons.io)
    implementation (libs.netty.all)
    implementation (libs.okhttp)
    implementation (libs.lightbody.mitm) { exclude(group = "org.slf4j") }
    implementation (libs.jzlib)
    implementation (libs.guava)

    implementation (libs.timber)
    implementation (libs.lifecycle.runtime.ktx)
    implementation (libs.androidx.room.runtime)
    implementation (libs.androidx.room.ktx)

    implementation (project(":core:database"))
    implementation (project(":core:util"))
}