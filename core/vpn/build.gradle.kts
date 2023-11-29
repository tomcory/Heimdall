@Suppress("DSL_SCOPE_VIOLATION") // TODO: Remove once KTIJ-19369 is fixed
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

kotlin {
    jvmToolchain (11)
}

android {
    namespace = "de.tomcory.heimdall.core.vpn"

    defaultConfig {
        compileSdk = 34
        minSdk = 24
    }
}

dependencies {
    implementation (libs.timber)
    implementation (libs.lifecycle.runtime.ktx)

    // Room dependencies
    implementation (libs.androidx.room.ktx)

    implementation (libs.bouncycastle.bcpkix.jdk15on)
    implementation (libs.guava)
    implementation (libs.netty.all) { exclude(group = "org.slf4j") }

    // pcap4j
    implementation (libs.pcap4j.core)
    implementation (libs.pcap4j.packetfactory.static)

    implementation (project(":core:database"))
    implementation (project(":core:util"))
}