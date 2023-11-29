pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

plugins {
    id ("org.gradle.toolchains.foojay-resolver-convention") version "0.4.0"
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri("https://jitpack.io")
            name = "Jitpack"
        }
    }
}

rootProject.name = "Heimdall"

include (":app")
include(":core:database")
include (":core:datastore")
include (":core:datastore-proto")
include(":core:export")
include(":core:vpn")
include(":core:util")
include(":core:proxy")
include(":core:scanner")
