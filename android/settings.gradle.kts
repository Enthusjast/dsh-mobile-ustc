pluginManagement {
    repositories { gradlePluginPortal(); google(); mavenCentral() }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}

rootProject.name = "dsh-mobile"
include(":core:protocol", ":core:crypto")
if (providers.gradleProperty("jvmOnly").orNull != "true") include(":core:keystore")
