plugins {
    base
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.android.library) apply false
}

subprojects {
    dependencyLocking { lockAllConfigurations() }
}

tasks.named("check") {
    dependsOn(":core:protocol:check", ":core:crypto:check")
    if (findProject(":core:keystore") != null) dependsOn(":core:keystore:check")
}
