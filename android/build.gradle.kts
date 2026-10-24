plugins {
    base
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.kapt) apply false
    alias(libs.plugins.hilt) apply false
    alias(libs.plugins.ksp) apply false
}

subprojects {
    dependencyLocking { lockAllConfigurations() }
}

tasks.named("check") {
    dependsOn(":core:protocol:check", ":core:crypto:check", ":core:auth:check", ":core:session:check", ":core:command:check", ":core:network:check")
    if (findProject(":core:data") != null) dependsOn(":core:data:check")
    if (findProject(":core:keystore") != null) dependsOn(":core:keystore:check")
    if (findProject(":app") != null) dependsOn(":app:check", ":core:ui:check")
}
