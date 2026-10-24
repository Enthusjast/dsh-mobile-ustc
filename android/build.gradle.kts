plugins {
    base
    alias(libs.plugins.kotlin.jvm) apply false
}

subprojects {
    dependencyLocking { lockAllConfigurations() }
}

tasks.named("check") {
    dependsOn(":core:protocol:check", ":core:crypto:check")
}
