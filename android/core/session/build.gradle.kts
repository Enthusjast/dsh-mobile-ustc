plugins {
    `java-library`
    alias(libs.plugins.kotlin.jvm)
}
kotlin { jvmToolchain(17) }
dependencies {
    api(project(":core:protocol"))
    implementation(libs.jackson.core)
    testImplementation(libs.junit)
}
tasks.test {
    inputs.dir(rootProject.file("../contracts/ws/v1"))
    inputs.file(rootProject.file("../contracts/security/approval-signatures.json"))
    systemProperty("contracts.root", rootProject.file("../contracts").absolutePath)
}
