plugins {
    `java-library`
    alias(libs.plugins.kotlin.jvm)
}

kotlin { jvmToolchain(17) }

dependencies {
    implementation(libs.jackson.core)
    implementation(libs.jcs)
    testImplementation(libs.junit)
}

tasks.test {
    inputs.dir(rootProject.file("../contracts/ws/v1"))
    inputs.dir(rootProject.file("../contracts/security"))
    inputs.dir(rootProject.file("../contracts/files/v1"))
    inputs.dir(rootProject.file("../contracts/push/v1"))
    inputs.file(rootProject.file("../contracts/golden/app-release-selection.json"))
    systemProperty("contracts.root", rootProject.file("../contracts").absolutePath)
}
