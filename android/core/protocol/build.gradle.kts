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
    inputs.dir(rootProject.file("../contracts/security"))
    inputs.dir(rootProject.file("../contracts/files/v1"))
    systemProperty("contracts.root", rootProject.file("../contracts").absolutePath)
}
