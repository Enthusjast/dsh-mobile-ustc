plugins {
    `java-library`
    alias(libs.plugins.kotlin.jvm)
}

kotlin { jvmToolchain(17) }

dependencies {
    api(project(":core:protocol"))
    implementation(libs.nimbus.jose)
    testImplementation(libs.junit)
}

tasks.test {
    inputs.dir(rootProject.file("../contracts/security"))
    systemProperty("contracts.root", rootProject.file("../contracts").absolutePath)
}

tasks.register<JavaExec>("generateInteropVectors") {
    group = "verification"
    description = "Regenerate public-only JCA-signed decisions for Go/Node interoperability."
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("cn.edu.ustc.dsh.crypto.GenerateInteropVectors")
    args(rootProject.file("../contracts/security/approval-signatures.json").absolutePath,
        rootProject.file("../contracts/security/approval-kotlin-signatures.json").absolutePath)
}
