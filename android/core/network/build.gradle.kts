plugins {
    `java-library`
    alias(libs.plugins.kotlin.jvm)
}

val fixtureClasspath = layout.buildDirectory.file("fixtures/classpath.txt")
tasks.register("writeFixtureClasspath") {
    dependsOn(tasks.testClasses)
    inputs.files(sourceSets.test.get().runtimeClasspath)
    outputs.file(fixtureClasspath)
    doLast {
        fixtureClasspath.get().asFile.apply { parentFile.mkdirs(); writeText(sourceSets.test.get().runtimeClasspath.asPath) }
    }
}
kotlin { jvmToolchain(17) }
dependencies {
    api(project(":core:auth"))
    api(project(":core:session"))
    api(project(":core:command"))
    implementation(libs.okhttp)
    api(libs.coroutines.core)
    testImplementation(libs.junit)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.okhttp.tls)
    testImplementation(libs.nimbus.jose)
}
tasks.test {
    inputs.dir(rootProject.file("../contracts/ws/v1"))
    inputs.file(rootProject.file("../contracts/golden/app-release-selection.json"))
    systemProperty("contracts.root", rootProject.file("../contracts").absolutePath)
}
