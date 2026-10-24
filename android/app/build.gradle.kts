plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.kapt)
    alias(libs.plugins.hilt)
}

val deploymentAssets = layout.buildDirectory.dir("generated/deploymentAssets")
val deploymentSource = providers.gradleProperty("deploymentConfig")
val prepareDeployment by tasks.registering {
    inputs.property("configuration", deploymentSource.orElse("<absent>"))
    deploymentSource.orNull?.let { inputs.file(rootProject.file(it)) }
    outputs.dir(deploymentAssets)
    if (deploymentSource.isPresent) dependsOn(":core:auth:validateDeployment")
    doLast {
        val directory = deploymentAssets.get().asFile
        // A build without configuration must also remove a previous build's asset.
        directory.deleteRecursively()
        directory.mkdirs()
        if (deploymentSource.isPresent) {
            val input = rootProject.file("core/auth/build/generated/validatedDeployment/deployment.json")
            check(input.isFile && input.length() <= 128 * 1024) { "Invalid public deployment configuration file" }
            input.copyTo(directory.resolve("deployment.json"))
        }
    }
}

android {
    namespace = "cn.edu.ustc.dsh.mobile"
    compileSdk = 36
    buildToolsVersion = "35.0.0"
    defaultConfig {
        applicationId = "cn.edu.ustc.dsh.mobile"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-dev"
        manifestPlaceholders["appAuthRedirectScheme"] = "cn.edu.ustc.dsh.mobile"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testInstrumentationRunnerArguments["accountFixture"] = providers.gradleProperty("accountFixture").orElse("false").get()
        testInstrumentationRunnerArguments["networkFixture"] = providers.gradleProperty("networkFixture").orElse("false").get()
    }
    buildFeatures { compose = true; buildConfig = true }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    sourceSets.getByName("main").assets.srcDir(deploymentAssets)
}
tasks.named("preBuild") { dependsOn(prepareDeployment) }
kotlin { jvmToolchain(17) }
kapt { correctErrorTypes = true }
dependencies {
    implementation(project(":core:auth"))
    implementation(project(":core:network"))
    implementation(project(":core:keystore"))
    implementation(project(":core:data"))
    implementation(project(":core:ui"))
    implementation(libs.activity.compose)
    implementation(libs.activity.ktx)
    implementation(libs.lifecycle.compose)
    implementation(libs.lifecycle.viewmodel)
    implementation(libs.coroutines.android)
    implementation(libs.androidx.browser)
    implementation(libs.appauth)
    implementation(libs.hilt.android)
    kapt(libs.hilt.compiler)
    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.okhttp.mockwebserver)
    androidTestImplementation(libs.okhttp.tls)
    androidTestImplementation(libs.nimbus.jose)
    debugImplementation(libs.compose.ui.test.manifest)
}
