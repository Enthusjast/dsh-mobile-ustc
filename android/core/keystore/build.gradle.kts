plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "cn.edu.ustc.dsh.keystore"
    compileSdk = 36
    buildToolsVersion = "35.0.0"
    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testInstrumentationRunnerArguments["biometricFixture"] = providers.gradleProperty("biometricFixture").orElse("false").get()
        testInstrumentationRunnerArguments["vaultFixture"] = providers.gradleProperty("vaultFixture").orElse("false").get()
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions { animationsDisabled = true }
    sourceSets.getByName("androidTest").assets.srcDir(rootProject.file("../contracts/security"))
}

kotlin { jvmToolchain(17) }

dependencies {
    api(project(":core:crypto"))
    implementation(libs.nimbus.jose)
    api(libs.androidx.biometric)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.androidx.test.core)
}
