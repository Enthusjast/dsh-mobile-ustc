# Android Keystore integration evidence

On 2026-10-24, the Android modules passed shared JVM tests, Android lint, AAR/test-APK builds and four instrumented tests on an isolated AOSP Android 8.0 / API 26 x86_64 emulator. The biometric test was explicitly enabled and all four tests passed with no skipped cases. This is an Android runtime and provider test; no school identity, real phone, production hardware attestation or complete mobile app was involved.

The build pins JDK target 17, Kotlin 2.3.21, AGP 8.13.2, Gradle 8.14.5, compileSdk 36, Build Tools 35.0.0 and minSdk 26. AndroidX Biometric is pinned to 1.1.0. The local emulator used version 37.2.12 with software CPU/graphics because the current account cannot access KVM. SDK, image, emulator state, logs and build outputs remain outside Git. The SDK Command-line Tools 22.0 archive's SHA-256 was checked against the official download entry before extraction. No system PostgreSQL or TokenWorks process was used for this Android test.

The shared JVM suites verify the Go/Node approval vectors and the public-only Kotlin/JCA vectors in both directions. Android tests use the same protocol/crypto classes, not substitutes:

- Proof keys persist in AndroidKeyStore, expose no private encoding, have different thumbprints across account/organization scopes and produce 64-byte JOSE ECDSA signatures that verify with the platform public key. The recomputed JWK thumbprint matches.
- Deletion fences existing handles. Loading a deleted key fails without creating a replacement. Explicit re-enrollment creates a different key. Closing an account's key owner prevents its old handles from signing while leaving persistent enrollment under explicit lifecycle control.
- Approval-key enrollment fails without a secure lock/enrolled strong biometric and creates no fallback key. This branch passed on the initial unconfigured emulator. After a fixture PIN and fingerprint were enrolled through Settings, the provider denied signing without authentication. API 26 reports this at `sign()` through `SignatureException`, while some providers reject at `initSign()` with `UserNotAuthenticatedException`.
- A real AndroidX BiometricPrompt CryptoObject successfully authenticated separate allow and reject operations. Each actual AndroidKeyStore signature was DER→JOSE converted and independently verified against the full context, registered public key and current time. Cancelled operations reinitialized the old Signature and could not sign; completed operations could not be reused.

Run static/JVM checks and build the test APK:

```sh
cd android
./gradlew check :core:keystore:assembleDebugAndroidTest
```

Run the three noninteractive platform tests on an explicitly selected test device. The interactive test is skipped unless opted in:

```sh
ANDROID_SERIAL=<test-serial> ./gradlew :core:keystore:connectedDebugAndroidTest
```

For the complete four-test run, provision a dedicated device/emulator with a test screen lock and enrolled strong biometric, then enable the UI test and confirm its two prompts:

```sh
ANDROID_SERIAL=<test-serial> ./gradlew :core:keystore:connectedDebugAndroidTest -PbiometricFixture=true
```

The local fixture used a private API 26 AVD on `emulator-5580`. Fingerprint enrollment followed the system Security & Location → Fingerprint UI; emulator sensor samples used fingerprint ID 1. Test sensor injection was restricted to the exact AVD created for this task. A real device requires its user's biometric confirmation. The instrumentation code does not enroll fingerprints, change a device PIN, or automatically confirm unrelated authentication prompts. The test-only activity and fixtures are absent from the published library.

Generated reports are under `android/core/keystore/build/reports/androidTests/connected/debug`; the APK is `android/core/keystore/build/outputs/apk/androidTest/debug/keystore-debug-androidTest.apk`. It is an instrumentation APK, not a foreground remote-control client or release artifact. A normal build/test pass does not run device tests automatically. SDK-free shared checks remain available through `./gradlew -PjvmOnly=true check`.

The application must still map scopes from trusted account/organization state, register the separate public keys, build DPoP and Relay proofs, wire account/revocation/prompt cleanup, show the full approval context and send decisions through fresh authorized HTTPS admission. Platform authentication proves local key use; it cannot supply school MFA/ACR or grant execution authority. Strong-biometric policy is currently supported; device-credential alternatives must be explicitly designed and verified before being offered. Modern Android branches, biometric enrollment/credential changes, hardware-required policy/attestation, process death, backup/restore, network/account switching and physical target devices remain acceptance gates. M1/M2 are not complete.
