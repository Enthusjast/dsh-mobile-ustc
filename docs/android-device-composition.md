# APK, Go and DSH device composition

`npm run test:remote-android -- emulator-5580` explicitly selects a dedicated owned AVD for the application-to-service-to-host chain. The default required AVD name is `dsh-remote-api26`; another explicitly owned name can be supplied with `--android-avd`. A normal JVM, Go or Android test invocation does not activate this composition. The test class is selected individually rather than being mistaken for ordinary fixture-peer instrumentation.

Provision that isolated emulator with a secure unlocked test PIN and enrolled strong fingerprint ID 1 before running. The committed runner checks the exact serial/AVD identity and supplies a sensor sample only after the active instrumentation run announces its matching per-use prompt. It does not create a PIN, enroll a fingerprint, or modify unrelated emulator/device settings. This automated mode accepts emulators only; physical-device acceptance remains separate.

Use the repository's pinned npm DSH and installed Go/PostgreSQL/Android tools:

```sh
REMOTE_TEST_GO=/opt/go1.26.10/bin/go \
REMOTE_TEST_PG_BIN=/usr/lib/postgresql/18/bin \
REMOTE_TEST_ADB="$PWD/.local/android-sdk/platform-tools/adb" \
npm run test:remote-android -- emulator-5580
```

The runner builds the debug app/test APKs and host plugin, starts a disposable UTF8 PostgreSQL cluster on a private Unix socket and runs only the opted-in Go device-composition test with race detection. It keeps the full Go race suite separate from the software emulator. The Go test owns another isolated database, a TLS resource handler, a test-only identity issuer and an independently provisioned signed-approval authority. The normal host plugin runs inside installed npm DSH 0.2.1-rc.2 with a private local model/profile/workspace.

The identity fixture stands in for the unavailable school configuration. Its authorization permit is a random per-run secret. It validates the actual public-client parameters, S256 challenge, DPoP key thumbprint, proof signature/method/URI/time/JTI, code verifier and one-use code before issuing signed fixture access/ID tokens. Invalid PKCE, another proof key, missing fixture permission and code/proof reuse are separately rejected. The real Go resource middleware, registered-key proof, scope checks, assurance mapping, control metadata, signed lease and native final guard remain in the path. This does not establish deployed school MFA or browser/SSO behavior.

The APK receives only deployment/CA data, this run's test authorization permit and runtime/session IDs. Input is written with `run-as` into a run-specific `noBackupFilesDir` directory; it is not an Intent, public asset or shared-storage credential file. Neither host credentials/private keys nor pre-generated phone tokens or proof/approval private keys are copied into the APK. The app creates its own non-exportable proof and approval keys, completes its actual PKCE/DPoP exchange, registers the device through a per-use biometric possession proof and opens current authorized directories.

The native test then renders the production Compose route and biometric adapter, submits ordinary chat prompts into DSH, retrieves the resulting exact Bash contexts and selects one allow_once and one reject. Allow requires complete parameter review and explicit unsaved consent. Both decisions use the actual AndroidKeyStore approval key and fresh HTTPS admission. Native settled/denied results are reconciled into the encrypted original records. Controller recreation must restore the same keys, device ID, original request IDs, compact proofs and one attempt per decision without restoring executable callbacks or opening another prompt.

The host harness independently requires exactly one `authorized` append in the allowed file and absence of the rejected file. The Go test checks the actual registered distinct proof/approval thumbprints, one device registration, both accepted native results bound to that device and one authorization-code exchange across recreation. Only public result metadata returns from Android.

The test erases its own account scope and input secret after use. The host runner removes only its run directory and owned `adb reverse` mapping; it never clears all application data. Failed/cancelled instrumentation is stopped on the explicitly selected test AVD. A forced process kill can prevent in-app final cleanup, so the dedicated disposable image remains part of this fixture's failure boundary. No system PostgreSQL, production account, desktop model credential or TokenWorks process participates.

On 2026-10-25 the complete explicit composition passed on the owned API 26 AVD. The Go test completed in 138 seconds (139 seconds including race instrumentation/package completion). All three actual per-use prompts completed: device registration, allow_once and reject. PostgreSQL verified one registered device with distinct native proof/approval thumbprints, two decisions/results bound to that device and one code exchange across controller recreation. The normal DSH host verified the allowed file contained exactly one `authorized` append and the rejected file was absent. The full Kotlin/Go race/DSH regression also passed after the emulator was stopped. The existing 169 JVM tests, lint/APK build and prior complete 96-case application regression remain separate component evidence.

This closes the local API 26 APK-to-Go-to-DSH composition gap for registration, scoped chat, complete approval review, platform signing, native results and encrypted controller recreation. It uses a test authorization grant and an injected test CA in the test APK; it does not prove browser/real-school login, physical hardware policy, host OS credential provisioning, actual process kill/power loss, all Android/desktop platforms, public-network behavior, files/push, capacity or complete M1/M2 acceptance.
