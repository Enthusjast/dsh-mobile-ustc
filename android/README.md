# Android development

The Android tree starts with two Android-compatible JVM modules: `:core:protocol` owns strict bounded JSON, RFC 8785 canonicalization and complete approval contexts/decisions; `:core:crypto` owns registered P-256 public keys, ES256 verification and canonical approval signing preparation. This first slice does not contain an APK, login, Keystore, transport, cache or UI yet. It establishes shared bytes and signatures before connecting those platform components.

Run from this directory with JDK 17 or 21:

```sh
./gradlew check
```

Or run `npm run test:android` from the repository root. No Android SDK is required for these two JVM modules. Kotlin is pinned to 2.3.21 and the Gradle wrapper to 8.14.5 with the published distribution SHA-256. Dependencies use Maven Central/Google and exact versions; generated lockfiles and SHA-256 verification metadata are committed. Verification metadata records the initial downloads; it is not a claim that an independent signature or vulnerability review was completed. Update locks/checksums deliberately when changing dependencies. The Kotlin/Gradle compatibility table is in the [Kotlin Gradle documentation](https://kotlinlang.org/docs/gradle-configure-project.html).

`JsonDocument` uses Jackson Core 2.20.1 for a strict UTF-8, duplicate-name and syntax preflight, then the erdtman JCS 1.1 implementation for ECMAScript number formatting and UTF-16 property ordering. The JCS library's parser alone accepts some duplicate-null names and nonstandard number forms, so it is never the validation boundary. Both parsed and generated objects enforce 128 KiB, 32 levels, 16,384 nodes and scalar Unicode. Parsed object/array containers are copied and immutable. Errors omit input text and parser causes.

Approval contexts require every exact field, enrolled identifiers, current millisecond UTC times, unique resource facts and canonical 32-byte nonces. The binding includes full arguments and resources. Decisions allow only `allow_once` or `reject`; both bind all execution/identity/policy/nonce facts, have at most the request's expiry and use the same 30-second issue freshness and five-second future clock limit as Go/TypeScript. No signing API accepts a caller-provided binding hash in place of the context.

Crypto uses Nimbus JOSE+JWT 10.5 for ES256 verification and DER/JOSE conversion. The registered key is independently supplied; embedded private material, caller keys, remote key URLs, unknown/aliased fields, wrong purpose and noncanonical JOSE/JSON bytes are rejected. `ApprovalSignatures.prepare` creates complete immutable signing bytes before a platform prompt. `PreparedApprovalSignature.finishDerSignature` converts a JCA `SHA256withECDSA` DER result to the 64-byte JOSE form, independently verifies it and rechecks expiry. Cancellation or one completion ends that operation. These objects are ephemeral and must not be restored across process death or authority changes. This is content signing, not a replacement for current server authorization or the host's one-use execution journal.

Tests consume the same `contracts/security/jcs-vectors.json` and `approval-signatures.json` as Go/TypeScript. `approval-kotlin-signatures.json` adds public-only Kotlin/JCA allow, reject, altered-choice and raw-DER vectors; all three languages verify those vectors. Regenerate deliberately:

```sh
./gradlew :core:crypto:generateInteropVectors
```

Fresh private keys exist only in the generator's process memory. Regeneration changes public keys/signatures and writes the public fixture; it does not modify schema or lease fixtures. Rerun `./gradlew check`, `npm run verify` and `go test -race -count=1 ./...` in `services/remote` after changing shared vectors. Go test caching must be disabled because the fixtures live outside its module.

Still required: Android Keystore and per-use biometric signing, separate DPoP/proof keys, school PKCE/OIDC configuration and ID-token verification, current authenticated HTTPS/WSS transport, complete-context review, account/runtime-isolated encrypted caching, command reconciliation, Compose screens and device/process/network tests. A JVM pass establishes protocol/crypto interoperability only; it does not establish Android API compatibility, hardware key policy, real school identity, M1 or M2 acceptance.
