package cn.edu.ustc.dsh.mobile

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.network.LoginHttp
import cn.edu.ustc.dsh.network.PrivateApkCandidate
import cn.edu.ustc.dsh.network.RemoteRequestException
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import okhttp3.*
import okhttp3.mockwebserver.*
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.Buffer
import org.junit.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class AndroidApkVerifierTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val verifier = AndroidApkVerifier(context)
    private lateinit var fixtures: JsonObject
    private lateinit var directory: File
    private lateinit var original: AndroidApkVerifier.Installed
    private lateinit var sessions: Set<Int>
    private val candidates = ArrayList<PrivateApkCandidate>()
    @Before fun setup() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("networkFixture") == "true")
        fixtures = JsonDocument.parse(instrumentation.context.assets.open("apk-updates/fixtures.json").use { it.readBytes() }).root.obj("fixtures")
        directory = File(context.cacheDir, "apk-updates/verification-${UUID.randomUUID()}").also { assertTrue(it.mkdirs()) }
        original = verifier.installed()
        assertEquals(context.packageName, original.packageName)
        assertEquals(fixtures.obj("upgrade").string("actual_signer_sha256"), original.signingCertificate)
        assertNotEquals(original.signingCertificate, fixtures.obj("wrong-signer").string("actual_signer_sha256"))
        sessions = context.packageManager.packageInstaller.mySessions.map { it.sessionId }.toSet()
        assertTrue(context.assets.list("apk-updates").isNullOrEmpty())
    }
    @After fun cleanup() {
        candidates.forEach { it.close() }
        if (::directory.isInitialized) { assertTrue(directory.listFiles()!!.isEmpty()); directory.delete() }
        if (::original.isInitialized) assertEquals(original, verifier.installed())
        if (::sessions.isInitialized) assertEquals(sessions, context.packageManager.packageInstaller.mySessions.map { it.sessionId }.toSet())
    }
    private fun bytes(name: String) = instrumentation.context.assets.open("apk-updates/" + fixtures.obj(name).string("file")).use { it.readBytes() }
    private fun release(name: String, vararg changes: Pair<String, JsonValue>): AppRelease {
        val record = fixtures.obj(name)
        return AppRelease.parse(jsonObject("release_id" to "99999999-9999-4999-8999-999999999999".json(), "version_code" to 2L.json(),
            "version_name" to record.string("version_name").json(), "package_name" to context.packageName.json(), "sha256" to record.string("sha256").json(),
            "size_bytes" to record.integer("size_bytes").json(), "signing_cert_sha256" to original.signingCertificate.json(), "download_url" to "https://updates.example.invalid/fixture.apk".json(),
            "minimum_protocol_version" to 1L.json(), "maximum_protocol_version" to 1L.json(), "minimum_android_api" to record.integer("minimum_android_api").json(),
            "rollout_basis_points" to 10000L.json(), "release_notes" to "Fixture APK inspection; no installation".json()).with(*changes))
    }
    private fun stage(name: String, vararg changes: Pair<String, JsonValue>): PrivateApkCandidate {
        val candidate = PrivateApkCandidate(directory, release(name, *changes))
        try { candidate.output().use { it.write(bytes(name)) }; candidate.seal() }
        catch (error: Exception) { candidate.close(); throw error }
        candidates += candidate
        return candidate
    }
    private fun rejected(candidate: PrivateApkCandidate, code: String? = null) {
        try { verifier.verify(candidate, original); fail("invalid APK passed platform preflight") }
        catch (error: RemoteRequestException) { if (code != null) assertEquals(code, error.code) }
        assertTrue(directory.listFiles()!!.isEmpty())
    }
    @Test fun aRealSameSignerUpgradeHasTheBoundPackageVersionAndCertificate() {
        val candidate = stage("upgrade")
        val proof = verifier.verify(candidate, original)
        assertEquals(2L, proof.versionCode); assertEquals(original.signingCertificate, proof.signingCertificate)
        val output = ByteArrayOutputStream(); candidate.copyVerifiedTo(output); assertArrayEquals(bytes("upgrade"), output.toByteArray())
        assertFalse(proof.toString().contains(directory.path))
    }
    @Test fun recomputingTheHashOfATamperedValidZipCannotReplaceContentSignatureVerification() {
        val candidate = stage("tampered")
        assertNotEquals(fixtures.obj("upgrade").string("sha256"), candidate.release.sha256)
        // Manifest-only parsing succeeds. A certificate-verifying parse must fail.
        val info = candidate.inspectVerified { @Suppress("DEPRECATION") context.packageManager.getPackageArchiveInfo(it.absolutePath, 0) }
        assertNotNull(info); assertEquals(context.packageName, info!!.packageName)
        rejected(candidate, "update.apk_invalid")
    }
    @Test fun aValidArchiveFromAnotherSignerCannotUseTheInstalledSigningAnchor() {
        val candidate = stage("wrong-signer")
        assertEquals(original.signingCertificate, candidate.release.signingCertificate)
        rejected(candidate, "update.identity_mismatch")
    }
    @Test fun anArchiveWithMultipleValidSignersCannotUseOneMatchingCertificate() { rejected(stage("multiple-signers"), "update.apk_invalid") }
    @Test fun aPastCertificateCannotAuthorizeANewCurrentSignerOnRotationAwarePlatforms() {
        val candidate = stage("rotated")
        if (Build.VERSION.SDK_INT >= 28) rejected(candidate, "update.identity_mismatch")
        else {
            // This SDK-targeted fixture still uses the original current signer
            // on 26/27. Those systems do not understand the newer v3 rotation.
            assertEquals(original.signingCertificate, verifier.verify(candidate, original).signingCertificate)
        }
    }
    @Test fun wrongPackageSameVersionDowngradeAndFalseVersionMetadataAreRejected() {
        rejected(stage("wrong-package"), "update.identity_mismatch")
        rejected(stage("same-version"), "update.identity_mismatch")
        rejected(stage("downgrade"), "update.apk_invalid")
        rejected(stage("upgrade", "version_code" to 3L.json()), "update.identity_mismatch")
        rejected(stage("same-version", "version_code" to original.versionCode.json()), "update.identity_mismatch")
    }
    @Test fun metadataCannotIntroduceANewSigningIdentityOrAnUnobservedInstalledVersion() {
        rejected(stage("upgrade", "signing_cert_sha256" to fixtures.obj("wrong-signer").string("actual_signer_sha256").json()), "update.identity_mismatch")
        val candidate = stage("upgrade")
        try { verifier.verify(candidate, original.copy(versionCode = original.versionCode + 1)); fail("unobserved installed snapshot accepted") }
        catch (error: RemoteRequestException) { assertEquals("update.identity_mismatch", error.code) }
    }
    @Test fun protocolAndTheActualManifestSdkFloorMustAgreeWithMetadata() {
        rejected(stage("upgrade", "minimum_protocol_version" to 2L.json(), "maximum_protocol_version" to 2L.json()), "update.incompatible")
        rejected(stage("upgrade", "minimum_android_api" to 27L.json()), "update.incompatible")
        if (Build.VERSION.SDK_INT >= 28) verifier.verify(stage("higher-sdk"), original)
        else rejected(stage("higher-sdk"), "update.incompatible")
    }
    @Test fun aTruncatedArchiveWithMatchingDownloadMetadataIsStillRejected() { rejected(stage("truncated"), "update.apk_invalid") }
    @Test fun aPreviousVerdictCannotBlessBytesReplacedBeforeInstallation() {
        val candidate = stage("upgrade")
        verifier.verify(candidate, original)
        val file = candidate.inspectVerified { it }
        assertTrue(file.setWritable(true, true)); file.writeBytes(bytes("tampered"))
        rejected(candidate, "update.integrity_mismatch")
    }
    @Test fun cancellationRetiresThePrivateCandidateBeforeAnyPlatformOrInstallerResult() {
        val candidate = stage("upgrade")
        try { verifier.verify(candidate, original) { throw CancellationException() }; fail("retired verification returned") } catch (_: CancellationException) {}
        assertTrue(directory.listFiles()!!.isEmpty())
    }
    @Test fun aCandidateOutsideTheApplicationsPrivateUpdateDirectoryCannotBeInspected() {
        val outside = File(context.cacheDir, "unrelated-apk-${UUID.randomUUID()}")
        val candidate = PrivateApkCandidate(outside, release("upgrade"))
        try {
            candidate.output().use { it.write(bytes("upgrade")) }; candidate.seal()
            rejected(candidate, "update.storage_unavailable")
            assertTrue(outside.listFiles()!!.isEmpty())
        } finally { candidate.close(); outside.delete() }
    }
    @Test fun anonymousHttpsDownloadsReachTheSameRealPlatformSignatureGate(): Unit = runBlocking {
        val server = MockWebServer()
        server.protocols = listOf(Protocol.HTTP_1_1)
        val certificate = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
        val tls = HandshakeCertificates.Builder().heldCertificate(certificate).build()
        val trusted = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
        server.useHttps(tls.sslSocketFactory(), false); server.start()
        val transport = OkHttpClient.Builder().sslSocketFactory(trusted.sslSocketFactory(), trusted.trustManager).followRedirects(false).followSslRedirects(false)
            .retryOnConnectionFailure(false).cookieJar(CookieJar.NO_COOKIES).authenticator(Authenticator.NONE).proxyAuthenticator(Authenticator.NONE).build()
        // Test APK only. The production factory retains system TLS trust.
        val http = LoginHttp::class.java.getDeclaredConstructor(OkHttpClient::class.java).apply { isAccessible = true }.newInstance(transport)
        val origin = server.url("/").toString().trimEnd('/')
        try {
            for (name in listOf("upgrade", "tampered")) {
                val response = MockResponse().setHeader("Content-Type", "application/vnd.android.package-archive")
                server.enqueue(if (name == "upgrade") response.setChunkedBody(Buffer().write(bytes(name)), 1024) else response.setBody(Buffer().write(bytes(name))))
                val metadata = release(name, "download_url" to server.url("/candidate.apk").toString().json())
                val candidate = http.downloadAppRelease(metadata, setOf(origin), directory).also { candidates += it }
                if (name == "upgrade") { verifier.verify(candidate, original); candidate.close() } else rejected(candidate, "update.apk_invalid")
                val request = server.takeRequest(); assertEquals("GET", request.method)
                for (header in listOf("Authorization", "DPoP", "Cookie")) assertNull(request.getHeader(header))
            }
        } finally { server.shutdown() }
    }
}
