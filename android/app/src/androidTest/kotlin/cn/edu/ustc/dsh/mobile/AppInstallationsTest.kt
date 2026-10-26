package cn.edu.ustc.dsh.mobile

import android.content.Intent
import android.content.pm.PackageInstaller
import android.net.Uri
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.auth.AppUpdateDeployment
import cn.edu.ustc.dsh.network.PrivateApkCandidate
import cn.edu.ustc.dsh.network.RemoteRequestException
import cn.edu.ustc.dsh.protocol.*
import dagger.hilt.EntryPoints
import kotlinx.coroutines.*
import org.junit.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

/** Only prepares/commits as far as system consent. Never launches or approves the no-code APK. */
@RunWith(AndroidJUnit4::class)
class AppInstallationsTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val verifier = AndroidApkVerifier(context)
    private lateinit var backend: AppInstallations
    private lateinit var slot: String
    private lateinit var original: AndroidApkVerifier.Installed
    private lateinit var originalSessions: Set<Int>
    private lateinit var candidate: PrivateApkCandidate
    private val id = "11111111-1111-4111-8111-111111111111"
    private val hash = "a".repeat(64)
    private val owner = LocalDataOwner(id, id, hash, id, id)
    private val configuration get() = AppUpdateDeployment.parse(JsonDocument.of(jsonObject("v" to 1L.json(), "deployment_sha256" to hash.json(),
        "package_name" to context.packageName.json(), "download_origins" to JsonArray(listOf("https://updates.example.invalid".json())))).canonicalBytes(), hash, context.packageName)
    @Before fun setup() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("networkFixture") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("installerFixture") == "true")
        // Use the same Hilt singleton as the real explicit result receiver.
        val receiver = AppInstallResultReceiver()
        EntryPoints.get(context.applicationContext, AppInstallResultReceiver_GeneratedInjector::class.java).injectAppInstallResultReceiver(receiver)
        backend = receiver.installations
        assertTrue("test driver must grant only REQUEST_INSTALL_PACKAGES app-op", backend.canInstall())
        assertNotEquals(android.content.pm.PackageManager.PERMISSION_GRANTED, context.checkSelfPermission("android.permission.INSTALL_PACKAGES"))
        original = verifier.installed()
        originalSessions = context.packageManager.packageInstaller.mySessions.map { it.sessionId }.toSet()
        assertTrue("test installer must start without other own sessions", originalSessions.isEmpty())
        slot = "apk-installer-${UUID.randomUUID()}"
        val fixture = JsonDocument.parse(instrumentation.context.assets.open("apk-updates/fixtures.json").use { it.readBytes() }).root.obj("fixtures").obj("upgrade")
        val release = AppRelease.parse(jsonObject("release_id" to id.json(), "version_code" to 2L.json(), "version_name" to fixture.string("version_name").json(),
            "package_name" to context.packageName.json(), "sha256" to fixture.string("sha256").json(), "size_bytes" to fixture.integer("size_bytes").json(),
            "signing_cert_sha256" to original.signingCertificate.json(), "download_url" to "https://updates.example.invalid/fixture.apk".json(),
            "minimum_protocol_version" to 1L.json(), "maximum_protocol_version" to 1L.json(), "minimum_android_api" to 26L.json(), "rollout_basis_points" to 10000L.json(), "release_notes" to "Precommit only".json()))
        candidate = PrivateApkCandidate(File(context.cacheDir, "apk-updates"), release)
        candidate.output().use { output -> instrumentation.context.assets.open("apk-updates/" + fixture.string("file")).use { it.copyTo(output) } }
        candidate.seal()
    }
    @After fun cleanup(): Unit = runBlocking {
        if (::candidate.isInitialized) candidate.close()
        if (::slot.isInitialized) {
            backend.read(slot)?.let { backend.cancel(slot, it.record.id) }
            AppInstallationStorage(context, slot).resetAfterSessionCleanup()
        }
        if (::original.isInitialized) assertEquals("candidate must never replace the running app", original, verifier.installed())
        if (::originalSessions.isInitialized) withTimeout(10_000) {
            while (context.packageManager.packageInstaller.mySessions.map { it.sessionId }.toSet() != originalSessions) delay(25)
        }
    }
    private suspend fun prepare() = backend.prepare(slot, id, owner, configuration, candidate, original) {}
    private fun callback(record: AppInstallationRecord, status: Int, session: Int = record.sessionId, nonce: String = record.nonce): Intent =
        Intent(AppInstallations.ACTION).setData(Uri.Builder().scheme(AppInstallations.SCHEME).authority(slot).appendPath(session.toString()).appendPath(nonce).build())
            .putExtra(PackageInstaller.EXTRA_SESSION_ID, session).putExtra(PackageInstaller.EXTRA_STATUS, status)
    private suspend fun pending(): StoredAppInstallation = withTimeout(30_000) {
        while (true) {
            val saved = backend.read(slot)!!
            if (saved.record.phase == AppInstallPhase.WAITING_USER) return@withTimeout saved
            assertEquals("system rejected the fixture before requesting consent", AppInstallPhase.COMMITTING, saved.record.phase)
            delay(50)
        }
        @Suppress("UNREACHABLE_CODE") error("unreachable")
    }
    @Test fun preparationCopiesTheExactBytesIntoOneUnsealedSessionAndBindsTheDurableDigest(): Unit = runBlocking {
        val saved = prepare()
        assertEquals(AppInstallPhase.PREPARED, saved.record.phase); assertEquals(candidate.release.sha256, saved.record.preparedSHA256)
        val info = backend.ownSession(saved.record.sessionId)!!
        assertEquals(context.packageName, info.appPackageName); assertFalse(info.isSealed)
        context.packageManager.packageInstaller.openSession(info.sessionId).use { session ->
            assertEquals(setOf("base.apk"), session.names.toSet())
            // API 26's enforced policy rejects the read FD even before sealing.
            // The product uses the verified write/fsync receipt on every SDK.
            if (Build.VERSION.SDK_INT >= 28) session.openRead("base.apk").use { input ->
                val bytes = input.readBytes()
                assertEquals(candidate.release.sizeBytes, bytes.size.toLong())
                assertEquals(candidate.release.sha256, sha256(bytes))
            }
        }
        assertNull(backend.takePrompt(slot, saved.record))
    }
    @Test fun changedPrivateCandidateBytesAreRejectedBeforeAuthorizationOrCommit(): Unit = runBlocking {
        val saved = prepare()
        val file = candidate.inspectVerified { it }
        assertTrue(file.setWritable(true, true))
        file.writeBytes(file.readBytes().also { it[0] = 0 })
        var authorized = false
        try { backend.commit(slot, id, { authorized = true }) {}; fail("modified candidate was committed") }
        catch (error: RemoteRequestException) { assertEquals("update.integrity_mismatch", error.code) }
        assertFalse(authorized); assertEquals(AppInstallPhase.RETIRED, backend.read(slot)!!.record.phase)
        assertNull(backend.ownSession(saved.record.sessionId))
    }
    @Test fun aReconstructedProcessMustRetireAnUnsubmittedSessionAndPrepareAgain(): Unit = runBlocking {
        val saved = prepare(); var authorized = false
        try { AppInstallations(context).commit(slot, id, { authorized = true }) {}; fail("disk record replaced a live prepared candidate") }
        catch (error: RemoteRequestException) { assertEquals("update.prepare_again", error.code) }
        assertFalse(authorized); assertEquals(AppInstallPhase.RETIRED, backend.read(slot)!!.record.phase)
        assertNull(backend.ownSession(saved.record.sessionId))
    }
    @Test fun lostForegroundOrFreshAuthorityRetiresAnUnsubmittedAttempt(): Unit = runBlocking {
        val saved = prepare()
        try { backend.commit(slot, id, { throw CancellationException("actor retired") }) {}; fail("stale actor committed") }
        catch (_: CancellationException) {}
        assertEquals(AppInstallPhase.RETIRED, backend.read(slot)!!.record.phase)
        assertNull(backend.ownSession(saved.record.sessionId))
    }
    @Test fun mismatchedCallbacksAndSuccessHintsCannotProveAnInstalledUpdate(): Unit = runBlocking {
        val saved = prepare()
        val storage = AppInstallationStorage(context, slot)
        val committing = storage.save(saved.record.transition(AppInstallPhase.COMMITTING, System.currentTimeMillis()), saved.revision)
        backend.receive(callback(committing.record, PackageInstaller.STATUS_SUCCESS, nonce = "B".repeat(42) + "A"))
        backend.receive(callback(committing.record, PackageInstaller.STATUS_SUCCESS, session = committing.record.sessionId + 1))
        assertEquals(committing.revision, backend.read(slot)!!.revision)
        backend.receive(callback(committing.record, PackageInstaller.STATUS_SUCCESS))
        assertEquals(AppInstallPhase.RESULT_REPORTED, backend.read(slot)!!.record.phase)
        assertFalse(backend.installedArtifact(committing.record))
        try { backend.confirmInstalled(slot, id) {}; fail("hint was treated as actual update") }
        catch (error: RemoteRequestException) { assertEquals("update.installation_unknown", error.code) }
    }
    @Test fun aSealedPendingSessionCanBeContinuedExplicitlyWithoutOpeningItsBytesOrCreatingAnotherSession(): Unit = runBlocking {
        val prepared = prepare(); var authorizations = 0
        backend.commit(slot, id, { assertTrue(it.belongsTo(owner, configuration)); authorizations++ }) {}
        val waiting = pending()
        assertEquals(prepared.record.sessionId, waiting.record.sessionId)
        assertTrue(backend.ownSession(waiting.record.sessionId)!!.isSealed)
        val prompt = withTimeout(10_000) {
            var result: Intent? = null
            while (result == null) { result = backend.takePrompt(slot, waiting.record); if (result == null) delay(25) }
            result
        }
        assertNotNull(prompt.component); assertNull(backend.takePrompt(slot, waiting.record))
        assertThrows(SecurityException::class.java) {
            context.packageManager.packageInstaller.openSession(waiting.record.sessionId).use { it.openRead("base.apk").close() }
        }
        // Discard the in-memory prompt, as on process reconstruction. Reopen the
        // journal and explicitly repeat fresh authority on the same sealed ID.
        val reopened = AppInstallations(context)
        reopened.commit(slot, id, { assertTrue(it.sameAttempt(waiting.record)); authorizations++ }) {}
        val again = pending()
        assertTrue(again.revision > waiting.revision)
        assertEquals(2, authorizations)
        assertEquals(setOf(prepared.record.sessionId), context.packageManager.packageInstaller.mySessions.map { it.sessionId }.toSet())
        assertNotNull(withTimeout(10_000) { var result: Intent? = null; while (result == null) { result = backend.takePrompt(slot, again.record); if (result == null) delay(25) }; result })
        assertEquals(original, verifier.installed())
    }
    @Test fun aFailedContinuationPreservesAnAlreadyCommittedAttemptForReconciliation(): Unit = runBlocking {
        val prepared = prepare(); backend.commit(slot, id, {}) {}; val waiting = pending()
        try { backend.commit(slot, id, { throw RemoteRequestException("access.denied") }) {}; fail("revoked actor continued") }
        catch (error: RemoteRequestException) { assertEquals("access.denied", error.code) }
        assertEquals(waiting.revision, backend.read(slot)!!.revision)
        assertNotNull(backend.ownSession(prepared.record.sessionId))
        assertEquals(setOf(prepared.record.sessionId), context.packageManager.packageInstaller.mySessions.map { it.sessionId }.toSet())
    }
    @Test fun aSealedAttemptWithoutDurablePendingConsentCannotBeRecommittedAsAStatusQuery(): Unit = runBlocking {
        val prepared = prepare(); backend.commit(slot, id, {}) {}; val waiting = pending()
        val unknown = AppInstallationStorage(context, slot).save(waiting.record.transition(AppInstallPhase.COMMITTING, System.currentTimeMillis()), waiting.revision)
        backend.takePrompt(slot, waiting.record)
        var authorized = false
        try { backend.commit(slot, id, { authorized = true }) {}; fail("unknown sealed attempt was replayed") }
        catch (error: RemoteRequestException) { assertEquals("update.installation_unknown", error.code) }
        assertFalse(authorized); assertEquals(unknown.revision, backend.read(slot)!!.revision)
        assertNotNull(backend.ownSession(prepared.record.sessionId)); assertFalse(backend.installedArtifact(unknown.record))
    }
    @Test fun thePrivateReceiverRejectsMissingOrNonSystemConsentIntents(): Unit = runBlocking {
        val saved = prepare()
        @Suppress("DEPRECATION") val receiver = context.packageManager.getReceiverInfo(android.content.ComponentName(context, AppInstallResultReceiver::class.java), 0)
        assertFalse(receiver.exported)
        val committing = AppInstallationStorage(context, slot).save(saved.record.transition(AppInstallPhase.COMMITTING, System.currentTimeMillis()), saved.revision)
        backend.receive(callback(committing.record, PackageInstaller.STATUS_PENDING_USER_ACTION))
        backend.receive(callback(committing.record, PackageInstaller.STATUS_PENDING_USER_ACTION).putExtra(Intent.EXTRA_INTENT, Intent(context, MainActivity::class.java)))
        assertEquals(committing.revision, backend.read(slot)!!.revision)
        assertNull(backend.takePrompt(slot, committing.record))
    }
    @Test fun retirementRejectsLateCallbacksAndNeverCreatesAnImplicitReplacement(): Unit = runBlocking {
        val saved = prepare(); backend.cancel(slot, id)
        val retired = backend.read(slot)!!
        backend.receive(callback(saved.record, PackageInstaller.STATUS_SUCCESS))
        assertEquals(retired.revision, backend.read(slot)!!.revision)
        try { backend.commit(slot, id, {}) {}; fail("retired installation was replayed") }
        catch (error: RemoteRequestException) { assertEquals("update.installation_unknown", error.code) }
        assertTrue(context.packageManager.packageInstaller.mySessions.isEmpty())
    }
}
