package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.auth.AppUpdateDeployment
import cn.edu.ustc.dsh.protocol.*
import dagger.hilt.EntryPoints
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import org.junit.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

/** Real TLS/OIDC/DPoP, private download, platform verifier and installer; no candidate is approved. */
@RunWith(AndroidJUnit4::class)
class AccountAppUpdateTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private var fixture: AccountFixture? = null
    private var controller: LoginController? = null
    private lateinit var backend: AppInstallations
    private lateinit var original: AndroidApkVerifier.Installed
    private lateinit var sessions: Set<Int>
    private lateinit var configuration: AppUpdateDeployment
    private lateinit var environment: LoginEnvironment
    private fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
    private fun await(test: () -> Boolean) {
        val end = android.os.SystemClock.elapsedRealtime() + 60_000
        while (android.os.SystemClock.elapsedRealtime() < end) { if (test()) return; Thread.sleep(25) }
        throw AssertionError("update fixture timed out: ${controller?.state?.value?.phase}; ${controller?.state?.value?.appUpdates}; fixture=${fixture?.failure?.get()}; download=${fixture?.appUpdateDownloadFailure?.get()}; flow=${fixture?.appUpdateFlowFailure?.get()}")
    }
    @Before fun setup() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("accountFixture") == "true" && args.getString("networkFixture") == "true" && args.getString("installerFixture") == "true")
        assertTrue(context.getSystemService(KeyguardManager::class.java).let { it.isDeviceSecure && !it.isDeviceLocked })
        val receiver = AppInstallResultReceiver()
        EntryPoints.get(context.applicationContext, AppInstallResultReceiver_GeneratedInjector::class.java).injectAppInstallResultReceiver(receiver)
        backend = receiver.installations; assertTrue(backend.canInstall())
        original = AndroidApkVerifier(context).installed()
        sessions = context.packageManager.packageInstaller.mySessions.map { it.sessionId }.toSet(); assertTrue(sessions.isEmpty())
        fixture = AccountFixture(context).also { it.appUpdateMode = true; it.seed(ttlSeconds = 600) }
        val server = fixture!!
        configuration = AppUpdateDeployment.parse(JsonDocument.of(jsonObject("v" to 1L.json(), "deployment_sha256" to server.config.fingerprint.json(), "package_name" to context.packageName.json(),
            "download_origins" to JsonArray(listOf(server.origin.json())))).canonicalBytes(), server.config.fingerprint, context.packageName)
        environment = server.environment(appUpdateConfiguration = { configuration.bytes() })
        candidate("upgrade")
        main { controller = LoginController(context, server.http, environment, installations = backend); controller!!.foreground(true) }
        await { controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing } }
    }
    @After fun cleanup(): Unit = runBlocking {
        main { controller?.close() }
        fixture?.let { server ->
            if (::backend.isInitialized) backend.read(server.slot)?.let { backend.cancel(server.slot, it.record.id) }
            AppInstallationStorage(context, server.slot).resetAfterSessionCleanup()
            assertNull(server.failure.get()); server.close()
        }
        if (::original.isInitialized) assertEquals(original, AndroidApkVerifier(context).installed())
        if (::sessions.isInitialized) withTimeout(10_000) {
            while (context.packageManager.packageInstaller.mySessions.map { it.sessionId }.toSet() != sessions) delay(25)
        }
    }
    private fun candidate(name: String) {
        val server = fixture!!
        val metadata = JsonDocument.parse(instrumentation.context.assets.open("apk-updates/fixtures.json").use { it.readBytes() }).root.obj("fixtures").obj(name)
        server.appUpdateBytes = instrumentation.context.assets.open("apk-updates/" + metadata.string("file")).use { it.readBytes() }
        server.appUpdateRelease = AppRelease.parse(jsonObject("release_id" to UUID.randomUUID().toString().json(), "version_code" to 2L.json(), "version_name" to metadata.string("version_name").json(),
            "package_name" to context.packageName.json(), "sha256" to metadata.string("sha256").json(), "size_bytes" to metadata.integer("size_bytes").json(),
            "signing_cert_sha256" to original.signingCertificate.json(), "download_url" to (server.origin + "/app-updates/candidate.apk").json(), "minimum_protocol_version" to 1L.json(),
            "maximum_protocol_version" to 1L.json(), "minimum_android_api" to 26L.json(), "rollout_basis_points" to 10000L.json(), "release_notes" to "Account-scoped fixture; do not approve installation".json()))
    }
    private fun available() {
        main { controller!!.openAppUpdates() }
        await { controller!!.state.value.appUpdates?.let { !it.busy && it.phase == AppUpdatePhase.AVAILABLE } == true }
    }
    private fun prepared() {
        available(); main { controller!!.downloadAppUpdate() }
        await { controller!!.state.value.appUpdates?.let { !it.busy && it.phase == AppUpdatePhase.PREPARED } == true }
    }
    @Test fun withdrawingThePublicationAfterPreparationPreventsCommitAndKeepsTheReasonVisible(): Unit = runBlocking {
        prepared(); val server = fixture!!
        val session = backend.read(server.slot)!!.record.sessionId
        assertEquals(1, server.appUpdateDownloads.get()); assertTrue(server.appUpdateQueries.get() >= 2)
        server.appUpdateRelease = null
        main { controller!!.installAppUpdate() }
        await { controller!!.state.value.appUpdates?.let { !it.busy && it.error == "update.publication_changed" } == true }
        assertEquals(AppInstallPhase.RETIRED, backend.read(server.slot)!!.record.phase); assertNull(backend.ownSession(session))
        assertNull(withTimeoutOrNull(150) { controller!!.appUpdateEvents.first() })
    }
    @Test fun leavingTheForegroundRetiresPreparedBytesAndNeverRestoresAnOldInstallAction(): Unit = runBlocking {
        prepared(); val server = fixture!!; val before = backend.read(server.slot)!!.record
        main { controller!!.foreground(false) }
        await { runBlocking { backend.read(server.slot)!!.record.phase == AppInstallPhase.RETIRED } }
        assertNull(controller!!.state.value.appUpdates); assertTrue(controller!!.state.value.appUpdateSettings)
        assertNull(backend.ownSession(before.sessionId)); assertTrue(File(context.cacheDir, "apk-updates").listFiles().isNullOrEmpty())
        main { controller!!.foreground(true) }
        await { controller!!.state.value.appUpdates?.let { !it.busy } == true }
        assertNotEquals(AppUpdatePhase.PREPARED, controller!!.state.value.appUpdates!!.phase)
        assertEquals(1, server.appUpdateDownloads.get())
    }
    @Test fun aLateAuthenticatedMetadataResponseCannotRestoreALoggedOutPage() {
        val server = fixture!!; server.holdAppUpdateMetadata = true
        main { controller!!.openAppUpdates() }; await { server.appUpdateQueries.get() == 1 }
        main { controller!!.cancel() }; await { controller!!.state.value.phase == HomePhase.SIGNED_OUT }
        Thread.sleep(2200)
        assertFalse(controller!!.state.value.appUpdateSettings); assertNull(controller!!.state.value.appUpdates)
        assertEquals(0, server.appUpdateDownloads.get())
    }
    @Test fun logoutDuringTheFinalPublicationCheckRetiresTheUnsubmittedSession(): Unit = runBlocking {
        prepared(); val server = fixture!!; val before = backend.read(server.slot)!!.record
        val queries = server.appUpdateQueries.get(); server.holdAppUpdateMetadata = true
        main { controller!!.installAppUpdate() }
        await { server.appUpdateQueries.get() > queries }
        main { controller!!.cancel() }; await { controller!!.state.value.phase == HomePhase.SIGNED_OUT }
        await { runBlocking { backend.read(server.slot)!!.record.phase == AppInstallPhase.RETIRED } }
        assertNull(backend.ownSession(before.sessionId)); assertNull(withTimeoutOrNull(150) { controller!!.appUpdateEvents.first() })
        assertNull(controller!!.state.value.appUpdates); assertFalse(controller!!.state.value.appUpdateSettings)
    }
    @Test fun aTamperedArchiveCannotReachSessionPreparationEvenWithMatchingMetadataHash(): Unit = runBlocking {
        val repeats = InstrumentationRegistry.getArguments().getString("apkTamperRepeat")?.toInt() ?: 1
        require(repeats in 1..20)
        candidate("tampered"); available()
        repeat(repeats) { attempt ->
            if (attempt != 0) {
                main { controller!!.checkAppUpdates() }
                await { controller!!.state.value.appUpdates?.let { !it.busy && it.phase == AppUpdatePhase.AVAILABLE } == true }
            }
            main { controller!!.downloadAppUpdate() }
            await { controller!!.state.value.appUpdates?.let { !it.busy && it.error != null } == true }
            assertEquals("tampered attempt ${attempt + 1}; ${fixture!!.appUpdateFlowFailure.get()}", "update.apk_invalid", controller!!.state.value.appUpdates!!.error)
            assertNull(backend.read(fixture!!.slot)); assertEquals(sessions, context.packageManager.packageInstaller.mySessions.map { it.sessionId }.toSet())
            assertTrue(File(context.cacheDir, "apk-updates").listFiles().isNullOrEmpty())
        }
    }
    @Test fun aConfirmationEventCannotSurviveABackgroundRoundTripAndOnlyTheOriginalSessionRemains(): Unit = runBlocking {
        prepared(); val server = fixture!!; val before = backend.read(server.slot)!!.record
        main { controller!!.installAppUpdate() }
        val initial = withTimeoutOrNull(35_000) { controller!!.appUpdateEvents.first() }
        val event = initial ?: run {
            // Slow software emulation may exceed the foreground prompt window.
            // Continue only after another explicit action on durable WAITING_USER.
            await { controller!!.state.value.appUpdates?.let { !it.busy && it.phase == AppUpdatePhase.WAITING_USER } == true }
            main { controller!!.installAppUpdate() }
            withTimeout(60_000) { controller!!.appUpdateEvents.first() }
        }
        assertEquals(AppUpdateLaunchKind.CONFIRMATION, event.kind)
        main { controller!!.foreground(false) }
        var action: (() -> android.content.Intent)? = null
        main { action = controller!!.consumeAppUpdateLaunch(event) }; assertNull(action)
        main { controller!!.foreground(true) }
        await { controller!!.state.value.appUpdates?.let { !it.busy && it.phase == AppUpdatePhase.WAITING_USER } == true }
        main { action = controller!!.consumeAppUpdateLaunch(event) }; assertNull(action)
        assertEquals(before.sessionId, backend.read(server.slot)!!.record.sessionId)
        assertEquals(setOf(before.sessionId), context.packageManager.packageInstaller.mySessions.map { it.sessionId }.toSet())
    }
    @Test fun aLoggedInAccountWithoutUpdateConfigurationNeverQueriesAnImplicitSource() {
        main {
            controller!!.close()
            controller = LoginController(context, fixture!!.http, fixture!!.environment(), installations = backend)
            controller!!.foreground(true)
        }
        await { controller!!.state.value.phase == HomePhase.READY && !controller!!.state.value.refreshing }
        main { controller!!.openAppUpdates() }
        await { controller!!.state.value.appUpdates?.phase == AppUpdatePhase.UNCONFIGURED }
        assertEquals(0, fixture!!.appUpdateQueries.get()); assertEquals(0, fixture!!.appUpdateDownloads.get())
    }
    @Test fun buttonsFromAnOldViewCannotInstallOrCleanupTheReplacementAttempt(): Unit = runBlocking {
        prepared(); val previous = controller!!.state.value.appUpdates!!
        main { controller!!.foreground(false) }
        await { runBlocking { backend.read(fixture!!.slot)!!.record.phase == AppInstallPhase.RETIRED } }
        main { controller!!.foreground(true) }
        await { controller!!.state.value.appUpdates?.let { !it.busy } == true }
        main { controller!!.checkAppUpdates() }
        await { controller!!.state.value.appUpdates?.let { !it.busy && it.phase == AppUpdatePhase.AVAILABLE } == true }
        main { controller!!.downloadAppUpdate() }
        await { controller!!.state.value.appUpdates?.let { !it.busy && it.phase == AppUpdatePhase.PREPARED } == true }
        val replacement = backend.read(fixture!!.slot)!!
        assertNotEquals(previous.attemptId, replacement.record.id)
        main {
            controller!!.installAppUpdate(previous.viewId, previous.attemptId, previous.release!!.document.sha256())
            controller!!.cleanupAppUpdate(previous.viewId, previous.cleanupToken)
            controller!!.requestAppInstallPermission(previous.viewId)
        }
        assertEquals(replacement.revision, backend.read(fixture!!.slot)!!.revision)
        assertFalse(backend.ownSession(replacement.record.sessionId)!!.isSealed)
        assertNull(withTimeoutOrNull(150) { controller!!.appUpdateEvents.first() })
    }
}
