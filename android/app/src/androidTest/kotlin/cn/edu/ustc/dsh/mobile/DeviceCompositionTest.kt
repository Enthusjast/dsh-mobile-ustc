package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import androidx.activity.compose.setContent
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.lifecycle.lifecycleScope
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.auth.*
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.keystore.*
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import cn.edu.ustc.dsh.ui.DshTheme
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Authenticator
import okhttp3.CookieJar
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.tls.HandshakeCertificates
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.UUID

/** Opt-in real APK/Go/DSH composition. Its identity issuer is an explicit local fixture. */
@RunWith(AndroidJUnit4::class)
class DeviceCompositionTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private var controller: LoginController? = null
    private var binding: Job? = null
    private var biometric: BiometricUi? = null
    private lateinit var run: String
    private fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
    private fun until(label: String, test: () -> Boolean) {
        val end = android.os.SystemClock.elapsedRealtime() + 60_000
        while (android.os.SystemClock.elapsedRealtime() < end) {
            if (test()) return
            Thread.sleep(25)
        }
        throw AssertionError("Device composition timed out: $label; phase=${controller?.state?.value?.phase}; code=${controller?.state?.value?.error}; approval=${controller?.state?.value?.approvalError}; files=${controller?.state?.value?.exports?.error}; save=${controller?.state?.value?.exportSaveError}")
    }
    private fun progress(phase: String, token: String) = instrumentation.sendStatus(2, Bundle().apply { putString("stream", "\nDEVICE_COMPOSITION_BIOMETRIC_$phase $run $token\n") })
    private fun attach(scenario: ActivityScenario<MainActivity>) = scenario.onActivity { activity ->
        binding?.cancel(); biometric?.cancel()
        val current = controller!!; val tokens = mutableMapOf<Long, String>()
        val ui = BiometricUi(activity, current::promptOpened,
            { id, result -> tokens.remove(id)?.let { progress("DONE", it) }; current.authenticated(id, result) },
            { id -> tokens.remove(id)?.let { progress("DONE", it) }; current.authenticationCancelled(id) })
        biometric = ui
        binding = activity.lifecycleScope.launch {
            current.state.collect { state ->
                val launch = state.biometric
                val token = launch?.let { UUID.randomUUID().toString().also { token -> tokens[it.id] = token } }
                ui.update(state.authenticationId, launch)
                if (token != null) progress("READY", token)
            }
        }
        activity.setContent { DshTheme { HomeRoute(HomeViewModel(current), {}, current::cancel) } }
    }
    private fun open(runtime: String, session: String) {
        main { controller!!.openRuntime(runtime) }
        until("native session directory") { controller!!.state.value.let { !it.loadingSessions && it.sessions.any { row -> row.id == session } } }
        main { controller!!.openSession(session) }
        until("real relay subscription") { controller!!.state.value.let { it.reader?.phase == SessionReadPhase.READY && it.approvals?.let { client -> client.connected && client.contentReady && client.view.loaded } == true } }
    }
    private fun checkpoint(slot: String, config: LoginConfiguration): AccountCheckpoint = AccountVault(context, slot).read()!!.use { opened ->
        DeviceKeyStore(context).use { owner ->
            val proof = owner.load(DeviceKeyScope(opened.accountId, opened.organizationId), DeviceKeyPurpose.PROOF, 1)
            AccountCheckpoint.parseAuthenticated(opened.bytes(), config, proof.thumbprint, System.currentTimeMillis(), opened.accountId)
        }
    }
    private fun catalog(source: ExportSource? = null): ExportPage {
        val previous = controller!!.state.value.exports?.page
        main { controller!!.browseExports(source, false) }
        // The facade collector may still expose the preceding directory while
        // the new request is queued. Require the actual replacement response.
        until("authorized export catalog") { controller!!.state.value.exports?.let { !it.listing && it.page != null && it.page !== previous } == true }
        return controller!!.state.value.exports!!.page!!
    }
    private fun source(page: ExportPage, label: String, matches: (ExportSource) -> Boolean): ExportSource {
        val selected = page.items.filter(matches)
        assertEquals("Expected $label; catalog=" + page.items.map { "${it.origin.wire}/${if (it.directory) "directory" else "file"}/${it.name}" }, 1, selected.size)
        return selected.single()
    }
    private fun filePhase(label: String) = instrumentation.sendStatus(2, Bundle().apply { putString("stream", "\nDEVICE_COMPOSITION_FILE_PHASE $run $label\n") })
    private fun exportAndSave(source: ExportSource, expected: ExportManifest): JsonObject {
        filePhase("prepare-${source.origin.wire}-${expected.name}")
        val before = controller!!.state.value.exports!!.rows.map { it.stored.intent.requestId }.toSet()
        main { controller!!.requestExport(source) }
        until("scanned original export") { controller!!.state.value.exports?.rows?.any { it.stored.intent.requestId !in before && it.status?.downloadable() == true } == true }
        val row = controller!!.state.value.exports!!.rows.single { it.stored.intent.requestId !in before }
        assertTrue(row.status!!.manifest.same(expected)); assertTrue(row.stored.manifest!!.same(expected))
        assertEquals(source.origin, row.stored.intent.origin)
        val resolver = context.contentResolver
        val initial = resolver.call(FixtureDocumentProvider.URI, "createExport", "moving", null)!!.getParcelable<Uri>("uri")!!
        // Deliver one explicit chooser result in the same main-loop step. This
        // exercises production consent handling without launching DocumentsUI.
        main {
            controller!!.chooseExportDestination(row.stored.intent.requestId)
            val consent = controller!!.state.value.exportSavePicker!!
            controller!!.exportDestinationPicked(consent.id, initial)
        }
        until("authenticated export document save") { controller!!.state.value.exportSaved }
        filePhase("saved-${source.origin.wire}-${expected.name}")
        assertNull(controller!!.state.value.exportSaveError)
        val saved = resolver.call(FixtureDocumentProvider.URI, "findExport", "moving", null)!!.getParcelable<Uri>("uri")!!
        try {
            assertNotEquals(initial, saved)
            val actual = resolver.openInputStream(saved)!!.use { it.readBytes() }
            assertEquals(expected.sizeBytes, actual.size.toLong()); assertEquals(expected.sha256, sha256(actual))
            return jsonObject("request_id" to row.stored.intent.requestId.json(), "file_id" to row.stored.fileId!!.json(), "origin" to source.origin.wire.json(),
                "name" to expected.name.json(), "size_bytes" to actual.size.toLong().json(), "sha256" to sha256(actual).json())
        } finally { DocumentsContract.deleteDocument(resolver, saved) }
    }
    @Test fun actualKeysApprovalsAndFilesSurviveNativeSessionRecovery() {
        assumeTrue("explicit device composition required", InstrumentationRegistry.getArguments().getString("deviceComposition") == "true")
        run = Contract.uuid(InstrumentationRegistry.getArguments().getString("deviceCompositionRun")!!)
        val directory = File(context.noBackupFilesDir, "device-composition/$run")
        val input = File(directory, "input.json")
        require(input.isFile && input.length() <= JsonDocument.MAX_BYTES)
        val fixture = JsonDocument.parse(input.readBytes()).root
        fixture.exactKeys("run_id", "secret", "deployment", "ca_pem", "runtime_id", "session_id", "object_origin", "object_ca_pem", "artifact_manifests")
        require(fixture.string("run_id") == run); Contract.nonce(fixture.string("secret"))
        val config = LoginConfiguration.parse(JsonDocument.of(fixture.obj("deployment")).canonicalBytes())
        val runtime = Contract.uuid(fixture.string("runtime_id")); val session = Contract.uuid(fixture.string("session_id"))
        val guard = context.getSystemService(KeyguardManager::class.java)
        assertTrue("owned fixture needs an unlocked secure device", guard.isDeviceSecure && !guard.isDeviceLocked)
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(fixture.string("ca_pem").byteInputStream()) as X509Certificate
        val objectCertificate = CertificateFactory.getInstance("X.509").generateCertificate(fixture.string("object_ca_pem").byteInputStream()) as X509Certificate
        val trust = HandshakeCertificates.Builder().addTrustedCertificate(certificate).addTrustedCertificate(objectCertificate).build()
        val transport = OkHttpClient.Builder().sslSocketFactory(trust.sslSocketFactory(), trust.trustManager)
            .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false).cache(null).cookieJar(CookieJar.NO_COOKIES)
            .authenticator(Authenticator.NONE).proxyAuthenticator(Authenticator.NONE)
            .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS).readTimeout(15, java.util.concurrent.TimeUnit.SECONDS).callTimeout(20, java.util.concurrent.TimeUnit.SECONDS).build()
        // Fixture CA injection is confined to the test APK; the production factory uses system trust.
        val http = LoginHttp::class.java.getDeclaredConstructor(OkHttpClient::class.java).apply { isAccessible = true }.newInstance(transport)
        val slot = "composition-$run"; val ledger = "$slot-keys"
        val environment = LoginEnvironment({ JsonDocument.of(fixture.obj("deployment")).canonicalBytes() }, slot, ledger)
        var scenario: ActivityScenario<MainActivity>? = null
        try {
            main { controller = LoginController(context, http, environment); controller!!.foreground(true) }
            until("fresh account") { controller!!.state.value.phase == HomePhase.SIGNED_OUT }
            scenario = ActivityScenario.launch(MainActivity::class.java); attach(scenario)
            main { controller!!.login() }
            until("PKCE authorization request") { controller!!.state.value.browser != null }
            val browser = controller!!.state.value.browser!!
            val body = JsonDocument.of(jsonObject("authorization_uri" to browser.uri.toString().json())).canonicalBytes().toRequestBody("application/json".toMediaType())
            val authorization = transport.newCall(Request.Builder().url(config.remoteOrigin+"/fixture/authorize").post(body).header("X-DSH-Fixture", fixture.string("secret")).build()).execute().use { response ->
                assertTrue("fixture authorization failed", response.isSuccessful)
                JsonDocument.parse(response.body!!.bytes()).root
            }
            authorization.exactKeys("code", "state")
            val callback = Uri.parse(config.redirectUri).buildUpon().appendQueryParameter("state", authorization.string("state")).appendQueryParameter("code", authorization.string("code")).build()
            main { controller!!.browserOpened(browser.id); controller!!.callback(callback.toString()) }
            until("verified fixture identity") { controller!!.state.value.phase == HomePhase.ENROLL }
            compose.onNodeWithText("确认并登记设备").performScrollTo().performClick()
            until("actual device registration") { controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing && it.runtimes.any { row -> row.id == runtime } } }
            val accepted = checkpoint(slot, config)
            assertEquals(EnrollmentCheckpoint.ACTIVE, accepted.enrollment)
            assertNotEquals(accepted.approvalKeyJkt, accepted.session.proofKeyThumbprint)
            open(runtime, session)
            val originals = mutableListOf<PendingApprovalDecision>()
            for (choice in ApprovalChoice.entries) {
                val mode = if (choice == ApprovalChoice.ALLOW_ONCE) "ALLOW" else "REJECT"
                val marker = "REMOTE_APPROVAL_${mode}_ANDROID"
                main { controller!!.submitMessage("queue", marker) }
                until("native pending $mode") { controller!!.state.value.approvals?.view?.items?.any { it.canReview } == true }
                val reference = controller!!.state.value.approvals!!.view.items.single { it.canReview }
                main { controller!!.reviewApproval(reference.status.id) }
                until("complete native $mode details") { controller!!.state.value.approvals?.view?.items?.any { it.handle != null } == true }
                val review = controller!!.state.value.approvals!!.view.items.single { it.handle != null }
                val native = review.context!!
                assertEquals("bash", native.root.string("tool"))
                assertEquals("printf authorized >> approval-${mode.lowercase()}.txt", native.root.obj("arguments").string("command"))
                if (choice == ApprovalChoice.ALLOW_ONCE) {
                    compose.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsNotEnabled()
                    compose.onNodeWithText("我已核对本页").performScrollTo().performClick()
                    compose.onNodeWithText("我已核对全部动作、参数及资源，仅为本次调用作出决定。").performScrollTo().performClick()
                    compose.onNodeWithText("仅本次允许并确认身份").performScrollTo().performClick()
                } else compose.onNodeWithText("拒绝并确认身份").performScrollTo().performClick()
                val expected = if (choice == ApprovalChoice.ALLOW_ONCE) ApprovalHostState.SETTLED else ApprovalHostState.DENIED
                until("durable native $mode result") { controller!!.state.value.let { state -> state.approvalStage == ApprovalUiStage.IDLE && state.approvals?.records?.any { it.intent.approvalId == reference.status.id && it.remote?.hostState == expected } == true } }
                val original = controller!!.state.value.approvals!!.records.single { it.intent.approvalId == reference.status.id }
                assertEquals(ApprovalDecisionDelivery.ACCEPTED, original.delivery); assertEquals(1L, original.attempts); assertEquals(choice, original.intent.decision.choice)
                if (choice == ApprovalChoice.ALLOW_ONCE) assertEquals(ApprovalExecutionOutcome.SUCCEEDED, original.remote!!.outcome)
                originals += original
                until("native $mode turn completed") { controller!!.state.value.reader?.window?.let { window -> !window.taskRunning && window.items.any { it.blocks.any { block -> block.text == marker } } } == true }
                main { controller!!.closeApprovalReview() }
            }
            filePhase("phone-upload")
            main {
                controller!!.pickDocument(null, "", "queue")
                val consent = controller!!.state.value.documentPicker!!
                controller!!.documentPicked(consent.id, FixtureDocumentProvider.URI)
            }
            until("scanned and native-staged phone upload") { controller!!.state.value.uploads?.rows?.singleOrNull()?.ready() == true }
            val upload = controller!!.state.value.uploads!!.rows.single().stored
            assertEquals(FixtureDocumentProvider.NAME, upload.intent.manifest.name)
            assertEquals(sha256(FixtureDocumentProvider.BYTES), upload.intent.manifest.sha256)
            main { controller!!.toggleUpload(upload.intent.requestId); controller!!.submitMessage("queue", "") }
            until("native file-only message admission") { controller!!.state.value.uploads?.rows?.singleOrNull()?.stored?.messageId != null &&
                controller!!.state.value.outbox?.records?.any { it.intent.fileIds() == listOf(upload.fileId) && it.everAgentQueued } == true }
            val fileMessage = controller!!.state.value.outbox!!.records.single { it.intent.fileIds() == listOf(upload.fileId) }
            until("persisted native attachment summary") { controller!!.state.value.reader?.window?.let { window -> !window.taskRunning && window.items.any { item -> item.persisted && item.blocks.any { block -> block.text.startsWith("[附件：") && block.text.contains("（${FixtureDocumentProvider.BYTES.size} 字节）") } } } == true }
            filePhase("native-file-message")
            until("negotiated file export") { controller!!.state.value.exports?.connected == true }
            val fileResults = mutableListOf<JsonObject>()
            val manifests = fixture.array("artifact_manifests").map { ExportManifest.parse(it as JsonObject) }
            assertEquals(setOf("report.bin", "empty.bin"), manifests.map { it.name }.toSet())
            for (manifest in manifests) {
                val directory = source(catalog(), "workspace reports root") { it.directory && it.origin == ExportOrigin.WORKSPACE_ARTIFACT && it.name == "reports" }
                val selected = source(catalog(directory), manifest.name) { !it.directory && it.name == manifest.name }
                fileResults += exportAndSave(selected, manifest)
            }
            val attachments = source(catalog(), "session attachment root") { it.directory && it.origin == ExportOrigin.SESSION_ATTACHMENT }
            val nativeSource = source(catalog(attachments), "persisted native attachment") { !it.directory }
            fileResults += exportAndSave(nativeSource, ExportManifest(nativeSource.name, FixtureDocumentProvider.BYTES.size.toLong(), sha256(FixtureDocumentProvider.BYTES)))
            main { controller!!.archiveSession(controller!!.state.value.reader!!.runtimeEpoch!!, true, false) }
            until("native archived catalog and receipt") { controller!!.state.value.let { state -> !state.submitting && state.reader?.phase == SessionReadPhase.READY && state.outbox?.canArchive == true && state.sessions.singleOrNull { it.id == session }?.state == "archived" && state.outbox.records.any { it.intent.kind == CommandKind.ARCHIVE && it.remote == RemoteCommandState.SETTLED } } }
            assertTrue(controller!!.state.value.outbox!!.records.filter { it.intent.kind == CommandKind.ARCHIVE }.none { it.everAgentQueued })
            main { controller!!.archiveSession(controller!!.state.value.reader!!.runtimeEpoch!!, false, false) }
            until("native restored catalog and receipt") { controller!!.state.value.let { state -> !state.submitting && state.reader?.phase == SessionReadPhase.READY && state.outbox?.canArchive == true && state.sessions.singleOrNull { it.id == session }?.state in setOf("available", "running") && state.outbox.records.count { it.intent.kind == CommandKind.ARCHIVE && it.remote == RemoteCommandState.SETTLED } == 2 } }
            val archiveOriginals = controller!!.state.value.outbox!!.records.filter { it.intent.kind == CommandKind.ARCHIVE }
            main { controller!!.close(); controller = LoginController(context, http, environment); controller!!.foreground(true) }
            attach(scenario)
            until("accepted identity restored") { controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing } }
            open(runtime, session)
            until("encrypted original decisions restored") { controller!!.state.value.approvals?.records?.size == 2 }
            until("encrypted archive originals restored") { controller!!.state.value.outbox?.records?.count { it.intent.kind == CommandKind.ARCHIVE } == 2 }
            until("encrypted file originals restored") { controller!!.state.value.uploads?.rows?.singleOrNull()?.stored?.messageId == fileMessage.intent.requestId &&
                controller!!.state.value.exports?.rows?.let { rows -> rows.size == 3 && rows.all { it.status?.downloadable() == true } } == true }
            assertEquals(upload.intent.digest, controller!!.state.value.uploads!!.rows.single().stored.intent.digest)
            assertEquals(upload.fileId, controller!!.state.value.uploads!!.rows.single().stored.fileId)
            assertEquals(fileMessage.intent.digest, controller!!.state.value.outbox!!.records.single { it.intent.requestId == fileMessage.intent.requestId }.intent.digest)
            for (original in fileResults) {
                val restored = controller!!.state.value.exports!!.rows.single { it.stored.intent.requestId == original.string("request_id") }
                assertEquals(original.string("file_id"), restored.stored.fileId); assertEquals(original.string("sha256"), restored.stored.manifest!!.sha256)
            }
            for (original in archiveOriginals) {
                val row = controller!!.state.value.outbox!!.records.single { it.intent.requestId == original.intent.requestId }
                assertEquals(original.intent.digest, row.intent.digest); assertEquals(1L, row.attempts)
                assertEquals(RemoteCommandState.SETTLED, row.remote); assertFalse(row.everAgentQueued)
            }
            val restored = controller!!.state.value.approvals!!.records
            for (original in originals) {
                val row = restored.single { it.intent.requestId == original.intent.requestId }
                assertEquals(original.intent.digest, row.intent.digest); assertTrue(original.intent.signed.compact == row.intent.signed.compact); assertEquals(1L, row.attempts)
            }
            assertNull(controller!!.state.value.authenticationId); assertNull(controller!!.state.value.reviewingApprovalId)
            assertTrue(controller!!.state.value.approvals!!.view.items.all { it.handle == null })
            val reopened = checkpoint(slot, config)
            assertEquals(accepted.deviceId, reopened.deviceId); assertEquals(accepted.approvalKeyJkt, reopened.approvalKeyJkt); assertEquals(accepted.session.proofKeyThumbprint, reopened.session.proofKeyThumbprint)
            runBlocking {
                DeviceKeyStore(context).use { keys ->
                    val proof = keys.load(DeviceKeyScope(reopened.accountId, reopened.organizationId), DeviceKeyPurpose.PROOF, 1)
                    val verified = TokenVerifier.revalidateStored(reopened.session, config, http.keys(http.discovery(config)), System.currentTimeMillis())
                    val resource = http.resource(config, verified, proof.proofSigner())
                    for (original in fileResults) {
                        val known = resource.exportRequestStatus(original.string("request_id"))
                        assertEquals(original.string("file_id"), known.id); assertEquals(original.string("sha256"), known.manifest.sha256)
                    }
                }
            }
            val result = JsonDocument.of(jsonObject("v" to 1L.json(), "state" to "passed".json(), "run_id" to run.json(), "device_id" to accepted.deviceId!!.json(),
                "proof_key_jkt" to accepted.session.proofKeyThumbprint.json(), "approval_key_jkt" to accepted.approvalKeyJkt!!.json(), "reopened" to JsonBoolean(true),
                "archive_requests" to JsonArray(archiveOriginals.map { it.intent.requestId.json() }), "session_id" to session.json(), "exports" to JsonArray(fileResults),
                "upload" to jsonObject("file_id" to upload.fileId!!.json(), "request_id" to upload.intent.requestId.json(), "message_id" to fileMessage.intent.requestId.json(),
                    "sha256" to upload.intent.manifest.sha256.json(), "size_bytes" to upload.intent.manifest.sizeBytes.json())))
            File(directory, "result.json").writeBytes(result.canonicalBytes())
        } finally {
            main { binding?.cancel(); biometric?.cancel(); controller?.cancel() }
            controller?.let { until("fixture account erased") { it.state.value.phase == HomePhase.SIGNED_OUT } }
            main { controller?.close() }
            scenario?.close()
            context.contentResolver.call(FixtureDocumentProvider.URI, "resetExports", null, null)
            input.delete()
            transport.dispatcher.cancelAll(); transport.connectionPool.evictAll(); transport.dispatcher.executorService.shutdownNow()
        }
    }
}
