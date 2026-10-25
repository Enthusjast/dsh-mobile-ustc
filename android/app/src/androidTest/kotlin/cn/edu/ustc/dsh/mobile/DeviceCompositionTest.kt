package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import android.net.Uri
import android.os.Bundle
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
        throw AssertionError("Device composition timed out: $label; phase=${controller?.state?.value?.phase}; code=${controller?.state?.value?.error}; approval=${controller?.state?.value?.approvalError}")
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
    @Test fun actualPlatformKeysAndReviewUiDriveOneNativeAllowAndOneNativeReject() {
        assumeTrue("explicit device composition required", InstrumentationRegistry.getArguments().getString("deviceComposition") == "true")
        run = Contract.uuid(InstrumentationRegistry.getArguments().getString("deviceCompositionRun")!!)
        val directory = File(context.noBackupFilesDir, "device-composition/$run")
        val input = File(directory, "input.json")
        require(input.isFile && input.length() <= JsonDocument.MAX_BYTES)
        val fixture = JsonDocument.parse(input.readBytes()).root
        fixture.exactKeys("run_id", "secret", "deployment", "ca_pem", "runtime_id", "session_id")
        require(fixture.string("run_id") == run); Contract.nonce(fixture.string("secret"))
        val config = LoginConfiguration.parse(JsonDocument.of(fixture.obj("deployment")).canonicalBytes())
        val runtime = Contract.uuid(fixture.string("runtime_id")); val session = Contract.uuid(fixture.string("session_id"))
        val guard = context.getSystemService(KeyguardManager::class.java)
        assertTrue("owned fixture needs an unlocked secure device", guard.isDeviceSecure && !guard.isDeviceLocked)
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(fixture.string("ca_pem").byteInputStream()) as X509Certificate
        val trust = HandshakeCertificates.Builder().addTrustedCertificate(certificate).build()
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
            main { controller!!.close(); controller = LoginController(context, http, environment); controller!!.foreground(true) }
            attach(scenario)
            until("accepted identity restored") { controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing } }
            open(runtime, session)
            until("encrypted original decisions restored") { controller!!.state.value.approvals?.records?.size == 2 }
            val restored = controller!!.state.value.approvals!!.records
            for (original in originals) {
                val row = restored.single { it.intent.requestId == original.intent.requestId }
                assertEquals(original.intent.digest, row.intent.digest); assertTrue(original.intent.signed.compact == row.intent.signed.compact); assertEquals(1L, row.attempts)
            }
            assertNull(controller!!.state.value.authenticationId); assertNull(controller!!.state.value.reviewingApprovalId)
            assertTrue(controller!!.state.value.approvals!!.view.items.all { it.handle == null })
            val reopened = checkpoint(slot, config)
            assertEquals(accepted.deviceId, reopened.deviceId); assertEquals(accepted.approvalKeyJkt, reopened.approvalKeyJkt); assertEquals(accepted.session.proofKeyThumbprint, reopened.session.proofKeyThumbprint)
            val result = JsonDocument.of(jsonObject("v" to 1L.json(), "state" to "passed".json(), "run_id" to run.json(), "device_id" to accepted.deviceId!!.json(),
                "proof_key_jkt" to accepted.session.proofKeyThumbprint.json(), "approval_key_jkt" to accepted.approvalKeyJkt!!.json(), "reopened" to JsonBoolean(true)))
            File(directory, "result.json").writeBytes(result.canonicalBytes())
        } finally {
            main { binding?.cancel(); biometric?.cancel(); controller?.cancel() }
            controller?.let { until("fixture account erased") { it.state.value.phase == HomePhase.SIGNED_OUT } }
            main { controller?.close() }
            scenario?.close()
            input.delete()
            transport.dispatcher.cancelAll(); transport.connectionPool.evictAll(); transport.dispatcher.executorService.shutdownNow()
        }
    }
}
