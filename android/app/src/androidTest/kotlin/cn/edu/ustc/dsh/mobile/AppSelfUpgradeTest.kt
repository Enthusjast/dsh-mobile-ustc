package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Bundle
import android.os.Build
import android.view.accessibility.AccessibilityNodeInfo
import androidx.activity.compose.setContent
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.auth.*
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.data.SqlCommandJournal
import cn.edu.ustc.dsh.keystore.*
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.ui.DshTheme
import dagger.hilt.EntryPoints
import kotlinx.coroutines.*
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
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

/** A host issuer survives the intentional process death at actual package replacement. */
@RunWith(AndroidJUnit4::class)
class AppSelfUpgradeTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private lateinit var run: String
    private lateinit var directory: File
    private lateinit var input: JsonObject
    private lateinit var config: LoginConfiguration
    private lateinit var transport: OkHttpClient
    private lateinit var http: LoginHttp
    private lateinit var backend: AppInstallations
    private lateinit var controller: LoginController
    private lateinit var slot: String
    private lateinit var ledger: String
    private var scenario: ActivityScenario<MainActivity>? = null
    private var biometric: BiometricUi? = null
    private var installerPackage: String? = null
    private var waitedSystemAnrs = 0
    private var lastSystemRoot = "not queried"
    private fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
    private fun status(value: String) = instrumentation.sendStatus(2, Bundle().apply { putString("stream", "\nAPP_SELF_UPGRADE_$value $run\n") })
    private fun until(label: String, condition: () -> Boolean) {
        val end = android.os.SystemClock.elapsedRealtime() + 120_000
        while (android.os.SystemClock.elapsedRealtime() < end) { if (condition()) return; Thread.sleep(25) }
        throw AssertionError("self upgrade timed out at $label; phase=${controller.state.value.phase}; error=${controller.state.value.error}; update=${controller.state.value.appUpdates}; system=$lastSystemRoot")
    }
    private fun setup() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("appSelfUpgrade") == "true")
        run = Contract.uuid(InstrumentationRegistry.getArguments().getString("appSelfUpgradeRun")!!)
        directory = File(context.noBackupFilesDir, "app-self-upgrade/$run")
        input = JsonDocument.parse(File(directory, "input.json").readBytes()).root
        input.exactKeys("v", "run_id", "secret", "ca_pem", "deployment", "runtime_id", "workspace_id", "candidate_sha256", "candidate_version_name", "candidate_size_bytes", "signing_cert_sha256")
        input.integer("v", 1, 1); assertEquals(run, input.string("run_id")); Contract.nonce(input.string("secret"))
        config = LoginConfiguration.parse(JsonDocument.of(input.obj("deployment")).canonicalBytes())
        val guard = context.getSystemService(KeyguardManager::class.java)
        assertTrue("secure unlocked enrolled test device required", guard.isDeviceSecure && !guard.isDeviceLocked)
        val automation = instrumentation.uiAutomation
        automation.serviceInfo = automation.serviceInfo.apply { flags = flags or AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS or
            AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS or AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS }
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(input.string("ca_pem").byteInputStream()) as X509Certificate
        val trust = HandshakeCertificates.Builder().addTrustedCertificate(certificate).build()
        transport = OkHttpClient.Builder().sslSocketFactory(trust.sslSocketFactory(), trust.trustManager).followRedirects(false).followSslRedirects(false)
            .retryOnConnectionFailure(false).cookieJar(CookieJar.NO_COOKIES).cache(null).authenticator(Authenticator.NONE).proxyAuthenticator(Authenticator.NONE)
            .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS).readTimeout(15, java.util.concurrent.TimeUnit.SECONDS).callTimeout(20, java.util.concurrent.TimeUnit.SECONDS).build()
        http = LoginHttp::class.java.getDeclaredConstructor(OkHttpClient::class.java).apply { isAccessible = true }.newInstance(transport)
        val receiver = AppInstallResultReceiver()
        EntryPoints.get(context.applicationContext, AppInstallResultReceiver_GeneratedInjector::class.java).injectAppInstallResultReceiver(receiver)
        backend = receiver.installations
        slot = "upgrade-$run"; ledger = "$slot-keys"
        val updates = JsonDocument.of(jsonObject("v" to 1L.json(), "deployment_sha256" to config.fingerprint.json(), "package_name" to context.packageName.json(),
            "download_origins" to JsonArray(listOf(config.remoteOrigin.json())))).canonicalBytes()
        val environment = LoginEnvironment({ JsonDocument.of(input.obj("deployment")).canonicalBytes() }, slot, ledger, appUpdateConfiguration = { updates })
        main { controller = LoginController(context, http, environment, installations = backend); controller.foreground(true) }
        scenario = ActivityScenario.launch(MainActivity::class.java)
        scenario!!.onActivity { activity ->
            val tokens = mutableMapOf<Long, String>()
            val ui = BiometricUi(activity, controller::promptOpened,
                { id, result -> tokens.remove(id)?.let { status("BIO_DONE $it") }; controller.authenticated(id, result) },
                { id -> tokens.remove(id)?.let { status("BIO_DONE $it") }; controller.authenticationCancelled(id) })
            biometric = ui
            activity.lifecycle.addObserver(LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_START) controller.foreground(true)
                if (event == Lifecycle.Event.ON_STOP) controller.foreground(false)
            })
            activity.lifecycleScope.launch {
                controller.state.collect { state ->
                    val token = state.biometric?.let { launch -> tokens.getOrPut(launch.id) { UUID.randomUUID().toString() } }
                    ui.update(state.authenticationId, state.biometric)
                    if (token != null) status("BIO_READY $token")
                }
            }
            activity.lifecycleScope.launch {
                activity.repeatOnLifecycle(Lifecycle.State.STARTED) {
                    controller.appUpdateEvents.collect { event ->
                        val factory = controller.consumeAppUpdateLaunch(event) ?: return@collect
                        val intent = factory()
                        assertNotNull(intent.component)
                        if (event.kind == AppUpdateLaunchKind.PERMISSION) {
                            assertEquals("package:${context.packageName}", intent.dataString)
                            status("PERMISSION_UI")
                        } else { installerPackage = intent.component!!.packageName; status("CONFIRMATION_UI") }
                        activity.startActivity(intent)
                    }
                }
            }
            activity.setContent { DshTheme { HomeRoute(HomeViewModel(controller), {}, controller::cancel) } }
        }
    }
    private fun authorizeIfNeeded() {
        until("restored identity") { controller.state.value.phase in setOf(HomePhase.SIGNED_OUT, HomePhase.REAUTHENTICATE, HomePhase.ENROLL, HomePhase.READY) }
        if (controller.state.value.phase in setOf(HomePhase.SIGNED_OUT, HomePhase.REAUTHENTICATE)) {
            main { controller.login() }; until("PKCE request") { controller.state.value.browser != null }
            val launch = controller.state.value.browser!!
            val body = JsonDocument.of(jsonObject("authorization_uri" to launch.uri.toString().json())).canonicalBytes().toRequestBody("application/json".toMediaType())
            val reply = transport.newCall(Request.Builder().url(config.remoteOrigin + "/fixture/authorize").post(body).header("X-DSH-Fixture", input.string("secret")).build()).execute().use {
                assertTrue(it.isSuccessful); JsonDocument.parse(it.body!!.bytes()).root
            }
            reply.exactKeys("code", "state")
            val uri = Uri.parse(config.redirectUri).buildUpon().appendQueryParameter("state", reply.string("state")).appendQueryParameter("code", reply.string("code")).build()
            main { controller.browserOpened(launch.id); controller.callback(uri.toString()) }
            until("verified account") { controller.state.value.phase in setOf(HomePhase.ENROLL, HomePhase.READY) }
        }
    }
    private fun checkpoint(): AccountCheckpoint = AccountVault(context, slot).read()!!.use { saved ->
        DeviceKeyStore(context).use { keys ->
            val proof = keys.load(DeviceKeyScope(saved.accountId, saved.organizationId), DeviceKeyPurpose.PROOF, 1)
            AccountCheckpoint.parseAuthenticated(saved.bytes(), config, proof.thumbprint, System.currentTimeMillis(), saved.accountId)
        }
    }
    private fun systemRoot(packageName: String): AccessibilityNodeInfo? {
        @Suppress("DEPRECATION") val application = context.packageManager.getApplicationInfo(packageName, 0)
        assertTrue(application.flags.and(ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0)
        if (Build.VERSION.SDK_INT >= 33) instrumentation.uiAutomation.clearCache()
        val root = instrumentation.uiAutomation.rootInActiveWindow ?: run { lastSystemRoot = "null"; return null }
        lastSystemRoot = "package=${root.packageName}, class=${root.className}, children=${root.childCount}, label=${containsText(root,"DSH 远控")}, toggle=${switchNode(root)?.className}"
        if (root.packageName?.toString() == "android" && waitedSystemAnrs < 3 && containsText(root,"System UI isn't responding")) {
            findNode(root) { it.isClickable && it.text?.toString() == "Wait" }?.let {
                if (it.performAction(AccessibilityNodeInfo.ACTION_CLICK)) { waitedSystemAnrs++; status("SYSTEM_ANR_WAIT") }
            }
            return null
        }
        return root.takeIf { it.packageName?.toString() == packageName }
    }
    private fun findNode(node: AccessibilityNodeInfo, predicate: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo? {
        if (predicate(node)) return node
        for (index in 0 until node.childCount) node.getChild(index)?.let { findNode(it,predicate)?.let { result -> return result } }
        return null
    }
    private fun containsText(node: AccessibilityNodeInfo, value: String) = findNode(node) {
        it.text?.toString()?.contains(value) == true || it.contentDescription?.toString()?.contains(value) == true
    } != null
    private fun switchNode(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
        if (node.isCheckable && node.isEnabled) return node
        for (index in 0 until node.childCount) node.getChild(index)?.let { switchNode(it)?.let { result -> return result } }
        return null
    }
    private fun sourcePermissionClickTarget(toggle: AccessibilityNodeInfo): AccessibilityNodeInfo? {
        var current: AccessibilityNodeInfo? = toggle
        repeat(4) {
            val node = current ?: return null
            if (node.packageName?.toString() != "com.android.settings") return null
            // API 26 exposes the checked state on a nonclickable Switch; the
            // containing labelled preference owns ACTION_CLICK. API 36 exposes
            // both semantics on the Compose toggle itself.
            if (node.isEnabled && node.isClickable && (node === toggle || containsText(node, "Allow from this source"))) return node
            current = node.parent
        }
        return null
    }
    @Test fun prepareAndWaitForRealSystemUpgrade(): Unit = runBlocking {
        setup(); assertEquals(1L, AndroidApkVerifier(context).installed().versionCode)
        authorizeIfNeeded(); assertEquals(HomePhase.ENROLL, controller.state.value.phase)
        compose.onNodeWithText("确认并登记设备").performScrollTo().performClick()
        until("registered phone") { controller.state.value.let { it.phase == HomePhase.READY && !it.refreshing && it.runtimes.any { row -> row.id == input.string("runtime_id") } } }
        val before = checkpoint(); assertEquals(EnrollmentCheckpoint.ACTIVE, before.enrollment)
        val runtime = Contract.uuid(input.string("runtime_id")); val workspace = Contract.uuid(input.string("workspace_id")); val session = UUID.randomUUID().toString()
        val owner = CommandOwner(before.accountId, before.organizationId, config.fingerprint, before.userId, before.deviceId!!)
        val command = CommandIntent.message(UUID.randomUUID().toString(), runtime, session, "queue", "APP_UPGRADE_RETAIN_中文🙂_$run")
        SqlCommandJournal.open(context, owner).use { journal -> journal.create(command); journal.beginAttempt(command.requestId) }
        SqlCommandJournal.open(context, owner).use { journal -> assertEquals(command.digest,journal.list(runtime,session).single().intent.digest) }
        File(directory, "before.json").writeBytes(JsonDocument.of(jsonObject("account_id" to before.accountId.json(), "device_id" to before.deviceId!!.json(),
            "user_id" to before.userId.json(), "proof_key_jkt" to before.session.proofKeyThumbprint.json(), "approval_key_jkt" to before.approvalKeyJkt!!.json(),
            "runtime_id" to runtime.json(), "workspace_id" to workspace.json(), "session_id" to session.json(), "request_id" to command.requestId.json(), "command_sha256" to command.digest.json())).canonicalBytes())
        main { controller.openAppUpdates() }
        until("applicable full v2") { controller.state.value.appUpdates?.let { !it.busy && it.phase == AppUpdatePhase.AVAILABLE } == true }
        val release = controller.state.value.appUpdates!!.release!!
        assertEquals(input.string("candidate_sha256"), release.sha256); assertEquals(input.integer("candidate_size_bytes"), release.sizeBytes)
        assertFalse("settings roundtrip must begin without source permission", backend.canInstall())
        compose.onNodeWithText("允许本应用安装").performScrollTo().performClick()
        until("settings paused updater") { controller.state.value.appUpdates == null }
        var toggle: AccessibilityNodeInfo? = null
        var toggleTarget: AccessibilityNodeInfo? = null
        until("system source-permission switch") {
            val root = systemRoot("com.android.settings") ?: return@until false
            if (!containsText(root,"DSH 远控")) return@until false
            toggle = switchNode(root)
            toggleTarget = toggle?.let(::sourcePermissionClickTarget)
            toggleTarget != null
        }
        assertFalse(toggle!!.isChecked); assertTrue(toggleTarget!!.performAction(AccessibilityNodeInfo.ACTION_CLICK))
        until("system source permission granted") { backend.canInstall() }
        assertTrue(instrumentation.uiAutomation.performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK))
        until("settings returned with permission") { controller.state.value.appUpdates?.let { !it.busy && it.canInstall && it.phase == AppUpdatePhase.AVAILABLE } == true }
        assertTrue(File(context.cacheDir,"apk-updates").listFiles().isNullOrEmpty())
        status("PERMISSION_RETURNED")
        compose.onNodeWithText("下载并校验").performScrollTo().performClick()
        until("verified full executable candidate") { controller.state.value.appUpdates?.let { !it.busy && it.phase == AppUpdatePhase.PREPARED } == true }
        assertEquals(release.document.sha256(), controller.state.value.appUpdates!!.release!!.document.sha256())
        val record = backend.read(slot)!!.record
        File(directory,"prepared.json").writeBytes(JsonDocument.of(jsonObject("installation_id" to record.id.json(),"session_id" to record.sessionId.toLong().json(),"sha256" to record.release.sha256.json())).canonicalBytes())
        compose.onNodeWithText("打开系统安装确认").performScrollTo().performClick()
        var confirm: AccessibilityNodeInfo? = null
        until("system-owned exact-app update confirmation") {
            val packageName = installerPackage ?: return@until false
            val root = systemRoot(packageName) ?: return@until false
            if (!containsText(root,"DSH 远控")) return@until false
            confirm = findNode(root) { it.isEnabled && it.isClickable && it.className?.toString()?.endsWith("Button") == true &&
                it.text?.toString()?.trim()?.lowercase(java.util.Locale.ROOT) in setOf("update","install") }
            confirm != null
        }
        val correlation = jsonObject("run_id" to run.json(),"installation_id" to record.id.json(),"session_id" to record.sessionId.toLong().json(),
            "sha256" to record.release.sha256.json(),"system_package" to installerPackage!!.json())
        File(directory,"confirmation.json").outputStream().use { it.write(JsonDocument.of(correlation).canonicalBytes()); it.fd.sync() }
        status("APPROVING")
        assertTrue(confirm!!.performAction(AccessibilityNodeInfo.ACTION_CLICK))
        // Replacement intentionally kills this instrumentation. A separate post
        // phase and the host's exact installed artifact proof determine outcome.
        withTimeout(300_000) { while (true) delay(1000) }
    }
    @Test fun reopenAfterRealSystemUpgradeAndVerifyIdentityKeysAndRoom(): Unit = runBlocking {
        setup(); assertEquals(2L, AndroidApkVerifier(context).installed().versionCode)
        authorizeIfNeeded()
        until("existing registered phone restored") { controller.state.value.let { it.phase == HomePhase.READY && !it.refreshing } }
        val before = JsonDocument.parse(File(directory,"before.json").readBytes()).root
        val after = checkpoint()
        assertEquals(before.string("account_id"),after.accountId); assertEquals(before.string("device_id"),after.deviceId)
        assertEquals(before.string("user_id"),after.userId); assertEquals(before.string("proof_key_jkt"),after.session.proofKeyThumbprint)
        assertEquals(before.string("approval_key_jkt"),after.approvalKeyJkt)
        val owner = CommandOwner(after.accountId,after.organizationId,config.fingerprint,after.userId,after.deviceId!!)
        SqlCommandJournal.open(context,owner).use { journal ->
            val row = journal.list(before.string("runtime_id"),before.string("session_id")).single()
            assertEquals(before.string("request_id"),row.intent.requestId); assertEquals(before.string("command_sha256"),row.intent.digest)
            assertEquals(1L,row.attempts); assertEquals(CommandDelivery.RECONCILE,row.delivery)
        }
        main { controller.openAppUpdates() }
        until("installed package and full bytes confirmed") { controller.state.value.appUpdates?.let { !it.busy && it.phase == AppUpdatePhase.INSTALLED } == true }
        val installed = backend.read(slot)!!.record
        assertEquals(AppInstallPhase.INSTALLED,installed.phase); assertEquals(input.string("candidate_sha256"),installed.release.sha256)
        assertTrue(backend.installedArtifact(installed))
        compose.onNodeWithText("已核对当前安装版本").performScrollTo().assertIsDisplayed()
        File(directory,"result.json").writeBytes(JsonDocument.of(jsonObject("run_id" to run.json(),"state" to "passed".json(),"device_id" to after.deviceId!!.json(),
            "proof_key_jkt" to after.session.proofKeyThumbprint.json(),"approval_key_jkt" to after.approvalKeyJkt!!.json(),"installed_sha256" to installed.release.sha256.json(),"room_attempts" to 1L.json())).canonicalBytes())
        main { controller.close(); biometric?.cancel() }; scenario?.close()
        backend.cancel(slot,installed.id); AppInstallationStorage(context,slot).erase(backend.read(slot)!!.revision)
        AccountVault(context,slot).clear(); PendingKeyLedger(context,ledger).recover(); SqlCommandJournal.eraseAccount(context,after.accountId,after.organizationId)
        transport.dispatcher.cancelAll(); transport.connectionPool.evictAll(); transport.dispatcher.executorService.shutdownNow()
    }
}
