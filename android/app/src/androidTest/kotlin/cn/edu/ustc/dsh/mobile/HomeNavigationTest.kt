package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import androidx.activity.ComponentActivity
import androidx.annotation.StringRes
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.auth.EnrollmentCheckpoint
import cn.edu.ustc.dsh.auth.PushDeployment
import cn.edu.ustc.dsh.network.SessionReadPhase
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.ui.DshTheme
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

/** Opt-in controller/Compose composition: local TLS, encrypted checkpoint and Android keys. */
@RunWith(AndroidJUnit4::class)
class HomeNavigationTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private var fixture: AccountFixture? = null
    private var controller: LoginController? = null
    private val model = mutableStateOf<HomeViewModel?>(null)
    private var center: NotificationCenter? = null

    @Before fun setup() {
        assumeTrue("explicit account fixture required", InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        assertTrue("secure unlocked fixture required", context.getSystemService(KeyguardManager::class.java).let { it.isDeviceSecure && !it.isDeviceLocked })
        fixture = AccountFixture(context).also { it.seed() }
        val accepted = fixture!!.checkpoint()!!
        assertEquals(EnrollmentCheckpoint.ACTIVE, accepted.enrollment)
        assertEquals(fixture!!.deviceId, accepted.deviceId)
        assertEquals(fixture!!.proofJkt, accepted.session.proofKeyThumbprint)
        assertNotEquals(accepted.session.proofKeyThumbprint, accepted.approvalKeyJkt)
    }

    @After fun cleanup() {
        main { controller?.close() }
        center?.let { hub ->
            hub.retire()
            fixture?.let { server -> runBlocking { hub.drain(server.http) }; PushStorage(context, server.slot).destroy() }
        }
        fixture?.close()
    }

    private fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
    private fun text(@StringRes id: Int, vararg arguments: Any): String = context.getString(id, *arguments)
    private fun action(@StringRes id: Int) = rule.onNode(hasText(text(id)) and hasClickAction())
    private fun listAction(tag: String, @StringRes id: Int): SemanticsNodeInteraction {
        rule.onNodeWithTag(tag).performScrollToNode(hasText(text(id)))
        return action(id)
    }
    private fun tab(@StringRes id: Int) = action(id)
    private fun row() = rule.onNodeWithTag("session-${fixture!!.sessionId}")
    private fun until(label: String, condition: () -> Boolean) {
        try {
            rule.waitUntil(30_000) {
                fixture!!.failure.get()?.let { throw AssertionError(it) }
                condition()
            }
        } catch (error: ComposeTimeoutException) {
            val state = controller?.state?.value
            throw AssertionError("Timed out: $label; phase=${state?.phase}; runtime=${state?.selectedRuntimeId}; session=${state?.selectedSessionId}; read=${state?.reader?.phase}; error=${state?.error}/${state?.sessionError}", error)
        }
    }

    private fun start(environment: LoginEnvironment = fixture!!.environment()) {
        main {
            controller = LoginController(context, fixture!!.http, environment)
            model.value = HomeViewModel(controller!!)
        }
        rule.setContent { model.value?.let { current -> DshTheme { HomeRoute(current, {}, current::cancel) } } }
        main { controller!!.foreground(true) }
    }

    private fun directory() {
        until("automatic authorized session directory") {
            controller!!.state.value.let { state ->
                state.phase == HomePhase.READY && !state.refreshing && !state.loadingSessions &&
                    state.selectedRuntimeId == fixture!!.runtimeId && state.selectedSessionId == null &&
                    state.sessions.singleOrNull()?.id == fixture!!.sessionId
            }
        }
        tab(R.string.nav_sessions).assertIsSelected()
        rule.onNodeWithTag("session-${fixture!!.sessionId}").assertIsDisplayed()
    }

    private fun openRead(expectedSubscriptions: Int) {
        row().performClick()
        until("single tap opens confirmed scoped reader") {
            controller!!.state.value.let { state ->
                state.selectedRuntimeId == fixture!!.runtimeId && state.selectedSessionId == fixture!!.sessionId &&
                    state.reader?.let { it.phase == SessionReadPhase.READY && it.window?.persistedThrough == 2L } == true &&
                    fixture!!.subscriptions.get() == expectedSubscriptions
            }
        }
        assertEquals(expectedSubscriptions, fixture!!.ticketRequests.get())
        val scope = fixture!!.ticketScopes.last()
        assertEquals(setOf(fixture!!.sessionId), scope.sessions)
        assertEquals(setOf("session.read"), scope.actions)
        assertTrue(scope.workspaces.isEmpty())
        assertEquals("电脑当前消息", controller!!.state.value.reader!!.window!!.items.single().blocks.single().text)
    }

    private fun systemBack() {
        rule.runOnIdle { rule.activity.onBackPressedDispatcher.onBackPressed() }
    }

    private fun assertRetired(expectedClosures: Int) {
        until("relay closed and reader retired") {
            fixture!!.relayClosures.get() >= expectedClosures && controller!!.state.value.reader == null && controller!!.state.value.selectedSessionId == null
        }
        assertNull(controller!!.state.value.outbox)
    }

    @Test fun restoredReadyListsAutomaticallyAndBothBackActionsReturnToTheSameDirectory() {
        fixture!!.holdSessions = true
        start()
        until("restored READY starts its first authorized directory without a computer tap") {
            controller!!.state.value.phase == HomePhase.READY && fixture!!.sessionRequests.get() == 1
        }
        assertEquals(0, fixture!!.ticketRequests.get())
        assertEquals(0, fixture!!.subscriptions.get())
        fixture!!.holdSessions = false
        directory()
        val rows = controller!!.state.value.sessions
        val requests = fixture!!.sessionRequests.get()

        openRead(1)
        rule.onNodeWithContentDescription("返回会话列表").performClick()
        assertRetired(1)
        directory()
        assertSame(rows, controller!!.state.value.sessions)
        assertEquals(requests, fixture!!.sessionRequests.get())

        openRead(2)
        systemBack()
        assertRetired(2)
        directory()
        assertSame(rows, controller!!.state.value.sessions)
        assertEquals(requests, fixture!!.sessionRequests.get())
        assertEquals(2, fixture!!.ticketRequests.get())
    }

    @Test fun switchingComputersAndSettingsRetiresTheContextWithoutHiddenReaders() {
        start(); directory(); openRead(1)
        systemBack(); assertRetired(1); directory()
        tab(R.string.nav_computers).performClick()
        until("computer destination clears directory ownership") { controller!!.state.value.selectedRuntimeId == null }
        tab(R.string.nav_computers).assertIsSelected()
        assertTrue(controller!!.state.value.sessions.isEmpty())
        assertNull(controller!!.state.value.reader)
        assertEquals(1, fixture!!.ticketRequests.get())

        listAction("computers-directory", R.string.action_open_sessions).performClick()
        directory()
        rule.onNodeWithContentDescription(text(R.string.action_back_computers)).performClick()
        until("computer-origin directory back retires its selection") { controller!!.state.value.selectedRuntimeId == null }
        tab(R.string.nav_computers).assertIsSelected()

        tab(R.string.nav_sessions).performClick(); directory(); openRead(2)
        rule.onNodeWithContentDescription("返回会话列表").performClick()
        assertRetired(2); directory()
        tab(R.string.nav_settings).performClick()
        until("settings destination clears directory ownership") { controller!!.state.value.selectedRuntimeId == null }
        tab(R.string.nav_settings).assertIsSelected()
        assertTrue(controller!!.state.value.sessions.isEmpty())
        assertNull(controller!!.state.value.reader)
        assertEquals(2, fixture!!.ticketRequests.get())
        assertEquals(2, fixture!!.subscriptions.get())
    }

    @Test fun notificationAndUpdateChildrenReturnToSettingsWithEitherBackAction() {
        start(); directory()
        tab(R.string.nav_settings).performClick()
        val requests = fixture!!.sessionRequests.get()
        listAction("settings-list", R.string.settings_notifications).performClick()
        until("notification settings child") { controller!!.state.value.notificationSettings }
        rule.onNodeWithText("返回").performScrollTo().performClick()
        until("page back closes notification child") { !controller!!.state.value.notificationSettings }
        tab(R.string.nav_settings).assertIsSelected()
        listAction("settings-list", R.string.settings_notifications).performClick()
        until("notification child reopens") { controller!!.state.value.notificationSettings }
        systemBack()
        until("system back closes notification child") { !controller!!.state.value.notificationSettings }
        tab(R.string.nav_settings).assertIsSelected()

        listAction("settings-list", R.string.settings_updates).performClick()
        until("app update settings child") { controller!!.state.value.appUpdateSettings }
        rule.onNodeWithText("返回").performScrollTo().performClick()
        until("page back closes update child") { !controller!!.state.value.appUpdateSettings }
        tab(R.string.nav_settings).assertIsSelected()
        listAction("settings-list", R.string.settings_updates).performClick()
        until("update child reopens") { controller!!.state.value.appUpdateSettings }
        systemBack()
        until("system back closes update child") { !controller!!.state.value.appUpdateSettings }
        tab(R.string.nav_settings).assertIsSelected()
        assertNull(controller!!.state.value.selectedRuntimeId)
        assertNull(controller!!.state.value.reader)
        assertEquals(requests, fixture!!.sessionRequests.get())
        assertEquals(0, fixture!!.ticketRequests.get())
    }

    @Test fun signoutDiscardsNavigationEvenWhenTheSameAccountIsRestoredInTheSameComposition() {
        start(); directory(); openRead(1)
        systemBack(); assertRetired(1); directory()
        tab(R.string.nav_settings).performClick()
        listAction("settings-list", R.string.action_exit_account).performClick()
        rule.onNode(hasText(text(R.string.action_exit_account)) and hasAnyAncestor(isDialog())).performClick()
        until("local account and reader cleared") { controller!!.state.value.phase == HomePhase.SIGNED_OUT && fixture!!.vault.read() == null }
        rule.onNodeWithText("使用学校账号登录").assertIsDisplayed()
        rule.onAllNodes(hasText(text(R.string.nav_settings)) and hasClickAction()).assertCountEquals(0)
        assertNull(controller!!.state.value.reader)
        assertNull(controller!!.state.value.selectedRuntimeId)
        assertNull(controller!!.state.value.selectedSessionId)
        assertTrue(controller!!.state.value.sessions.isEmpty())

        main { controller!!.close() }
        fixture!!.seed()
        main {
            controller = LoginController(context, fixture!!.http, fixture!!.environment())
            model.value = HomeViewModel(controller!!)
            controller!!.foreground(true)
        }
        directory()
        assertEquals(1, fixture!!.ticketRequests.get())
        assertEquals(1, fixture!!.subscriptions.get())
        assertNull(controller!!.state.value.reader)
        assertFalse(controller!!.state.value.notificationSettings)
        assertFalse(controller!!.state.value.appUpdateSettings)
    }

    @Test fun listOnlyAuthorizationNeverStartsAReader() {
        fixture!!.allowSessionRead = false
        start(); directory()
        rule.onNodeWithTag("session-${fixture!!.sessionId}").assertHasNoClickAction()
        assertNull(controller!!.state.value.reader)
        assertNull(controller!!.state.value.selectedSessionId)
        assertEquals(0, fixture!!.ticketRequests.get())
        assertEquals(0, fixture!!.subscriptions.get())
    }

    @Test fun knownSessionNotificationKeepsMinimalAccessAndReturnsToSettingsWithoutListing() {
        val server = fixture!!
        server.pushMode = true; server.questionMode = true; server.pushReferenceKind = "question"
        server.allowSessionList = false; server.allowHostList = false; server.allowCommandStatus = false
        val config = PushDeployment.parse(JsonDocument.of(jsonObject("v" to 1L.json(), "deployment_sha256" to server.config.fingerprint.json(), "package_name" to context.packageName.json(),
            "fcm" to jsonObject("project_id" to "fixture-project".json(), "application_id" to "1:123456789:android:abcdef012345".json(), "sender_id" to "123456789".json(), "api_key" to "fixture_public_key_1234567890".json()))).canonicalBytes(), server.config.fingerprint, context.packageName)
        start(server.environment(pushProvider = { hub ->
            center = hub
            server.pushDeliver = { packet -> hub.receive(config, config.senderId, packet) }
            object : DevicePushProvider {
                override val configuration = config
                override fun availability() = "ready"
                override suspend fun register() = "c" + "A".repeat(21)
                override suspend fun unregister() {}
            }
        }))
        until("minimal account authorization and notification channel ready") {
            controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing && it.notifications?.let { n -> !n.busy && n.canEnable } == true }
        }
        assertTrue(controller!!.state.value.runtimes.isEmpty())
        assertEquals(0, server.sessionRequests.get())
        tab(R.string.nav_settings).performClick()
        listAction("settings-list", R.string.settings_notifications).performClick()
        main { controller!!.enableNotifications() }
        until("real notification binding accepted") { controller!!.state.value.notifications?.phase == NotificationPhase.ACTIVE }
        val route = center!!.snapshot().route!!
        center!!.receive(config, config.senderId, mapOf("v" to "1", "kind" to "interaction", "binding_id" to route.id,
            "notification_id" to server.pushNotificationId, "expires_at" to Instant.now().plusSeconds(60).toString()))
        main { controller!!.openNotification(route.id, server.pushNotificationId) }
        until("known resource reauthorized and subscribed without directory rights") {
            controller!!.state.value.let { it.reader?.phase == SessionReadPhase.READY && it.notificationQuestion?.questionId == server.ordinaryQuestionId }
        }
        assertTrue(controller!!.state.value.runtimes.isEmpty())
        assertFalse(controller!!.state.value.knownTarget!!.runtime.canList())
        assertFalse("command.status" in controller!!.state.value.knownTarget!!.runtime.scope!!.actions)
        assertEquals(1, server.targetRequests.get())
        assertEquals(0, server.sessionRequests.get())
        assertEquals(setOf(server.sessionId), server.ticketScopes.single().sessions)
        assertFalse("session.list" in server.ticketScopes.single().actions)
        assertFalse("command.status" in server.ticketScopes.single().actions)
        assertEquals(0, server.questionWrites.get())

        rule.onNodeWithContentDescription("返回提醒").performClick()
        assertRetired(1)
        assertTrue(controller!!.state.value.notificationSettings)
        assertNull(controller!!.state.value.knownTarget)
        systemBack()
        until("notification child closes back to settings") { !controller!!.state.value.notificationSettings }
        tab(R.string.nav_settings).assertIsSelected()
        assertEquals(0, server.sessionRequests.get())
        assertEquals(1, server.ticketRequests.get())
    }
}
