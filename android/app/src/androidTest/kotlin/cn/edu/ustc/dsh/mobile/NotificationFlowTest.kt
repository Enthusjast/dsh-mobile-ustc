package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import android.app.NotificationManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.auth.PushDeployment
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.QuestionPhase
import kotlinx.coroutines.runBlocking
import org.junit.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger

@RunWith(AndroidJUnit4::class)
class NotificationFlowTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private var fixture: AccountFixture? = null
    private var controller: LoginController? = null
    private lateinit var environment: LoginEnvironment
    private lateinit var center: NotificationCenter
    private lateinit var config: PushDeployment
    private val providerCalls = AtomicInteger()
    private fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
    private fun await(check: () -> Boolean) {
        val deadline = android.os.SystemClock.elapsedRealtime() + 45_000
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            fixture!!.failure.get()?.let { throw AssertionError(it) }
            if (check()) return
            Thread.sleep(25)
        }
        val state = controller!!.state.value
        throw AssertionError("notification fixture timed out; phase=${state.notifications?.phase}; error=${state.notifications?.error}; reader=${state.reader?.phase}/${state.reader?.error}; command=${state.commandError}; known=${state.knownTarget != null}; canAnswer=${state.reader?.questions?.canAnswer}; note=${state.notificationNote}; lookups=${fixture!!.targetRequests.get()}")
    }
    @Before fun setup() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        assertTrue(context.getSystemService(KeyguardManager::class.java).let { it.isDeviceSecure && !it.isDeviceLocked })
        fixture = AccountFixture(context).also { it.pushMode = true; it.approvalMode = true; it.questionMode = true; it.seed() }
        val server = fixture!!
        config = PushDeployment.parse(JsonDocument.of(jsonObject("v" to 1L.json(), "deployment_sha256" to server.config.fingerprint.json(), "package_name" to context.packageName.json(),
            "fcm" to jsonObject("project_id" to "fixture-project".json(), "application_id" to "1:123456789:android:abcdef012345".json(), "sender_id" to "123456789".json(), "api_key" to "fixture_public_key_1234567890".json()))).canonicalBytes(), server.config.fingerprint, context.packageName)
        environment = server.environment(pushProvider = { hub ->
            center = hub
            server.pushDeliver = { packet -> hub.receive(config, config.senderId, packet) }
            object : DevicePushProvider {
                override val configuration = config
                override fun availability() = "ready"
                override suspend fun register(): String { providerCalls.incrementAndGet(); return "c" + "A".repeat(21) }
                override suspend fun unregister() {}
            }
        })
        main { controller = LoginController(context, server.http, environment); controller!!.foreground(true) }
        await { controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing && it.notifications?.let { n -> !n.busy && n.canEnable } == true } }
        main { controller!!.enableNotifications() }
        await { controller!!.state.value.notifications?.let { !it.busy && it.phase == NotificationPhase.ACTIVE } == true }
    }
    @After fun cleanup() {
        if (::center.isInitialized) { center.retire(); fixture?.let { runBlocking { center.drain(it.http) } }; PushStorage(context, environment.storageSlot).destroy() }
        main { controller?.close() }; fixture?.close()
    }
    private fun interaction() {
        val route = center.snapshot().route!!
        center.receive(config, config.senderId, mapOf("v" to "1", "kind" to "interaction", "binding_id" to route.id, "notification_id" to fixture!!.pushNotificationId, "expires_at" to Instant.now().plusSeconds(60).toString()))
    }
    @Test fun backgroundReceptionAndTapReauthorizeBeforeOpeningAFreshUnsignedReview() {
        val owner = controller!!; val original = center.snapshot().route!!.id
        assertEquals(1, fixture!!.pushRegistrations.get()); assertEquals(1, fixture!!.pushConfirmations.get())
        main { owner.openBinding(); owner.foreground(false) }; interaction()
        assertTrue(center.snapshot().notices.single().posted)
        main { owner.openNotification(original, fixture!!.pushNotificationId); owner.foreground(true) }
        await { owner.state.value.notifications?.phase == NotificationPhase.ACTIVE }
        await { owner.state.value.reviewingApprovalId == fixture!!.approvalBody.root.string("approval_id") && owner.state.value.approvals?.view?.items?.any { it.handle != null } == true }
        assertNull(owner.state.value.binding)
        assertEquals(1, fixture!!.pushReads.get())
        assertEquals(ApprovalUiStage.IDLE, owner.state.value.approvalStage); assertNull(owner.state.value.authenticationId)
        assertEquals(0, fixture!!.approvalWrites.get())
    }
    @Test fun recreationOnlyQueriesTheOriginalChannelAndEndedReferencesCannotOpenAReview() {
        val original = center.snapshot().route!!.id
        main { controller!!.close(); controller = LoginController(context, fixture!!.http, environment); controller!!.foreground(true) }
        await { controller!!.state.value.notifications?.phase == NotificationPhase.ACTIVE }
        assertEquals(original, center.snapshot().route!!.id); assertEquals(1, fixture!!.pushRegistrations.get()); assertEquals(1, providerCalls.get())
        interaction(); fixture!!.pushReferenceState = "denied"; fixture!!.pushReferenceAvailability = "ended"
        main { controller!!.openNotification(original, fixture!!.pushNotificationId) }
        await { controller!!.state.value.notifications?.note != null }
        assertNull(controller!!.state.value.reviewingApprovalId); assertEquals(0, fixture!!.approvalWrites.get())
    }
    @Test fun leavingNotificationSettingsFencesAnInFlightReferenceRead() {
        main { controller!!.openRuntime(fixture!!.runtimeId) }
        await { controller!!.state.value.sessions.isNotEmpty() }
        main { controller!!.openSession(fixture!!.sessionId) }
        await { controller!!.state.value.reader?.phase == cn.edu.ustc.dsh.network.SessionReadPhase.READY }
        interaction(); fixture!!.holdPushReference = true
        main { controller!!.openNotification(center.snapshot().route!!.id, fixture!!.pushNotificationId) }
        await { fixture!!.pushReads.get() == 1 }
        assertNull(controller!!.state.value.reader)
        main { controller!!.back() }
        Thread.sleep(2_500)
        assertFalse(controller!!.state.value.notificationSettings)
        assertNull(controller!!.state.value.selectedSessionId)
        assertNull(controller!!.state.value.reviewingApprovalId)
        assertEquals(0, fixture!!.approvalWrites.get())
    }
    @Test fun ordinaryQuestionTapRequiresFreshNativeStateAndAnExplicitAnswer() {
        val server = fixture!!; server.pushReferenceKind = "question"
        interaction()
        main { controller!!.openNotification(center.snapshot().route!!.id, server.pushNotificationId) }
        await { controller!!.state.value.notificationQuestion?.questionId == server.ordinaryQuestionId }
        assertEquals(0, server.questionWrites.get()); assertEquals(0, server.claimWrites.get()); assertEquals(0, server.approvalWrites.get())
        val row = controller!!.state.value.reader!!.questions.items.single { it.batch.id == server.ordinaryQuestionId }
        main { controller!!.answerQuestion(row.handle, QuestionAnswers(row.batch.id, listOf(QuestionAnswer("plan", listOf("继续"), "通知后明确答复")))) }
        await { server.questionWrites.get() == 1 && controller!!.state.value.reader!!.questions.items.none { it.batch.id == row.batch.id } }
        assertEquals(0, server.approvalWrites.get())
    }
    @Test fun aContinuedTimedNotificationOpensTheFreshLateAnswerFormWithoutClaiming() {
        val server = fixture!!; server.pushReferenceKind = "timed_question"; server.pushReferenceState = "continued"; server.blockingPending = false; server.timedQuestionState = "continued"
        val route = center.snapshot().route!!.id
        main { controller!!.foreground(false) }; interaction()
        main { controller!!.openNotification(route, server.pushNotificationId); controller!!.foreground(true) }
        await { controller!!.state.value.notificationQuestion?.questionId == server.timedQuestionId }
        val row = controller!!.state.value.reader!!.questions.items.single { it.batch.id == server.timedQuestionId }
        assertEquals(QuestionPhase.CONTINUED, row.batch.phase)
        assertEquals(0, server.questionWrites.get()); assertEquals(0, server.claimWrites.get()); assertEquals(0, server.approvalWrites.get())
        main { controller!!.answerQuestion(row.handle, QuestionAnswers(row.batch.id, listOf(QuestionAnswer("timed", listOf("回复"), "通知后补充答复")))) }
        await { server.questionWrites.get() == 1 && controller!!.state.value.outbox?.records?.any { it.everAgentQueued } == true }
        assertEquals(0, server.claimWrites.get()); assertEquals(0, server.approvalWrites.get())
    }
    @Test fun endedAndMismatchedReferencesCannotSelectAnotherCurrentQuestion() {
        val server = fixture!!; server.pushReferenceKind = "question"; server.pushReferenceState = "ended"; server.pushReferenceAvailability = "ended"
        interaction()
        main { controller!!.openNotification(center.snapshot().route!!.id, server.pushNotificationId) }
        await { controller!!.state.value.notifications?.note != null }
        assertNull(controller!!.state.value.selectedSessionId); assertNull(controller!!.state.value.notificationQuestion)
        server.pushReferenceState = "pending"; server.pushReferenceAvailability = "online"; server.pushReferenceId = java.util.UUID.randomUUID().toString()
        main { controller!!.openNotification(center.snapshot().route!!.id, server.pushNotificationId) }
        await { controller!!.state.value.notificationNote != null }
        assertNull(controller!!.state.value.notificationQuestion); assertEquals(0, server.questionWrites.get()); assertEquals(0, server.claimWrites.get())
    }
    @Test fun aKnownQuestionOpensAndReconcilesWithoutDirectoryOrGenericStatusRights() {
        val server = fixture!!
        server.allowSessionList = false; server.allowHostList = false; server.allowCommandStatus = false; server.pushReferenceKind = "question"
        main { controller!!.refresh() }
        await { !controller!!.state.value.refreshing && controller!!.state.value.runtimes.isEmpty() }
        val lists = server.sessionRequests.get()
        interaction(); main { controller!!.openNotification(center.snapshot().route!!.id, server.pushNotificationId) }
        await { controller!!.state.value.notificationQuestion?.questionId == server.ordinaryQuestionId }
        assertTrue(controller!!.state.value.runtimes.isEmpty())
        assertFalse(controller!!.state.value.knownTarget!!.runtime.canList())
        assertFalse("command.status" in controller!!.state.value.knownTarget!!.runtime.scope!!.actions)
        val row = controller!!.state.value.reader!!.questions.items.single { it.batch.id == server.ordinaryQuestionId }
        main { controller!!.answerQuestion(row.handle, QuestionAnswers(row.batch.id, listOf(QuestionAnswer("plan", listOf("继续"), "最小授权答复")))) }
        await { controller!!.state.value.outbox?.records?.any { it.remote == cn.edu.ustc.dsh.command.RemoteCommandState.SETTLED } == true }
        assertEquals(1, server.questionWrites.get()); assertTrue(server.answerStatusRequests.get() > 0); assertEquals(lists, server.sessionRequests.get())
        main { controller!!.foreground(false); controller!!.foreground(true) }
        await { server.targetRequests.get() >= 2 && controller!!.state.value.reader?.phase == cn.edu.ustc.dsh.network.SessionReadPhase.READY }
        main { controller!!.back() }
        assertTrue(controller!!.state.value.notificationSettings); assertNull(controller!!.state.value.knownTarget)
        assertEquals(lists, server.sessionRequests.get())
    }
    @Test fun aLateKnownTargetLookupCannotRestoreTheLoggedOutAccount() {
        val server = fixture!!; server.holdSessionTarget = true
        interaction(); main { controller!!.openNotification(center.snapshot().route!!.id, server.pushNotificationId) }
        await { server.targetRequests.get() == 1 }
        main { controller!!.cancel() }
        await { controller!!.state.value.phase == HomePhase.SIGNED_OUT }
        Thread.sleep(2_500)
        assertEquals(HomePhase.SIGNED_OUT, controller!!.state.value.phase); assertNull(controller!!.state.value.knownTarget); assertNull(controller!!.state.value.reader)
    }
    @Test fun leavingDuringARefreshCannotRestoreTheKnownSessionContext() {
        val server = fixture!!; server.pushReferenceKind = "question"
        interaction(); main { controller!!.openNotification(center.snapshot().route!!.id, server.pushNotificationId) }
        await { controller!!.state.value.notificationQuestion?.questionId == server.ordinaryQuestionId }
        val reads = server.targetRequests.get()
        server.holdSessionTarget = true
        main { controller!!.refresh() }
        await { server.targetRequests.get() > reads }
        main { controller!!.back() }
        await { !controller!!.state.value.refreshing }
        assertTrue(controller!!.state.value.notificationSettings)
        assertNull(controller!!.state.value.knownTarget); assertNull(controller!!.state.value.reader); assertNull(controller!!.state.value.selectedSessionId)
    }
    @Test fun localLogoutFencesLatePacketsAndCanDeleteTheChannelWithoutOldCredentials(): Unit = runBlocking {
        val original = center.snapshot().route!!.id
        main { controller!!.foreground(false) }; interaction()
        fixture!!.pushCleanupUnavailable = true
        main { controller!!.cancel() }
        await { controller!!.state.value.phase == HomePhase.SIGNED_OUT }
        assertNull(center.snapshot().route)
        assertEquals(original, center.snapshot().revocations.single().id)
        center.receive(config, config.senderId, mapOf("v" to "1", "kind" to "interaction", "binding_id" to original, "notification_id" to fixture!!.pushNotificationId, "expires_at" to Instant.now().plusSeconds(60).toString()))
        assertTrue(context.getSystemService(NotificationManager::class.java).activeNotifications.none { it.tag == "dsh-interactions-${environment.storageSlot}" })
        assertFalse(center.drain(fixture!!.http)); fixture!!.pushCleanupUnavailable = false
        assertTrue(center.drain(fixture!!.http)); assertEquals(1, fixture!!.pushCleanups.get())
        assertEquals("disabled", fixture!!.pushStates[original])
    }
}
