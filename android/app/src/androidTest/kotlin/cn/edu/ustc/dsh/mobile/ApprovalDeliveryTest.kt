package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.lifecycle.lifecycleScope
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.keystore.DeviceCryptoException
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import cn.edu.ustc.dsh.ui.DshTheme
import kotlinx.coroutines.launch
import org.junit.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class ApprovalDeliveryTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private var fixture: AccountFixture? = null
    private var controller: LoginController? = null
    private fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
    @Before fun setup() {
        assumeTrue("explicit owned account fixture required", InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        val guard = instrumentation.targetContext.getSystemService(KeyguardManager::class.java)
        assertTrue(guard.isDeviceSecure && !guard.isDeviceLocked)
        fixture = AccountFixture(instrumentation.targetContext).also { it.approvalMode = true }
    }
    @After fun cleanup() { main { controller?.close() }; fixture?.close() }
    private fun until(label: String, test: () -> Boolean) {
        val deadline = android.os.SystemClock.elapsedRealtime() + 45_000
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            fixture!!.failure.get()?.let { throw AssertionError(it) }
            if (test()) return
            Thread.sleep(25)
        }
        throw AssertionError("Timed out: $label; phase=${controller?.state?.value?.phase}; approval=${controller?.state?.value?.approvalStage}; error=${controller?.state?.value?.approvalError}")
    }
    private fun start(promptMillis: Long = MAX_DECISION_AGE_MS) {
        fixture!!.seed()
        restore(promptMillis)
    }
    private fun restore(promptMillis: Long = MAX_DECISION_AGE_MS) {
        main { controller = LoginController(instrumentation.targetContext, fixture!!.http, fixture!!.environment(approvalPromptMillis = promptMillis)); controller!!.foreground(true) }
        until("account directory") { controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing && it.runtimes.size == 1 } }
        main { controller!!.openRuntime(fixture!!.runtimeId) }
        until("session directory") { !controller!!.state.value.loadingSessions && controller!!.state.value.sessions.isNotEmpty() }
        main { controller!!.openSession(fixture!!.sessionId) }
        until("approval watch") { controller!!.state.value.approvals?.let { it.connected && it.contentReady && it.view.loaded } == true }
    }
    private fun review(): ApprovalReviewHandle {
        main { controller!!.reviewApproval(fixture!!.approvalBody.root.string("approval_id")) }
        until("complete online details") { controller!!.state.value.approvals?.view?.items?.any { it.handle != null } == true }
        return controller!!.state.value.approvals!!.view.items.single { it.handle != null }.handle!!
    }
    private fun prepared(handle: ApprovalReviewHandle, choice: ApprovalChoice = ApprovalChoice.ALLOW_ONCE): BiometricLaunch {
        main { controller!!.decideApproval(handle, choice) }
        until("per-use operation") { controller!!.state.value.biometric != null && controller!!.state.value.approvalStage == ApprovalUiStage.AUTHENTICATING }
        return controller!!.state.value.biometric!!
    }
    private fun progress(phase: String, token: String) {
        val run = InstrumentationRegistry.getArguments().getString("accountFixtureRun") ?: return
        instrumentation.sendStatus(2, Bundle().apply { putString("stream", "\nAPPROVAL_FIXTURE_BIOMETRIC_$phase $run $token\n") })
    }
    /** Uses the production Activity prompt adapter and the actual controller/key operation. */
    private fun host(render: Boolean = false): ActivityScenario<MainActivity> {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        scenario.onActivity { activity ->
            val current = controller!!; val tokens = mutableMapOf<Long, String>()
            val ui = BiometricUi(activity, current::promptOpened, { id, result -> tokens.remove(id)?.let { progress("DONE", it) }; current.authenticated(id, result) },
                { id -> tokens.remove(id)?.let { progress("DONE", it) }; current.authenticationCancelled(id) })
            activity.lifecycleScope.launch {
                current.state.collect { state ->
                    val launch = state.biometric
                    val token = launch?.let { UUID.randomUUID().toString().also { token -> tokens[it.id] = token } }
                    ui.update(state.authenticationId, launch)
                    if (token != null) progress("READY", token)
                }
            }
            if (render) activity.setContent { DshTheme { HomeRoute(HomeViewModel(current), {}, current::cancel) } }
        }
        return scenario
    }

    @Test fun reviewedUiUsesARealBiometricSignatureAndSeparatesAcceptanceFromNativeOutcome() {
        val test = fixture!!; test.approvalNativeResult = false; start(); review()
        host(render = true).use {
            compose.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsNotEnabled()
            compose.onNodeWithText("我已核对本页").performScrollTo().performClick()
            compose.onNodeWithText("我已核对全部动作、参数及资源，仅为本次调用作出决定。").performScrollTo().performClick()
            compose.onNodeWithText("仅本次允许并确认身份").performScrollTo().performClick()
            until("signed decision accepted") { controller!!.state.value.approvals?.records?.singleOrNull()?.delivery == ApprovalDecisionDelivery.ACCEPTED }
            val row = controller!!.state.value.approvals!!.records.single()
            val remote = row.remote!!
            assertNull(remote.hostState); assertNull(remote.outcome); assertEquals(1L, row.attempts)
            assertEquals(ApprovalChoice.ALLOW_ONCE, test.lastApproval.get()!!.decision.choice); assertEquals(1, test.approvalWrites.get())
            test.reportApproval(test.currentApprovalStatus().with("state" to "allowed".json(), "host_state" to "settled".json(), "execution_outcome" to "succeeded".json()))
            until("native result") { controller!!.state.value.approvals?.records?.singleOrNull()?.remote?.hostState == ApprovalHostState.SETTLED }
            assertEquals("工具执行成功，电脑已保存原生结果", approvalRecordLabel(controller!!.state.value.approvals!!.records.single()))
        }
    }
    @Test fun rejectUsesItsOwnRealPerUseAuthenticationAndExactSignedChoice() {
        start(); review()
        host(render = true).use {
            compose.onNodeWithText("拒绝并确认身份").performScrollTo().assertIsEnabled().performClick()
            until("native deny") { controller!!.state.value.approvals?.records?.singleOrNull()?.remote?.hostState == ApprovalHostState.DENIED }
            assertEquals(ApprovalChoice.REJECT, fixture!!.lastApproval.get()!!.decision.choice)
            assertEquals(1, fixture!!.approvalWrites.get())
        }
    }
    @Test fun cancelledAndLatePromptCallbacksCannotCancelANewerPreparation() {
        start(); val handle = review(); val first = prepared(handle)
        main { controller!!.authenticationCancelled(first.id) }
        until("first preparation cancelled") { controller!!.state.value.approvalStage == ApprovalUiStage.IDLE && controller!!.state.value.approvals?.signing == false }
        val second = prepared(handle, ApprovalChoice.REJECT)
        assertNotEquals(first.id, second.id)
        main { controller!!.authenticationCancelled(first.id) }
        assertEquals(second.id, controller!!.state.value.authenticationId)
        main { controller!!.closeApprovalReview() }
        assertNull(controller!!.state.value.authenticationId); assertNull(controller!!.state.value.reviewingApprovalId)
        assertThrows(DeviceCryptoException::class.java) { first.operation.cryptoObject }
        assertThrows(DeviceCryptoException::class.java) { second.operation.cryptoObject }
        assertEquals(0, fixture!!.approvalWrites.get())
    }
    @Test fun currentExpiryRetiresThePromptAndItsOldCryptoObject() {
        start(); val launch = prepared(review())
        fixture!!.endApproval("expired")
        until("expiry prompt cleanup") { controller!!.state.value.authenticationId == null && controller!!.state.value.approvalStage == ApprovalUiStage.IDLE }
        assertThrows(DeviceCryptoException::class.java) { launch.operation.cryptoObject }
        assertEquals(0, fixture!!.approvalWrites.get())
        assertTrue(controller!!.state.value.approvals!!.view.items.none { it.canReview })
    }
    @Test fun leavingForegroundDropsReviewAuthorityAndRequiresAnotherOnlineLookup() {
        start(); val old = review(); val launch = prepared(old)
        main { controller!!.foreground(false) }
        assertNull(controller!!.state.value.approvals); assertNull(controller!!.state.value.authenticationId); assertNull(controller!!.state.value.reviewingApprovalId)
        assertThrows(DeviceCryptoException::class.java) { launch.operation.cryptoObject }
        main { controller!!.foreground(true) }
        until("fresh foreground watch") { controller!!.state.value.approvals?.let { it.connected && it.contentReady && it.view.loaded } == true }
        assertTrue(controller!!.state.value.approvals!!.view.items.all { it.context == null })
        main { controller!!.decideApproval(old, ApprovalChoice.ALLOW_ONCE) }
        assertNull(controller!!.state.value.authenticationId); assertEquals(0, fixture!!.approvalWrites.get())
        assertNotEquals(old, review())
    }
    @Test fun aLostHttpReceiptAndControllerRecreationKeepOneOriginalPlatformSignedDecision() {
        fixture!!.dropApprovalReply = true; start(); val handle = review()
        host().use {
            main { controller!!.decideApproval(handle, ApprovalChoice.ALLOW_ONCE) }
            until("original result reconciled") { controller!!.state.value.approvals?.records?.singleOrNull()?.delivery == ApprovalDecisionDelivery.ACCEPTED && controller!!.state.value.approvalStage == ApprovalUiStage.IDLE }
        }
        val original = controller!!.state.value.approvals!!.records.single()
        main { controller!!.close(); controller = null }; restore()
        until("encrypted original reopened") { controller!!.state.value.approvals?.records?.singleOrNull()?.intent?.requestId == original.intent.requestId }
        val restored = controller!!.state.value.approvals!!.records.single()
        assertEquals(original.intent.digest, restored.intent.digest); assertTrue(original.intent.signed.compact == restored.intent.signed.compact)
        assertEquals(1L, restored.attempts); assertEquals(1, fixture!!.approvalWrites.get())
        assertNull(controller!!.state.value.authenticationId); assertNull(controller!!.state.value.reviewingApprovalId)
        assertTrue(controller!!.state.value.approvals!!.view.items.all { it.handle == null })
    }
    @Test fun localBiometricsDoNotSatisfyAnUnmetSchoolAssurancePolicy() {
        fixture!!.approvalAssurance = false; start(); val handle = review()
        host().use {
            main { controller!!.decideApproval(handle, ApprovalChoice.ALLOW_ONCE) }
            until("school assurance denied") { controller!!.state.value.approvalError == "approval.assurance_required" && controller!!.state.value.approvalStage == ApprovalUiStage.IDLE }
        }
        assertEquals(0, fixture!!.approvalWrites.get()); assertEquals(1L, controller!!.state.value.approvals!!.records.single().attempts)
        main { controller!!.reauthenticateApproval() }
        until("explicit school reauthentication") { controller!!.state.value.phase == HomePhase.REAUTHENTICATE }
        main { controller!!.login() }
        until("fresh school login request") { controller!!.state.value.browser != null }
        assertEquals("login", controller!!.state.value.browser!!.uri.getQueryParameter("prompt"))
    }
    @Test fun anOwnerRoleLossRetiresTheReviewEvenWhenOtherScopeMetadataIsUnchanged() {
        start(); val launch = prepared(review()); fixture!!.approvalRole = "operator"
        main { controller!!.refresh() }
        until("narrower owner authority") { controller!!.state.value.let { !it.refreshing && it.runtimes.single().access?.role == "operator" && it.approvals == null && it.reader?.phase == SessionReadPhase.READY } }
        assertNull(controller!!.state.value.authenticationId); assertNull(controller!!.state.value.reviewingApprovalId)
        assertThrows(DeviceCryptoException::class.java) { launch.operation.cryptoObject }
        assertEquals(0, fixture!!.approvalWrites.get())
    }
    @Test fun aPreparationDeadlineCannotLeaveAnAuthenticatingKeyOperationAlive() {
        start(promptMillis = 100)
        val handle = review(); main { controller!!.decideApproval(handle, ApprovalChoice.ALLOW_ONCE) }
        until("bounded local authentication") { controller!!.state.value.approvalError == "approval.authentication_expired" && controller!!.state.value.approvalStage == ApprovalUiStage.IDLE }
        assertNull(controller!!.state.value.authenticationId); assertEquals(0, fixture!!.approvalWrites.get())
    }
}
