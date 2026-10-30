package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.network.SessionReadPhase
import org.junit.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class ChatDeliveryTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private var fixture: AccountFixture? = null
    private var controller: LoginController? = null
    private fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
    @Before fun setup() {
        assumeTrue("explicit owned account fixture required", InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        val context = instrumentation.targetContext
        val guard = context.getSystemService(KeyguardManager::class.java)
        assertTrue(guard.isDeviceSecure && !guard.isDeviceLocked)
        fixture = AccountFixture(context).also { it.chatMode = true; it.seed() }
        main { controller = LoginController(context, fixture!!.http, fixture!!.environment()); controller!!.foreground(true) }
        until("directory") { controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing && it.runtimes.size == 1 } }
    }
    @After fun cleanup() { main { controller?.close() }; fixture?.close() }
    private fun until(label: String, test: () -> Boolean) {
        val deadline = android.os.SystemClock.elapsedRealtime() + 40_000
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            fixture!!.failure.get()?.let { throw AssertionError(it) }
            if (test()) return
            Thread.sleep(25)
        }
        throw AssertionError("Timed out: $label; reader=${controller?.state?.value?.reader?.phase}; data=${controller?.state?.value?.commandError}; outbox=${controller?.state?.value?.outbox?.error}")
    }
    private fun open(phase: SessionReadPhase = SessionReadPhase.READY) {
        val owner = controller!!; val test = fixture!!
        main { owner.openRuntime(test.runtimeId) }
        until("session metadata") { owner.state.value.let { !it.loadingSessions && it.sessions.size == 1 } }
        main { owner.openSession(test.sessionId) }
        until("session $phase with encrypted journal") { owner.state.value.let { it.reader?.phase == phase && it.outbox != null } }
    }
    @Test fun platformKeyTlsChatCommitsTheOriginalIntentBeforeReportingAgentAdmission() {
        val owner = controller!!; val test = fixture!!; open()
        main { owner.submitMessage("steer", "发送中文🙂") }
        until("native encrypted outbox admission") { owner.state.value.outbox?.records?.singleOrNull()?.everAgentQueued == true }
        val record = owner.state.value.outbox!!.records.single()
        assertEquals(1L, record.attempts); assertEquals("steer", record.intent.payload.string("mode")); assertEquals(1, test.commandWrites.get())
        assertEquals(record.intent.digest, test.commandStatuses[record.intent.requestId]!!.string("payload_sha256"))
        assertFalse(record.toString().contains("发送中文"))
        main { owner.back() }
        assertNull(owner.state.value.outbox)
    }
    @Test fun offlineIntentReopensFromSqlCipherAndOnlyAnExplicitActionSendsIt() {
        val owner = controller!!; val test = fixture!!; test.runtimeOffline = true; open(SessionReadPhase.OFFLINE)
        main { owner.submitMessage("queue", "离线持久草稿", false) }
        until("saved offline intent") { owner.state.value.outbox?.records?.size == 1 }
        val request = owner.state.value.outbox!!.records.single().intent.requestId
        main { owner.foreground(false); owner.foreground(true) }
        until("restored offline intent") { owner.state.value.let { it.reader?.phase == SessionReadPhase.OFFLINE && it.outbox?.records?.singleOrNull()?.intent?.requestId == request } }
        assertEquals(0, test.commandWrites.get())
        test.runtimeOffline = false; main { owner.retryRead() }
        until("connection restored") { owner.state.value.reader?.phase == SessionReadPhase.READY }
        assertEquals(0, test.commandWrites.get())
        main { owner.sendPending(request) }
        until("explicit original request admitted") { owner.state.value.outbox?.records?.singleOrNull()?.everAgentQueued == true }
        assertEquals(request, owner.state.value.outbox!!.records.single().intent.requestId); assertEquals(1, test.commandWrites.get())
    }
    @Test fun lostSocketReceiptRecoversByStatusAndLogoutErasesPendingBodies() {
        val owner = controller!!; val test = fixture!!; test.dropNextCommandReply = true; open()
        main { owner.submitMessage("queue", "回执丢失正文") }
        until("fresh connection reconciles admission") { owner.state.value.outbox?.records?.singleOrNull()?.everAgentQueued == true }
        assertEquals(1, test.commandWrites.get())
        val scopeHash = CommandOwner.scopeHash(test.accountId, test.organizationId)
        main { owner.cancel() }
        until("local exit") { owner.state.value.phase == HomePhase.SIGNED_OUT }
        assertFalse(File(instrumentation.targetContext.noBackupFilesDir, "mobile-data/$scopeHash").exists())
    }

    @Test fun aRepeatedInterruptionIsFencedBeforeTheOriginalRequestIsSaved() {
        val owner = controller!!; val test = fixture!!; open()
        val epoch = owner.state.value.reader!!.runtimeEpoch!!
        main { owner.cancelSession(epoch); owner.cancelSession(epoch) }
        until("one settled interruption request") {
            owner.state.value.outbox?.records?.filter { it.intent.kind == CommandKind.CANCEL }?.singleOrNull()?.remote == RemoteCommandState.SETTLED
        }
        assertEquals(1, test.commandWrites.get())
        until("busy fence released") { !owner.state.value.submitting }
        assertEquals(1, owner.state.value.outbox!!.records.count { it.intent.kind == CommandKind.CANCEL })
        assertEquals(epoch, owner.state.value.outbox!!.records.single { it.intent.kind == CommandKind.CANCEL }.intent.epoch)
    }
}
