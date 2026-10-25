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

@RunWith(AndroidJUnit4::class)
class SessionArchiveDeliveryTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private var fixture: AccountFixture? = null
    private var controller: LoginController? = null
    private fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
    private fun until(label: String, test: () -> Boolean) {
        val deadline = android.os.SystemClock.elapsedRealtime() + 40_000
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            fixture!!.failure.get()?.let { throw AssertionError(it) }
            if (test()) return
            Thread.sleep(25)
        }
        throw AssertionError("Timed out: $label; reader=${controller?.state?.value?.reader?.phase}; error=${controller?.state?.value?.commandError}")
    }
    @Before fun setup() {
        assumeTrue("explicit owned account fixture required", InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        val context = instrumentation.targetContext
        val guard = context.getSystemService(KeyguardManager::class.java)
        assertTrue(guard.isDeviceSecure && !guard.isDeviceLocked)
        fixture = AccountFixture(context).also { it.chatMode = true; it.archiveMode = true; it.seed() }
        main { controller = LoginController(context, fixture!!.http, fixture!!.environment()); controller!!.foreground(true) }
        until("directory") { controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing && it.runtimes.size == 1 } }
        main { controller!!.openRuntime(fixture!!.runtimeId) }
        until("session metadata") { controller!!.state.value.let { !it.loadingSessions && it.sessions.size == 1 } }
        main { controller!!.openSession(fixture!!.sessionId) }
        until("archive-capable reader") { controller!!.state.value.let { it.reader?.phase == SessionReadPhase.READY && it.outbox?.canArchive == true } }
    }
    @After fun cleanup() { main { controller?.close() }; fixture?.close() }
    private fun awaitState(archived: Boolean, records: Int) {
        until("current archive directory and original receipts") { controller!!.state.value.let { state ->
            !state.submitting && state.reader?.phase == SessionReadPhase.READY && state.outbox?.canArchive == true && state.outbox.records.size == records &&
                state.outbox.records.all { it.remote == RemoteCommandState.SETTLED } && state.sessions.singleOrNull()?.state == (if (archived) "archived" else "available")
        } }
    }
    @Test fun sqlCipherArchiveAndRestoreReopenWithFreshScopeAndPermitContinuation() {
        val owner = controller!!; val test = fixture!!
        main { owner.archiveSession(owner.state.value.reader!!.runtimeEpoch!!, true, false) }
        awaitState(true, 1)
        val original = owner.state.value.outbox!!.records.single()
        assertEquals(CommandKind.ARCHIVE, original.intent.kind); assertFalse(original.everAgentQueued); assertEquals(1L, original.attempts)
        main { owner.submitMessage("queue", "must restore first") }
        assertEquals(1, test.commandWrites.get())
        main { owner.archiveSession(owner.state.value.reader!!.runtimeEpoch!!, false, false) }
        awaitState(false, 2)
        assertEquals(2, test.archiveWrites.get())
        main { owner.submitMessage("queue", "continue restored conversation") }
        until("restored message admission") { owner.state.value.outbox?.records?.any { it.intent.kind == CommandKind.MESSAGE && it.everAgentQueued } == true }
        assertEquals(3, test.commandWrites.get())
    }
    @Test fun lostArchiveReplyAndControllerRecreationKeepOneOriginalWithoutReplay() {
        val owner = controller!!; val test = fixture!!; test.dropNextCommandReply = true
        main { owner.archiveSession(owner.state.value.reader!!.runtimeEpoch!!, true, true) }
        awaitState(true, 1)
        val original = owner.state.value.outbox!!.records.single()
        main { owner.close(); controller = LoginController(instrumentation.targetContext, test.http, test.environment()); controller!!.foreground(true) }
        until("recreated account") { controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing && it.runtimes.size == 1 } }
        main { controller!!.openRuntime(test.runtimeId) }
        until("recreated directory") { controller!!.state.value.sessions.size == 1 && !controller!!.state.value.loadingSessions }
        main { controller!!.openSession(test.sessionId) }
        awaitState(true, 1)
        val restored = controller!!.state.value.outbox!!.records.single()
        assertEquals(original.intent.requestId, restored.intent.requestId)
        assertEquals(original.intent.digest, restored.intent.digest); assertEquals(1L, restored.attempts)
        assertEquals(1, test.archiveWrites.get())
        main { controller!!.archiveSession(test.runtimeId, false, false) }
        assertEquals(1, test.archiveWrites.get())
    }
}
