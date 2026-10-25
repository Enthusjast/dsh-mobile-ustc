package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.network.*
import org.junit.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SessionCreationTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private var fixture: AccountFixture?=null
    private var controller: LoginController?=null
    private fun main(action: ()->Unit)=instrumentation.runOnMainSync(action)
    @Before fun setup() {
        assumeTrue("explicit owned account fixture required",InstrumentationRegistry.getArguments().getString("accountFixture")=="true")
        val guard=instrumentation.targetContext.getSystemService(KeyguardManager::class.java);assertTrue(guard.isDeviceSecure && !guard.isDeviceLocked)
        fixture=AccountFixture(instrumentation.targetContext).also {it.creationMode=true;it.seed()}
        main {controller=LoginController(instrumentation.targetContext,fixture!!.http,fixture!!.environment());controller!!.foreground(true)}
        until("current directory") {controller!!.state.value.let {it.phase==HomePhase.READY && !it.refreshing && it.runtimes.size==1}}
    }
    @After fun cleanup() {main {controller?.close()};fixture?.close()}
    private fun until(label: String,test: ()->Boolean) {
        val deadline=android.os.SystemClock.elapsedRealtime()+45_000
        while(android.os.SystemClock.elapsedRealtime()<deadline) {
            fixture!!.failure.get()?.let {throw AssertionError(it)}
            if(test()) return
            Thread.sleep(25)
        }
        throw AssertionError("Timed out: $label; creation=${controller?.state?.value?.creation?.phase}; error=${controller?.state?.value?.creation?.error}")
    }
    private fun open() {
        main {controller!!.openCreation(fixture!!.runtimeId)}
        until("creation options") {controller!!.state.value.creation?.let {it.phase==SessionCreationPhase.READY && it.outbox.connected}==true}
    }
    private fun create(): PendingCommand {
        val epoch=controller!!.state.value.creation!!.options!!.epoch
        main {controller!!.createSession(fixture!!.workspaceId,"fixture",epoch)}
        until("settled creation") {controller!!.state.value.creation?.outbox?.records?.singleOrNull()?.createdSessionId!=null}
        return controller!!.state.value.creation!!.outbox.records.single()
    }
    @Test fun platformKeyCreationOpensTheCurrentDirectoryResultAndContinuesThatSession() {
        open();val record=create();val owner=controller!!;val test=fixture!!
        assertNull(record.intent.sessionId);assertEquals(test.workspaceId,record.intent.workspaceId);assertEquals(1,test.creationWrites.get())
        main {owner.openCreatedSession(record.intent.requestId)}
        until("created session reader") {owner.state.value.let {it.selectedSessionId==record.createdSessionId && it.reader?.phase==SessionReadPhase.READY}}
        assertTrue(owner.state.value.reader!!.window!!.items.isEmpty())
        main {owner.submitMessage("queue","继续新会话")}
        until("new session admission") {owner.state.value.outbox?.records?.singleOrNull()?.everAgentQueued==true}
        assertEquals(record.createdSessionId,owner.state.value.outbox!!.records.single().intent.sessionId);assertEquals(1,test.commandWrites.get())
    }
    @Test fun lostReceiptAndControllerRecreationRecoverOneOriginalCreation() {
        val test=fixture!!;test.dropNextCommandReply=true;open();val record=create()
        assertEquals(1,test.creationWrites.get())
        main {controller!!.close();controller=null}
        main {controller=LoginController(instrumentation.targetContext,test.http,test.environment());controller!!.foreground(true)}
        until("revalidated account") {controller!!.state.value.let {it.phase==HomePhase.READY && !it.refreshing && it.runtimes.size==1}}
        open()
        until("original result reopened") {controller!!.state.value.creation?.outbox?.records?.singleOrNull()?.createdSessionId==record.createdSessionId}
        assertEquals(record.intent.requestId,controller!!.state.value.creation!!.outbox.records.single().intent.requestId)
        assertEquals(1L,controller!!.state.value.creation!!.outbox.records.single().attempts);assertEquals(1,test.creationWrites.get())
    }
    @Test fun backgroundAndLogoutRetireCreationStateWithoutRecreatingAnIntent() {
        open();val record=create();val owner=controller!!;val test=fixture!!
        main {owner.foreground(false)};assertNull(owner.state.value.creation)
        main {owner.foreground(true)}
        until("fresh creation view") {owner.state.value.creation?.let {it.phase==SessionCreationPhase.READY && it.outbox.records.singleOrNull()?.intent?.requestId==record.intent.requestId}==true}
        assertEquals(1,test.creationWrites.get())
        main {owner.cancel()};until("local logout") {owner.state.value.phase==HomePhase.SIGNED_OUT}
        assertNull(owner.state.value.creation);assertTrue(owner.state.value.runtimes.isEmpty())
    }
}
