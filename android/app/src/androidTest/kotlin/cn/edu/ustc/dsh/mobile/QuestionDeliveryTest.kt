package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import org.junit.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class QuestionDeliveryTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private var fixture: AccountFixture?=null
    private var controller: LoginController?=null
    private fun main(action: ()->Unit)=instrumentation.runOnMainSync(action)
    @Before fun setup() {
        assumeTrue("explicit owned account fixture required",InstrumentationRegistry.getArguments().getString("accountFixture")=="true")
        val guard=instrumentation.targetContext.getSystemService(KeyguardManager::class.java);assertTrue(guard.isDeviceSecure && !guard.isDeviceLocked)
        fixture=AccountFixture(instrumentation.targetContext).also {it.questionMode=true;it.seed()}
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
        throw AssertionError("Timed out: $label; phase=${controller?.state?.value?.reader?.phase}; error=${controller?.state?.value?.commandError}")
    }
    private fun open() {
        main {controller!!.openRuntime(fixture!!.runtimeId)}
        until("session directory") {controller!!.state.value.let {!it.loadingSessions && it.sessions.isNotEmpty()}}
        main {controller!!.openSession(fixture!!.sessionId)}
        until("current question") {controller!!.state.value.reader?.let {it.phase==SessionReadPhase.READY && it.questions.items.isNotEmpty()}==true}
    }
    private fun current()=controller!!.state.value.reader!!.questions.items.single()
    private fun answer() {
        val question=current()
        main {controller!!.answerQuestion(question.handle,QuestionAnswers(question.batch.id,listOf(QuestionAnswer("plan",listOf("继续"),"平台答复🙂"))))}
        until("ordinary answer settled") {controller!!.state.value.outbox?.records?.singleOrNull()?.remote==RemoteCommandState.SETTLED}
    }
    @Test fun platformKeyPlanAnswerPreservesItsContextAndNeverClaimsAgentAdmission() {
        open();val question=current();answer()
        until("question no longer pending") {controller!!.state.value.reader!!.questions.items.isEmpty()}
        val row=controller!!.state.value.outbox!!.records.single()
        assertEquals(question.batch.definition,row.intent.questionDefinition);assertEquals(CommandKind.QUESTION,row.intent.kind)
        assertFalse(row.everAgentQueued);assertFalse(row.intent.frame().fields.containsKey("local_context_sha256"));assertEquals(1,fixture!!.questionWrites.get())
        assertTrue(controller!!.state.value.reader!!.window!!.items.none {item->item.blocks.any {it.text.contains("平台答复")}})
    }
    @Test fun aLostAnswerReceiptAndControllerRecreationRecoverTheOriginalRequestWithoutReanswering() {
        val test=fixture!!;test.dropNextCommandReply=true;open();answer()
        val row=controller!!.state.value.outbox!!.records.single()
        main {controller!!.close();controller=null}
        main {controller=LoginController(instrumentation.targetContext,test.http,test.environment());controller!!.foreground(true)}
        until("account restored") {controller!!.state.value.let {it.phase==HomePhase.READY && !it.refreshing && it.runtimes.size==1}}
        main {controller!!.openRuntime(test.runtimeId)};until("metadata") {!controller!!.state.value.loadingSessions}
        main {controller!!.openSession(test.sessionId)}
        until("original answer reopened") {controller!!.state.value.outbox?.records?.singleOrNull()?.intent?.requestId==row.intent.requestId}
        assertEquals(row.intent.questionDefinition,controller!!.state.value.outbox!!.records.single().intent.questionDefinition)
        assertEquals(1,test.questionWrites.get());assertEquals(1L,controller!!.state.value.outbox!!.records.single().attempts)
    }
    @Test fun timedReleaseContinuesTheQuestionAndItsLateAnswerHasQueueAdmission() {
        val test=fixture!!;test.blockingPending=false;test.timedQuestionState="open";open()
        val question=current();assertNull(question.remainingMillis)
        main {controller!!.claimQuestion(question.handle)}
        until("native claim acknowledged") {current().claim?.phase==ClaimPhase.ACTIVE}
        assertEquals(1,test.claimWrites.get())
        main {controller!!.releaseQuestion(question.handle)}
        until("native continued state") {current().batch.phase==QuestionPhase.CONTINUED}
        val continued=current()
        main {controller!!.answerQuestion(continued.handle,QuestionAnswers(continued.batch.id,listOf(QuestionAnswer("timed",listOf("回复"),"迟到答复🙂"))))}
        until("late answer admitted") {controller!!.state.value.outbox?.records?.singleOrNull()?.everAgentQueued==true}
        assertEquals(CommandKind.TIMED_QUESTION,controller!!.state.value.outbox!!.records.single().intent.kind)
        assertEquals(1,test.releaseWrites.get());assertEquals(1,test.questionWrites.get())
    }
}
