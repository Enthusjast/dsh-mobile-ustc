package cn.edu.ustc.dsh.command

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class QuestionIntentTest {
    private val request="66666666-6666-4666-8666-666666666666"
    private val runtime="33333333-3333-4333-8333-333333333333"
    private val session="55555555-5555-4555-8555-555555555555"
    private val epoch="44444444-4444-4444-8444-444444444444"
    private val question="99999999-9999-4999-8999-999999999999"
    private fun answers()=QuestionAnswers(question,listOf(QuestionAnswer("plan",listOf("Continue"),"中文 < & \\ line\n")))
    private fun intent(timed: Boolean=false)=CommandIntent.answerQuestion(request,runtime,session,epoch,timed,answers(),"a".repeat(64))
    @Test fun blockingAndTimedAnswersMatchTheSharedGoNodeDigests() {
        val folder=File(System.getProperty("contracts.root"),"ws/v1/golden")
        for(name in listOf("question-answer","question-timed-answer")) {
            val root=JsonDocument.parse(File(folder,"$name.json").readBytes()).root
            val forwarded=JsonDocument.parse(File(folder,"$name.forwarded.json").readBytes()).root
            val parsed=CommandIntent.parse(root)
            assertEquals(forwarded.string("payload_sha256"),parsed.digest)
            assertNotEquals(parsed.digest,CommandIntent.answerQuestion(root.string("request_id"),root.string("runtime_id"),root.string("session_id"),request,name.contains("timed"),QuestionAnswers.parse(root.obj("payload")),"a".repeat(64)).digest)
        }
        assertNotEquals(intent().digest,intent(true).digest)
    }
    @Test fun encryptedStorageContextNeverChangesOrEntersTheWireBody() {
        val original=intent();val restored=CommandIntent.stored(original.storageBytes())
        assertEquals(original.digest,restored.digest);assertEquals(original.questionDefinition,restored.questionDefinition)
        assertEquals(JsonDocument.of(original.frame()).canonicalText(),JsonDocument.of(restored.frame()).canonicalText())
        assertFalse(original.frame().fields.containsKey("local_context_sha256"))
        assertThrows(ProtocolException::class.java) {CommandIntent.parse(JsonDocument.parse(original.storageBytes()).root)}
        assertFalse(answers().toString().contains("中文"));assertFalse(answers().values.single().toString().contains("Continue"))
    }
    @Test fun answerGrammarRejectsDuplicatesForeignFieldsAndUnsafeText() {
        assertThrows(ProtocolException::class.java) {QuestionAnswers(question,listOf(QuestionAnswer("x",emptyList()),QuestionAnswer("x",emptyList())))}
        assertThrows(ProtocolException::class.java) {QuestionAnswer("x",listOf("one","one"))}
        for(text in listOf("bad\u0000","\ud800","a".repeat(16_385))) assertThrows(ProtocolException::class.java) {QuestionAnswer("x",emptyList(),text)}
        assertThrows(ProtocolException::class.java) {QuestionAnswers.parse(answers().json().with("decision" to "allow_once".json()))}
        assertThrows(ProtocolException::class.java) {QuestionAnswers.parse(jsonObject("question_id" to question.json(),"answers" to JsonArray(listOf(jsonObject("id" to "x".json(),"selected" to JsonArray(emptyList()),"custom" to JsonNull)))))}
    }
    @Test fun foregroundSettlementAndLateMessageAdmissionRemainDifferentFacts() {
        fun receipt(intent: CommandIntent,state: RemoteCommandState)=CommandReceipt(request,session,intent.digest,state,"2026-10-25T00:00:00Z")
        val blocking=intent();val started=CommandEvolution.begin(CommandEvolution.created(blocking,0),1)
        assertThrows(CommandDataException::class.java) {CommandEvolution.receipt(started,receipt(blocking,RemoteCommandState.AGENT_QUEUED))}
        assertFalse(CommandEvolution.receipt(started,receipt(blocking,RemoteCommandState.SETTLED)).everAgentQueued)
        val timed=intent(true);val late=CommandEvolution.begin(CommandEvolution.created(timed,0),1)
        assertFalse(CommandEvolution.receipt(late,receipt(timed,RemoteCommandState.SETTLED)).everAgentQueued)
        assertTrue(CommandEvolution.receipt(late,receipt(timed,RemoteCommandState.AGENT_QUEUED)).everAgentQueued)
    }
}
