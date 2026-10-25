package cn.edu.ustc.dsh.session

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.util.Base64

class SessionQuestionsTest {
    private val runtime="33333333-3333-4333-8333-333333333333"
    private val epoch="44444444-4444-4444-8444-444444444444"
    private val session="55555555-5555-4555-8555-555555555555"
    private val request="66666666-6666-4666-8666-666666666666"
    private val subscription="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private val sync="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    private val question="99999999-9999-4999-8999-999999999999"
    private val claim="dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    private val route=SessionRoute(runtime,epoch,session,subscription)
    private val now=relayTime("2026-10-24T12:00:00Z")
    private fun golden(name: String)=JsonDocument.parse(File(System.getProperty("contracts.root"),"ws/v1/golden/$name.json").readBytes()).root
    private fun content(name: String)=SessionFragments(route).accept(golden(name))!!
    private fun window()=SessionQuestions(route,request).apply {attach(sync)}
    private fun timedOpen()=content("question-timed-snapshot").let {it.payload.with("items" to JsonArray(it.payload.array("items").map {value->(value as JsonObject).with("state" to "open".json())}))}
    @Test fun projectedPlanIsTypedAndRequiresEveryCurrentQuestionAndKnownSelections() {
        val window=window();window.accept(content("question-snapshot"),now,0)
        val view=window.state(true,0).items.single()
        assertEquals("Continue",view.batch.prompts.single().planApproval)
        window.validate(view.handle,QuestionAnswers(question,listOf(QuestionAnswer("plan",listOf("Continue")))),0)
        for(answer in listOf(QuestionAnswer("plan",listOf("unknown")),QuestionAnswer("plan",listOf("Continue","Cancel")),QuestionAnswer("plan",emptyList()))) {
            assertThrows(QuestionStateException::class.java) {window.validate(view.handle,QuestionAnswers(question,listOf(answer)),0)}
        }
        assertFalse(view.batch.toString().contains("Review this plan"))
    }
    @Test fun revisionsDoNotRestoreOlderQuestionsOrMutateADefinitionInPlace() {
        val window=window();val frame=content("question-snapshot");window.accept(frame,now,0)
        assertFalse(window.accept(frame,now,0))
        val old=SessionContent(frame.type,request,sync,frame.payload.with("revision" to 1L.json(),"items" to JsonArray(emptyList())))
        assertFalse(window.accept(old,now,0));assertEquals(1,window.state(true,0).items.size)
        val item=frame.payload.array("items").single() as JsonObject
        val prompt=item.array("questions").single() as JsonObject
        val changed=frame.payload.with("revision" to 3L.json(),"items" to JsonArray(listOf(item.with("questions" to JsonArray(listOf(prompt.with("detail" to "changed plan".json())))))))
        assertThrows(SessionDataException::class.java) {window.accept(SessionContent(frame.type,request,sync,changed),now,0)}
        window.attach(request);assertTrue(window.state(true,0).items.isEmpty())
    }
    @Test fun claimsDeductNetworkDelayAndLateTimingCannotReviveAReleasedClaim() {
        val window=window();window.accept(SessionContent("question.timed.snapshot",request,sync,timedOpen()),now,0)
        val handle=window.state(true,0).items.single().handle
        assertNull(window.state(true,0).items.single().remainingMillis)
        window.beginClaim(handle,claim,0)
        val timing=golden("question-claimed").with("payload" to jsonObject("question_id" to question.json(),"remaining_ms" to 1000L.json(),"expires_at" to "2026-10-24T12:00:01Z".json()))
        window.claimFrame(timing,now+400,400_000_000)
        assertEquals(600L,window.state(true,400_000_000).items.single().remainingMillis)
        val release="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
        assertEquals(claim,window.beginRelease(handle,release,500_000_000))
        window.claimFrame(timing,now+600,600_000_000)
        assertNull(window.state(true,600_000_000).items.single().claim)
        assertEquals(400L,window.state(true,600_000_000).items.single().remainingMillis)
        assertFalse(window.state(true,1_100_000_000).items.single().answerable)
        assertEquals(QuestionPhase.OPEN,window.state(true,600_000_000).items.single().batch.phase)
    }
    @Test fun blockingExpiryCannotBeExtendedAndTimedContinuationRequiresSourceState() {
        val window=window();val original=content("question-snapshot")
        val item=(original.payload.array("items").single() as JsonObject).with("expires_at" to "2026-10-24T12:00:01Z".json())
        val first=original.payload.with("items" to JsonArray(listOf(item)))
        window.accept(SessionContent(original.type,request,sync,first),now,0)
        val later=first.with("revision" to 3L.json(),"items" to JsonArray(listOf(item.with("expires_at" to "2026-10-24T12:01:00Z".json()))))
        window.accept(SessionContent(original.type,request,sync,later),now,100_000_000)
        assertFalse(window.state(true,1_100_000_000).items.single().answerable)
        val timed=window();timed.accept(content("question-timed-snapshot"),now,0)
        val view=timed.state(true,0).items.single();assertEquals(QuestionPhase.CONTINUED,view.batch.phase)
        timed.validate(view.handle,QuestionAnswers(question,listOf(QuestionAnswer("plan",emptyList()))),0)
    }
    @Test fun fragmentedLargeQuestionDetailsStayIndependentFromTheTranscriptParser() {
        val base=golden("question-snapshot");val item=base.obj("payload").array("items").single() as JsonObject
        val prompt=item.array("questions").single() as JsonObject
        val payload=base.obj("payload").with("items" to JsonArray(listOf(item.with("questions" to JsonArray(listOf(prompt.with("detail" to "中".repeat(30_000).json())))))))
        val bytes=SessionJson.encode(payload);assertTrue(bytes.size>RELAY_FRAME_BYTES)
        val fragments=SessionFragments(route);var assembled: SessionContent?=null
        val count=(bytes.size+40*1024-1)/(40*1024)
        for(index in 0 until count) {
            val chunk=bytes.copyOfRange(index*40*1024,minOf((index+1)*40*1024,bytes.size))
            assembled=fragments.accept(base.with("type" to "session.fragment".json(),"payload" to jsonObject("type" to "question.snapshot".json(),"fragment_id" to claim.json(),"index" to index.toLong().json(),"count" to count.toLong().json(),"data" to Base64.getEncoder().encodeToString(chunk).json())))
        }
        val window=window();window.accept(assembled!!,now,0)
        assertEquals(30_000,window.state(false,0).items.single().batch.prompts.single().detail!!.length)
    }
}
