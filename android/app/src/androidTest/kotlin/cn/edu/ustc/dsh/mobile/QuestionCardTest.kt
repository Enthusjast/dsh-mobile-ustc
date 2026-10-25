package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class QuestionCardTest {
    @get:Rule val rule=createAndroidComposeRule<ComponentActivity>()
    private val id="11111111-1111-4111-8111-111111111111"
    private val question="99999999-9999-4999-8999-999999999999"
    private fun view(multi: Boolean=false,extraText: Boolean=false,timed: String?=null,plan: Boolean=false): PresentedQuestion {
        var prompt=jsonObject("id" to "choice".json(),"question" to "选择处理方式".json(),"options" to JsonArray(listOf(jsonObject("label" to "A".json()),jsonObject("label" to "B".json()))),"multi_select" to JsonBoolean(multi))
        if(plan) prompt=prompt.with("detail" to "完整计划内容".json(),"intent" to jsonObject("kind" to "plan-review".json(),"approve" to "A".json()))
        val prompts=listOf(prompt)+if(extraText) listOf(jsonObject("id" to "text".json(),"question" to "请补充说明".json())) else emptyList()
        var batch=jsonObject("question_id" to question.json(),"expires_at" to (if(timed==null) java.time.Instant.now().plusSeconds(60).toString().json() else JsonNull),"questions" to JsonArray(prompts))
        if(timed!=null) batch=batch.with("state" to timed.json())
        val state=SessionQuestions(SessionRoute(id,id,id,id),id);state.attach(id)
        state.accept(SessionContent(if(timed==null) "question.snapshot" else "question.timed.snapshot",id,id,jsonObject("revision" to 1L.json(),"items" to JsonArray(listOf(batch)))))
        return state.state(true).items.single()
    }
    @Test fun noChoiceIsInventedAndTheSubmittedAnswerUsesTheExactOriginalLabel() {
        var result: QuestionAnswers?=null
        val current=view()
        rule.setContent {DshTheme {Column(Modifier.verticalScroll(rememberScrollState())) {QuestionCard(current,true,false,emptyList(),{_,value->result=value},{},{},{},{})}}}
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("发送完整答复").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("A",substring=false).performScrollTo().performClick()
        rule.onNodeWithText("发送完整答复").performScrollTo().assertIsEnabled().performClick()
        rule.runOnIdle {assertEquals(question,result!!.questionId);assertEquals(listOf("A"),result!!.values.single().selected)}
    }
    @Test fun multiSelectionAndFreeTextRequireACompleteStructuredBatch() {
        var result: QuestionAnswers?=null
        val current=view(multi=true,extraText=true)
        rule.setContent {DshTheme {Column(Modifier.verticalScroll(rememberScrollState())) {QuestionCard(current,true,false,emptyList(),{_,value->result=value},{},{},{},{})}}}
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("A",substring=false).performScrollTo().performClick();rule.onNodeWithText("B",substring=false).performScrollTo().performClick()
        rule.onNodeWithText("发送完整答复").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("答复：text").performScrollTo().performTextInput("中文答复🙂")
        rule.onNodeWithText("发送完整答复").performScrollTo().assertIsEnabled().performClick()
        rule.runOnIdle {assertEquals(setOf("A","B"),result!!.values.single {it.id=="choice"}.selected.toSet());assertEquals("中文答复🙂",result!!.values.single {it.id=="text"}.custom)}
    }
    @Test fun readOnlyPlanReviewDoesNotClaimTimingOrCreateAToolApproval() {
        var claims=0;var answers=0
        val current=view(timed="open",plan=true)
        rule.setContent {DshTheme {Column(Modifier.verticalScroll(rememberScrollState())) {QuestionCard(current,false,false,emptyList(),{_,_->answers++},{claims++},{},{},{})}}}
        rule.onNodeWithText("这是对助手的计划答复，不是工具执行批准。").assertIsDisplayed()
        rule.onNodeWithText("电脑尚未提供等待倒计时").assertIsDisplayed()
        rule.onNodeWithText("查看问题").performClick()
        rule.onNodeWithText("发送完整答复").performScrollTo().assertIsNotEnabled()
        rule.runOnIdle {assertEquals(0,claims);assertEquals(0,answers)}
    }
    @Test fun continuedQuestionsExplainLateDeliveryAndNeverInventACountdown() {
        var claims=0;var result: QuestionAnswers?=null
        val current=view(timed="continued")
        rule.setContent {DshTheme {Column(Modifier.verticalScroll(rememberScrollState())) {QuestionCard(current,true,false,emptyList(),{_,value->result=value},{claims++},{},{},{})}}}
        rule.onNodeWithText("任务已继续；新的答复会作为后续消息发送").assertIsDisplayed()
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("作为后续答复发送").performScrollTo().assertIsEnabled().performClick()
        rule.runOnIdle {assertEquals(0,claims);assertTrue(result!!.values.single().selected.isEmpty())}
    }
    @Test fun unsubmittedQuestionTextAndSelectionsDoNotEnterSavedInstanceState() {
        val current=view();val restore=StateRestorationTester(rule)
        restore.setContent {DshTheme {Column(Modifier.verticalScroll(rememberScrollState())) {QuestionCard(current,true,false,emptyList(),{_,_->},{},{},{},{})}}}
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("补充或自定义答复：choice").performScrollTo().performTextInput("UNSUBMITTED_QUESTION_SECRET")
        restore.emulateSavedInstanceStateRestore()
        rule.onNodeWithText("UNSUBMITTED_QUESTION_SECRET").assertDoesNotExist()
        rule.onNodeWithText("查看并答复").performScrollTo().performClick()
        rule.onNodeWithText("发送完整答复").performScrollTo().assertIsNotEnabled()
    }
}
