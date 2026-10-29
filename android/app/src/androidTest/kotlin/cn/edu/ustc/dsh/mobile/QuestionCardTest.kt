package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class QuestionCardTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private val id = "11111111-1111-4111-8111-111111111111"
    private val question = "99999999-9999-4999-8999-999999999999"
    private val claim = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    private val release = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"

    private fun questions(multi: Boolean = false, extraText: Boolean = false, timed: String? = null,
        plan: Boolean = false, detail: String = "完整计划内容"): SessionQuestions {
        var prompt = jsonObject("id" to "choice".json(), "question" to "选择处理方式".json(),
            "options" to JsonArray(listOf(jsonObject("label" to "A".json(), "description" to "按方案 A 处理".json()),
                jsonObject("label" to "B".json()))), "multi_select" to JsonBoolean(multi))
        if (plan) prompt = prompt.with("detail" to detail.json(), "intent" to jsonObject("kind" to "plan-review".json(), "approve" to "A".json()))
        val prompts = listOf(prompt) + if (extraText) listOf(jsonObject("id" to "text".json(), "question" to "请补充说明".json())) else emptyList()
        var batch = jsonObject("question_id" to question.json(),
            "expires_at" to (if (timed == null) java.time.Instant.now().plusSeconds(3600).toString().json() else JsonNull),
            "questions" to JsonArray(prompts))
        if (timed != null) batch = batch.with("state" to timed.json())
        return SessionQuestions(SessionRoute(id, id, id, id), id).apply {
            attach(id)
            accept(SessionContent(if (timed == null) "question.snapshot" else "question.timed.snapshot", id, id,
                jsonObject("revision" to 1L.json(), "items" to JsonArray(listOf(batch)))))
        }
    }

    private fun view(multi: Boolean = false, extraText: Boolean = false, timed: String? = null,
        plan: Boolean = false, detail: String = "完整计划内容") = questions(multi, extraText, timed, plan, detail).state(true).items.single()

    private fun show(current: PresentedQuestion, canAnswer: Boolean = true, records: List<PendingCommand> = emptyList(),
        onAnswer: (QuestionHandle, QuestionAnswers) -> Unit = { _, _ -> }, onClaim: (QuestionHandle) -> Unit = {},
        onRelease: (QuestionHandle) -> Unit = {}, onQuery: () -> Unit = {}) {
        rule.setContent {
            DshTheme {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    QuestionCard(current, canAnswer, false, records, onAnswer, onClaim, onRelease, {}, onQuery)
                }
            }
        }
    }

    @Test fun noChoiceIsInventedAndTheSubmittedAnswerUsesTheExactOriginalLabel() {
        var result: QuestionAnswers? = null
        val current = view()
        show(current, onAnswer = { handle, value -> assertEquals(current.handle, handle); result = value })
        rule.onNodeWithText("需要你答复").assertIsDisplayed()
        rule.onNodeWithText("发送完整答复").assertDoesNotExist()
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("发送完整答复").performScrollTo().assertIsNotEnabled()
        captureUiFixture(rule, "question-form", dialog = true)
        rule.onNodeWithText("A", substring = false).performScrollTo().assertIsNotSelected().performClick()
        rule.onNodeWithText("按方案 A 处理").assertExists()
        rule.onNodeWithText("发送完整答复").performScrollTo().assertIsEnabled().performClick()
        rule.runOnIdle {
            assertEquals(question, result!!.questionId)
            assertEquals(listOf("A"), result!!.values.single().selected)
            current.batch.validate(result!!)
        }
    }

    @Test fun multiSelectionAndFreeTextRequireACompleteStructuredBatch() {
        var result: QuestionAnswers? = null
        val current = view(multi = true, extraText = true)
        show(current, onAnswer = { _, value -> result = value })
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("A", substring = false).performScrollTo().assertIsOff().performClick()
        rule.onNodeWithText("B", substring = false).performScrollTo().performClick()
        rule.onNodeWithText("发送完整答复").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("答复：text").performScrollTo().performTextInput("中文答复🙂")
        rule.onNodeWithText("发送完整答复").performScrollTo().assertIsEnabled().performClick()
        rule.runOnIdle {
            assertEquals(setOf("A", "B"), result!!.values.single { it.id == "choice" }.selected.toSet())
            assertEquals("中文答复🙂", result!!.values.single { it.id == "text" }.custom)
            current.batch.validate(result!!)
        }
    }

    @Test fun explicitOpenClaimsAndClosingReleasesTheCurrentTimedHandleExactlyOnce() {
        val questions = questions(timed = "open")
        val current = questions.state(true).items.single()
        var claims = 0
        var releases = 0
        show(current, onClaim = { handle ->
            assertEquals(current.handle, handle)
            claims++
            assertEquals(claim, questions.beginClaim(handle, claim))
        }, onRelease = { handle ->
            assertEquals(current.handle, handle)
            releases++
            assertEquals(claim, questions.beginRelease(handle, release))
        })
        rule.runOnIdle { assertEquals(0, claims); assertNull(questions.state(true).items.single().claim) }
        rule.onNodeWithText("查看并答复").performClick()
        rule.runOnIdle { assertEquals(1, claims); assertEquals(ClaimPhase.PENDING, questions.state(true).items.single().claim!!.phase) }
        rule.onNodeWithText("暂不回答").performScrollTo().performClick()
        rule.runOnIdle { assertEquals(1, releases); assertNull(questions.state(true).items.single().claim) }
        rule.onNodeWithText("查看并答复").assertIsDisplayed()
        rule.onNodeWithText("发送完整答复").assertDoesNotExist()
    }

    @Test fun removingAnOpenFormRetiresItsClaimWithoutPersistingItsDraft() {
        val questions = questions(timed = "open")
        val current = questions.state(true).items.single()
        val visible = mutableStateOf(true)
        var releases = 0
        rule.setContent {
            DshTheme {
                if (visible.value) QuestionCard(current, true, false, emptyList(), { _, _ -> },
                    { questions.beginClaim(it, claim) }, { releases++; questions.beginRelease(it, release) }, {}, {})
            }
        }
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("补充或自定义答复：choice").performScrollTo().performTextInput("VOLATILE_ONLY")
        rule.runOnIdle { visible.value = false }
        rule.runOnIdle { assertEquals(1, releases); assertNull(questions.state(true).items.single().claim) }
        rule.runOnIdle { visible.value = true }
        rule.onNodeWithText("VOLATILE_ONLY").assertDoesNotExist()
        rule.onNodeWithText("查看并答复").assertIsDisplayed()
    }

    @Test fun readOnlyPlanReviewDoesNotClaimTimingOrCreateAToolApproval() {
        var claims = 0
        var answers = 0
        show(view(timed = "open", plan = true), canAnswer = false,
            onAnswer = { _, _ -> answers++ }, onClaim = { claims++ })
        rule.onNodeWithText("电脑尚未提供等待倒计时").assertIsDisplayed()
        rule.onNodeWithText("查看问题").performClick()
        rule.onNodeWithText("这是对助手的计划答复，不是工具执行批准。").assertIsDisplayed()
        rule.onNodeWithText("发送计划答复").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("已核对以上完整计划").performScrollTo().assertIsNotEnabled()
        rule.runOnIdle { assertEquals(0, claims); assertEquals(0, answers) }
    }

    @Test fun fullPlanMustBeRevealedAndReviewedBeforeContinueCanBeSelected() {
        var result: QuestionAnswers? = null
        val current = view(plan = true, detail = "计划内容\n".repeat(1700) + "PLAN_END")
        show(current, onAnswer = { _, value -> result = value })
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("PLAN_END", substring = true).assertDoesNotExist()
        rule.onNodeWithText("已核对以上完整计划").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("A", substring = false).performScrollTo().assertIsNotEnabled().assertIsNotSelected()
        rule.onNodeWithText("继续显示问题详情").performScrollTo().performClick()
        rule.onNodeWithText("PLAN_END", substring = true).assertExists()
        rule.onNodeWithText("A", substring = false).performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("已核对以上完整计划").performScrollTo().assertIsEnabled().assertIsOff().performClick()
        rule.onNodeWithText("A", substring = false).performScrollTo().assertIsEnabled().performClick()
        rule.onNodeWithText("发送计划答复").performScrollTo().assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(listOf("A"), result!!.values.single().selected); current.batch.validate(result!!) }
    }

    @Test fun customPlanContinueCannotBypassReviewButNonApprovalAnswerRemainsAvailable() {
        var result: QuestionAnswers? = null
        show(view(plan = true), onAnswer = { _, value -> result = value })
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("补充或自定义答复：choice").performScrollTo().performTextInput("A")
        rule.onNodeWithText("发送计划答复").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("补充或自定义答复：choice").performScrollTo().performTextClearance()
        rule.onNodeWithText("B", substring = false).performScrollTo().performClick()
        rule.onNodeWithText("发送计划答复").performScrollTo().assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(listOf("B"), result!!.values.single().selected) }
    }

    @Test fun closingDiscardsSelectionsFreeTextAndPlanReview() {
        show(view(plan = true))
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("已核对以上完整计划").performScrollTo().performClick()
        rule.onNodeWithText("A", substring = false).performScrollTo().performClick()
        rule.onNodeWithText("补充或自定义答复：choice").performScrollTo().performTextInput("UNSENT")
        rule.onNodeWithText("关闭答复表单").performClick()
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("UNSENT").assertDoesNotExist()
        rule.onNodeWithText("已核对以上完整计划").performScrollTo().assertIsOff()
        rule.onNodeWithText("A", substring = false).performScrollTo().assertIsNotEnabled().assertIsNotSelected()
        rule.onNodeWithText("发送计划答复").performScrollTo().assertIsNotEnabled()
    }

    @Test fun retiringTheNotificationHandleClosesTheOldFormWithoutClaimingTheReplacement() {
        val old = view(timed = "open")
        val replacement = PresentedQuestion(old.batch,
            old.handle.copy(syncId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), null, null, false)
        val current = mutableStateOf(old)
        val claims = mutableListOf<QuestionHandle>()
        val releases = mutableListOf<QuestionHandle>()
        rule.setContent {
            DshTheme {
                QuestionCard(current.value, true, false, emptyList(), { _, _ -> },
                    { claims += it }, { releases += it }, {}, {})
            }
        }
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("补充或自定义答复：choice").performScrollTo().performTextInput("OLD_HANDLE_DRAFT")
        rule.runOnIdle { current.value = replacement }
        rule.onNodeWithText("OLD_HANDLE_DRAFT").assertDoesNotExist()
        rule.onNodeWithText("发送完整答复").assertDoesNotExist()
        rule.runOnIdle { assertEquals(listOf(old.handle), claims); assertEquals(listOf(old.handle), releases) }
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("OLD_HANDLE_DRAFT").assertDoesNotExist()
        rule.runOnIdle { assertEquals(listOf(old.handle, replacement.handle), claims) }
    }

    @Test fun queuedFollowUpCannotGenerateAnotherAnswerOrClaim() {
        var claims = 0
        var answers = 0
        show(view(timed = "reply_queued"), onAnswer = { _, _ -> answers++ }, onClaim = { claims++ })
        rule.onNodeWithText("后续答复已入队，等待电脑更新").assertIsDisplayed()
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("发送完整答复").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("A", substring = false).performScrollTo().assertIsNotEnabled()
        rule.runOnIdle { assertEquals(0, claims); assertEquals(0, answers) }
    }

    @Test fun continuedQuestionsExplainLateDeliveryAndNeverInventACountdown() {
        var claims = 0
        var result: QuestionAnswers? = null
        val current = view(timed = "continued")
        show(current, onAnswer = { _, value -> result = value }, onClaim = { claims++ })
        rule.onNodeWithText("任务已继续；新的答复会作为后续消息发送").assertIsDisplayed()
        rule.onNodeWithText("电脑尚未提供等待倒计时").assertDoesNotExist()
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("作为后续答复发送").performScrollTo().assertIsEnabled().performClick()
        rule.runOnIdle {
            assertEquals(0, claims)
            assertTrue(result!!.values.single().selected.isEmpty())
            current.batch.validate(result!!)
        }
    }

    @Test fun locallyExpiredTimeDoesNotPretendTheComputerContinued() {
        val open = view(timed = "open")
        val expired = PresentedQuestion(open.batch, open.handle, 0, null, false)
        var claims = 0
        show(expired, onClaim = { claims++ })
        rule.onNodeWithText("当前问题暂不可应答，请核对电脑上的最新状态").assertIsDisplayed()
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("发送完整答复").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("作为后续答复发送").assertDoesNotExist()
        rule.runOnIdle { assertEquals(0, claims); assertEquals(QuestionPhase.OPEN, expired.batch.phase) }
    }

    @Test fun originalAnswerMustBeReconciledInsteadOfCreatingAnotherAnswerOrClaim() {
        val current = view(timed = "open")
        val original = QuestionAnswers(question, listOf(QuestionAnswer("choice", listOf("A"))))
        val intent = CommandIntent.answerQuestion(claim, id, id, id, true, original, current.batch.definition)
        val record = CommandEvolution.created(intent, 1)
        var claims = 0
        var answers = 0
        var queries = 0
        show(current, records = listOf(record), onAnswer = { _, _ -> answers++ }, onClaim = { claims++ }, onQuery = { queries++ })
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("原答复结果待确认，请先核对原请求").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("发送完整答复").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("核对原答复").performScrollTo().performClick()
        rule.runOnIdle { assertEquals(1, queries); assertEquals(0, claims); assertEquals(0, answers) }
    }

    @Test fun unsubmittedQuestionTextSelectionsAndReviewDoNotEnterSavedInstanceState() {
        val current = view(plan = true)
        val restore = StateRestorationTester(rule)
        restore.setContent {
            DshTheme {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    QuestionCard(current, true, false, emptyList(), { _, _ -> }, {}, {}, {}, {})
                }
            }
        }
        rule.onNodeWithText("查看并答复").performClick()
        rule.onNodeWithText("已核对以上完整计划").performScrollTo().performClick()
        rule.onNodeWithText("A", substring = false).performScrollTo().performClick()
        rule.onNodeWithText("补充或自定义答复：choice").performScrollTo().performTextInput("UNSUBMITTED_QUESTION_SECRET")
        restore.emulateSavedInstanceStateRestore()
        rule.onNodeWithText("UNSUBMITTED_QUESTION_SECRET").assertDoesNotExist()
        rule.onNodeWithText("查看并答复").performScrollTo().performClick()
        rule.onNodeWithText("已核对以上完整计划").performScrollTo().assertIsOff()
        rule.onNodeWithText("A", substring = false).performScrollTo().assertIsNotSelected().assertIsNotEnabled()
        rule.onNodeWithText("发送计划答复").performScrollTo().assertIsNotEnabled()
    }
}
