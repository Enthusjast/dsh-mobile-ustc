package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SessionsScreenTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private val id = "11111111-1111-4111-8111-111111111111"
    private val request = "22222222-2222-4222-8222-222222222222"
    private fun initial() = HomeState(HomePhase.READY, selectedRuntimeId = id, selectedSessionId = id)
    private fun transcript() = SessionWindow(request).apply {
        accept(SessionContent("session.snapshot", request, id, jsonObject("cursor" to 2L.json(), "has_more" to JsonBoolean(true), "assistant" to JsonNull,
            "records" to JsonArray(listOf(jsonObject("native_seq" to 2L.json(), "time" to 1000L.json(), "type" to "assistant/message".json(), "surface_op" to "append".json(),
                "data" to jsonObject("message" to jsonObject("content" to JsonArray(listOf(jsonObject("type" to "reasoning".json(), "text" to "合成思考内容".json()), jsonObject("type" to "text".json(), "text" to "合成回复".json())))))))))))
        accept(SessionContent("session.checkpoint", request, id, jsonObject("state" to "persisted".json(), "through_seq" to 2L.json())))
    }.snapshot()

    @Test fun historyActionAndReasoningDisclosureKeepTheTranscriptReadable() {
        var pages = 0
        rule.setContent { DshTheme { SessionsScreen(initial().copy(reader = SessionReadState(SessionReadPhase.READY, transcript())), {}, {}, { pages++ }, {}) } }
        rule.onNodeWithText("读取更早消息").performScrollTo().performClick()
        rule.runOnIdle { assertEquals(1, pages) }
        rule.onNodeWithText("合成思考内容").assertDoesNotExist()
        rule.onNodeWithText("查看思考过程").performScrollTo().performClick()
        rule.onNodeWithText("合成思考内容").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("合成回复").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("尚未确认保存").assertDoesNotExist()
    }
    @Test fun offlineAndCachedStatesUseDifferentContentAndRetryRemainsReachable() {
        var retries = 0
        rule.setContent { DshTheme { SessionsScreen(initial().copy(reader = SessionReadState(SessionReadPhase.OFFLINE)), {}, {}, {}, { retries++ }) } }
        rule.onNodeWithText("电脑离线").assertIsDisplayed()
        rule.onNodeWithText("需要电脑上线后才能读取内容。").assertIsDisplayed()
        rule.onNodeWithText("重新读取").performScrollTo().performClick()
        rule.runOnIdle { assertEquals(1, retries) }
        rule.onNodeWithText("会话还没有消息。").assertDoesNotExist()
    }
    @Test fun offlineHistoryIsLabeledAsCachedAndNeverClaimsTheCurrentTaskIsRunning() {
        val history = CachedTranscript(id, 1000, transcript().records).transcript
        rule.setContent { DshTheme { SessionsScreen(initial().copy(reader = SessionReadState(SessionReadPhase.OFFLINE, history)), {}, {}, {}, {}) } }
        rule.onNodeWithText("显示本机已确认保存的历史缓存。当前任务状态需重新连接确认。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("合成回复").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("电脑上的任务仍在进行。").assertDoesNotExist()
        rule.onNodeWithText("需要电脑上线后才能读取内容。").assertDoesNotExist()
        rule.onNodeWithText("会话还没有消息。").assertDoesNotExist()
    }
    @Test fun aNotificationFocusedQuestionAppearsOnceAndRequiresAnExplicitViewBeforeClaiming() {
        val prompt = jsonObject("id" to "choice".json(), "question" to "来自通知的当前提问".json(), "options" to JsonArray(listOf(jsonObject("label" to "A".json()))))
        val batch = jsonObject("question_id" to id.json(), "state" to "open".json(), "expires_at" to JsonNull, "questions" to JsonArray(listOf(prompt)))
        val model = SessionQuestions(SessionRoute(id, id, id, id), request).apply {
            attach(id)
            accept(SessionContent("question.timed.snapshot", request, id, jsonObject("revision" to 1L.json(), "items" to JsonArray(listOf(batch)))))
        }
        var claims = 0; var answers = 0
        rule.setContent { DshTheme { SessionsScreen(initial().copy(notificationQuestion = model.state(true).items.single().handle, notificationNote = "已核对当前提问", reader = SessionReadState(SessionReadPhase.READY, questions = model.state(true))), {}, {}, {}, {}, onClaim = { claims++ }, onAnswer = { _, _ -> answers++ }) } }
        rule.onNodeWithText("来自通知的当前提问").performScrollTo().assertIsDisplayed()
        rule.onAllNodesWithText("来自通知的当前提问").assertCountEquals(1)
        rule.runOnIdle { assertEquals(0, claims); assertEquals(0, answers) }
        rule.onNodeWithText("查看并答复").performScrollTo().performClick()
        rule.runOnIdle { assertEquals(1, claims); assertEquals(0, answers) }
    }
    @Test fun pendingApprovalHintRequiresCurrentOwnerAuthority() {
        val fixture = ApprovalUiFixture()
        val state = mutableStateOf(fixture.state(role = "viewer").copy(reviewingApprovalId = null, reader = SessionReadState(SessionReadPhase.READY)))
        rule.setContent { DshTheme { SessionsScreen(state.value, {}, {}, {}, {}) } }
        rule.onNodeWithText("当前会话需要你处理 · 查看").assertDoesNotExist()
        rule.runOnIdle { state.value = fixture.state().copy(reviewingApprovalId = null, reader = SessionReadState(SessionReadPhase.READY)) }
        rule.onNodeWithText("当前会话需要你处理 · 查看").assertIsDisplayed()
    }

    private val otherRequest = "33333333-3333-4333-8333-333333333333"
    private val epoch = "44444444-4444-4444-8444-444444444444"
    private fun authorized() = RuntimeDirectoryEntry.parse(jsonObject("id" to id.json(), "host_id" to id.json(), "organization_id" to id.json(), "protocol_version" to 1L.json(),
        "access" to jsonObject("role" to "operator".json(), "grant_version" to 1L.json(),
            "scope" to RelayScope(listOf("session.list", "session.read", "message.submit", "command.status", "session.cancel"), emptyList(), listOf(id)).json())))
    private fun ready(running: Boolean = false) = HomeState(HomePhase.READY, runtimes = listOf(RuntimeRow(id, id, "0.2.1-rc.2", "电脑夹具", authorized())),
        selectedRuntimeId = id, selectedSessionId = id, reader = SessionReadState(SessionReadPhase.READY, if (running) runningTranscript() else transcript(), runtimeEpoch = epoch))
    private fun runningTranscript(): SessionTranscript {
        val records = JsonArray(listOf(
            jsonObject("native_seq" to 1L.json(), "time" to 1L.json(), "type" to "turn/start".json(), "surface_op" to "append".json(),
                "data" to jsonObject("turn" to 1L.json())),
            jsonObject("native_seq" to 2L.json(), "time" to 2L.json(), "type" to "tool/call".json(), "surface_op" to "append".json(),
                "data" to jsonObject("callId" to "call-1".json(), "name" to "bash".json(), "arguments" to jsonObject()))
        ))
        return SessionWindow(request).apply {
            accept(SessionContent("session.snapshot", request, id, jsonObject("cursor" to 2L.json(), "has_more" to JsonBoolean(true),
                "assistant" to JsonNull, "records" to records)))
            accept(SessionContent("session.checkpoint", request, id, jsonObject("state" to "persisted".json(), "through_seq" to 2L.json())))
        }.snapshot()
    }
    private fun pending(newId: String, created: Long, delivery: CommandDelivery, remote: RemoteCommandState?, attempts: Long) =
        PendingCommand(CommandIntent.message(newId, id, id, "queue", "合成请求"), delivery, remote, attempts, 1, created, created + 500, null, false, false, null)

    @Test fun theNewestRequestIsVisibleInPlaceAndItsDetailsOpenWithThatOriginalRequest() {
        val newest = pending(otherRequest, 200, CommandDelivery.PENDING, null, 0)
        val older = pending(request, 100, CommandDelivery.CONFIRMED, RemoteCommandState.AGENT_QUEUED, 1)
        rule.setContent { DshTheme { SessionsScreen(ready().copy(outbox = CommandOutboxState(listOf(older, newest), connected = true)), {}, {}, {}, {}) } }
        rule.onNodeWithText("最近请求").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("手机待发送").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("查看发送记录").performScrollTo().performClick()
        rule.onNodeWithText("本机发送记录").assertIsDisplayed()
        rule.onNodeWithText("原请求：$otherRequest").assertIsDisplayed()
        rule.onNodeWithContentDescription("返回消息").performClick()
        rule.onNodeWithText("最近请求").performScrollTo().assertIsDisplayed()
    }
    @Test fun anEmptyJournalShowsNoRequestSummaryOrCancelAuthority() {
        rule.setContent { DshTheme { SessionsScreen(ready(running = true).copy(outbox = CommandOutboxState(connected = false)), {}, {}, {}, {}) } }
        rule.onNodeWithText("最近请求").assertDoesNotExist()
        rule.onNodeWithText("中断当前任务").assertDoesNotExist()
    }
    @Test fun interruptionNeedsLiveAuthorityAndReconfirmsBeforeSubmittingTheSavedEpoch() {
        var cancelled: String? = null
        val state = mutableStateOf(ready(running = true).copy(outbox = CommandOutboxState(connected = true)))
        rule.setContent { DshTheme { SessionsScreen(state.value, {}, {}, {}, {}, onCancelSession = { cancelled = it }) } }
        rule.onNodeWithText("中断当前任务").performScrollTo().assertIsDisplayed().performClick()
        rule.onNodeWithText("这不会清空已排队的消息。后续任务是否继续，以电脑端状态为准。").assertIsDisplayed()
        rule.runOnIdle { state.value = state.value.copy(outbox = CommandOutboxState(connected = false)) }
        rule.runOnIdle { assertEquals(null, cancelled) }
        rule.onNodeWithText("确认中断").assertDoesNotExist()
    }
    @Test fun toolRecordsExpandOnlyTheDisplayedFieldsAndNeverInventSuccess() {
        rule.setContent { DshTheme { SessionsScreen(ready(running = true), {}, {}, {}, {}) } }
        rule.onNodeWithText("bash").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("调用标识：call-1").assertDoesNotExist()
        rule.onNodeWithContentDescription("查看调用信息：bash").performScrollTo().performClick()
        assertEquals("已展开", rule.onNodeWithContentDescription("收起调用信息：bash").fetchSemanticsNode().config[SemanticsProperties.StateDescription])
        rule.onNodeWithText("调用标识：call-1").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("当前记录未提供更多详情。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("任务已完成").assertDoesNotExist()
        captureUiFixture(rule, "details-tool-expanded", darkTheme = false)
    }
    @Test fun aSharedCancelSummaryHasOneRouteWhileDifferentRequestsKeepTheirOwnRoutes() {
        val cancel = PendingCommand(CommandIntent.cancel(request, id, id, epoch), CommandDelivery.RECONCILE,
            RemoteCommandState.OUTCOME_UNKNOWN, 1, 1, 100, 100, null, true, false, null)
        val current = mutableStateOf(ready(running = true).copy(outbox = CommandOutboxState(listOf(cancel), connected = true)))
        rule.setContent { DshTheme { SessionsScreen(current.value, {}, {}, {}, {}) } }
        rule.onNodeWithText("查看发送记录").assertDoesNotExist()
        rule.onNodeWithText("查看原中断请求").performScrollTo().assertIsDisplayed()
        captureUiFixture(rule, "details-footer-pending-cancel", darkTheme = false)
        rule.onNodeWithText("查看原中断请求").performScrollTo().performClick()
        // The interruption status section also names this request; its ledger entry must be first and visible.
        rule.onAllNodesWithText("原请求：$request").onFirst().assertIsDisplayed()
        rule.onNodeWithContentDescription("返回消息").performClick()
        rule.runOnIdle {
            current.value = current.value.copy(outbox = CommandOutboxState(listOf(cancel,
                pending(otherRequest, 200, CommandDelivery.CONFIRMED, RemoteCommandState.HOST_ACCEPTED, 1)), connected = true))
        }
        rule.onNodeWithText("查看发送记录").performScrollTo().assertIsDisplayed()
        captureUiFixture(rule, "details-footer-distinct-requests", darkTheme = false)
        rule.onNodeWithText("查看发送记录").performScrollTo().performClick()
        rule.onNodeWithText("原请求：$otherRequest").assertIsDisplayed()
        rule.onNodeWithContentDescription("返回消息").performClick()
        rule.onNodeWithText("查看原中断请求").performScrollTo().performClick()
        rule.onAllNodesWithText("原请求：$request").onFirst().assertIsDisplayed()
    }
}
