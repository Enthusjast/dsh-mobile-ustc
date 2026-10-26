package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
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
        rule.setContent { DshTheme { SessionsScreen(initial().copy(reader = SessionReadState(SessionReadPhase.READY, transcript())), {}, {}, {}, { pages++ }, {}, {}) } }
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
        rule.setContent { DshTheme { SessionsScreen(initial().copy(reader = SessionReadState(SessionReadPhase.OFFLINE)), {}, {}, {}, {}, { retries++ }, {}) } }
        rule.onNodeWithText("电脑离线").assertIsDisplayed()
        rule.onNodeWithText("需要电脑上线后才能读取内容。").assertIsDisplayed()
        rule.onNodeWithText("重新读取").performScrollTo().performClick()
        rule.runOnIdle { assertEquals(1, retries) }
        rule.onNodeWithText("会话还没有消息。").assertDoesNotExist()
    }
    @Test fun listOnlyGrantDisablesBodyReadAndNavigationRemainsAvailable() {
        val grant = RuntimeDirectoryEntry.parse(jsonObject("id" to id.json(), "host_id" to id.json(), "organization_id" to id.json(), "protocol_version" to 1L.json(),
            "access" to jsonObject("role" to "viewer".json(), "grant_version" to 1L.json(), "scope" to RelayScope(listOf("session.list"), emptyList(), listOf(id)).json())))
        val session = SessionDirectoryEntry.parse(jsonObject("session_id" to id.json(), "workspace_id" to JsonNull, "state" to "available".json(), "last_persisted_seq" to 0L.json(), "updated_at" to "2026-10-25T00:00:00Z".json()))
        var back = 0
        rule.setContent { DshTheme { SessionsScreen(initial().copy(selectedSessionId = null, runtimes = listOf(RuntimeRow(id, id, "0.2.1-rc.2", "夹具电脑", grant)), sessions = listOf(session)), {}, { back++ }, {}, {}, {}, {}) } }
        rule.onNodeWithText("读取会话").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("当前授权仅可查看目录。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("返回电脑列表").performScrollTo().performClick()
        rule.runOnIdle { assertEquals(1, back) }
    }
    @Test fun offlineHistoryIsLabeledAsCachedAndNeverClaimsTheCurrentTaskIsRunning() {
        val history = CachedTranscript(id, 1000, transcript().records).transcript
        rule.setContent { DshTheme { SessionsScreen(initial().copy(reader = SessionReadState(SessionReadPhase.OFFLINE, history)), {}, {}, {}, {}, {}, {}) } }
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
        rule.setContent { DshTheme { SessionsScreen(initial().copy(notificationQuestion = model.state(true).items.single().handle, notificationNote = "已核对当前提问", reader = SessionReadState(SessionReadPhase.READY, questions = model.state(true))),
            {}, {}, {}, {}, {}, {}, onClaim = { claims++ }, onAnswer = { _, _ -> answers++ }) } }
        rule.onNodeWithText("来自通知的当前提问").performScrollTo().assertIsDisplayed()
        rule.onAllNodesWithText("来自通知的当前提问").assertCountEquals(1)
        rule.runOnIdle { assertEquals(0, claims); assertEquals(0, answers) }
        rule.onNodeWithText("查看并答复").performScrollTo().performClick()
        rule.runOnIdle { assertEquals(1, claims); assertEquals(0, answers) }
    }
}
