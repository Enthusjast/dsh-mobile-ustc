package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SessionComposerTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private val id = "11111111-1111-4111-8111-111111111111"
    private fun state(online: Boolean = true): HomeState {
        val access = RuntimeDirectoryEntry.parse(jsonObject("id" to id.json(), "host_id" to id.json(), "organization_id" to id.json(), "protocol_version" to 1L.json(),
            "access" to jsonObject("role" to "operator".json(), "grant_version" to 1L.json(), "scope" to RelayScope(listOf("session.read", "session.list", "message.submit", "command.status"), emptyList(), listOf(id)).json())))
        return HomeState(HomePhase.READY, runtimes = listOf(RuntimeRow(id, id, "0.2.1-rc.2", "电脑夹具", access)), selectedRuntimeId = id, selectedSessionId = id,
            reader = SessionReadState(if (online) SessionReadPhase.READY else SessionReadPhase.OFFLINE), outbox = CommandOutboxState(connected = online))
    }
    @Test fun queueAndSteerAreExplicitAndOfflineActionOnlySavesToThisDevice() {
        var submitted: Triple<String, String, Boolean>? = null
        rule.setContent { DshTheme { SessionsScreen(state(false), {}, {}, {}, {}, {}, {}, { mode, text, send -> submitted = Triple(mode, text, send) }) } }
        rule.onNodeWithText("保存待发送").assertIsNotEnabled()
        rule.onNodeWithText("消息内容").performTextInput("离线草稿🙂")
        rule.onNodeWithText("插入当前任务").performClick()
        rule.onNodeWithText("保存待发送").assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(Triple("steer", "离线草稿🙂", false), submitted) }
    }
    @Test fun unsubmittedTextDoesNotEnterSavedInstanceState() {
        val restore = StateRestorationTester(rule)
        restore.setContent { DshTheme { SessionsScreen(state(), {}, {}, {}, {}, {}, {}, { _, _, _ -> }) } }
        rule.onNodeWithText("消息内容").performTextInput("UNSAVED_SENSITIVE_INPUT")
        rule.onNodeWithText("发送").assertIsEnabled()
        restore.emulateSavedInstanceStateRestore()
        rule.onNodeWithText("发送").assertIsNotEnabled()
    }
    @Test fun uncertainDeliveryNeverClaimsAgentQueueOrTaskCompletion() {
        val command = CommandIntent.message(id, id, id, "queue", "待核对正文")
        val record = CommandEvolution.begin(CommandEvolution.created(command, 1), 2)
        rule.setContent { DshTheme { SessionsScreen(state().copy(outbox = CommandOutboxState(listOf(record), true, error = "command.delivery_unconfirmed")), {}, {}, {}, {}, {}, {}) } }
        rule.onNodeWithText("尚未核对发送结果，请查询原请求状态；不会自动重复发送。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("结果待确认").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Agent 已入队").assertDoesNotExist()
        rule.onNodeWithText("命令已完成").assertDoesNotExist()
        rule.onNodeWithText("重新转交同一请求").assertDoesNotExist()
    }
}
