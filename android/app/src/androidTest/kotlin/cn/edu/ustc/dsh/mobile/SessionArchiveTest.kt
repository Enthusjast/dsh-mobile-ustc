package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
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
class SessionArchiveTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private val id = "11111111-1111-4111-8111-111111111111"
    private val epoch = "77777777-7777-4777-8777-777777777777"

    @Test fun archiveDefaultsToIdleOnlyAndStoppingRequiresAnExplicitChoice() {
        var result: Triple<String, Boolean, Boolean>? = null
        rule.setContent { DshTheme { SessionArchiveActions(false, epoch, true, true, { e, a, s -> result = Triple(e, a, s) }, {}) } }
        rule.onNodeWithText("归档会话").performClick()
        rule.onNodeWithText("同时请求停止当前活动").assertIsOff()
        rule.onNodeWithText("确认归档").performClick()
        rule.runOnIdle { assertEquals(Triple(epoch, true, false), result) }
        rule.onNodeWithText("归档会话").performClick()
        rule.onNodeWithText("同时请求停止当前活动").performClick().assertIsOn()
        rule.onNodeWithText("确认归档").performClick()
        rule.runOnIdle { assertEquals(Triple(epoch, true, true), result) }
    }

    @Test fun stopConsentAndAnOldEpochDialogCannotSurviveRecreationOrRuntimeChange() {
        val restore = StateRestorationTester(rule)
        val current = mutableStateOf(epoch)
        var writes = 0
        restore.setContent { DshTheme { SessionArchiveActions(false, current.value, true, true, { _, _, _ -> writes++ }, {}) } }
        rule.onNodeWithText("归档会话").performClick()
        rule.onNodeWithText("同时请求停止当前活动").performClick().assertIsOn()
        restore.emulateSavedInstanceStateRestore()
        rule.onNodeWithText("确认归档").assertDoesNotExist()
        rule.onNodeWithText("归档会话").performClick()
        rule.onNodeWithText("同时请求停止当前活动").assertIsOff()
        rule.runOnIdle { current.value = id }
        rule.onNodeWithText("确认归档").assertDoesNotExist()
        rule.runOnIdle { assertEquals(0, writes) }
    }

    @Test fun archivedViewHidesComposerAndRestoreNeverRequestsStopOrClaimsTaskCompletion() {
        val access = RuntimeDirectoryEntry.parse(jsonObject("id" to id.json(), "host_id" to id.json(), "organization_id" to id.json(), "protocol_version" to 1L.json(),
            "access" to jsonObject("role" to "operator".json(), "grant_version" to 1L.json(), "scope" to RelayScope(listOf("session.read", "session.list", "message.submit", "session.archive", "command.status"), emptyList(), listOf(id)).json())))
        val session = SessionDirectoryEntry.parse(jsonObject("session_id" to id.json(), "workspace_id" to JsonNull, "state" to "archived".json(), "last_persisted_seq" to (-1L).json(), "updated_at" to "2026-10-25T00:00:00Z".json()))
        val intent = CommandIntent.archive(id, id, id, epoch, true, true)
        val record = CommandEvolution.receipt(CommandEvolution.begin(CommandEvolution.created(intent, 1), 2), CommandReceipt(id, id, intent.digest, RemoteCommandState.SETTLED, "2026-10-25T00:00:00Z", epoch))
        val state = HomeState(HomePhase.READY, runtimes = listOf(RuntimeRow(id, id, "0.2.1-rc.2", "电脑夹具", access)), selectedRuntimeId = id, selectedSessionId = id, sessions = listOf(session),
            reader = SessionReadState(SessionReadPhase.READY, runtimeEpoch = epoch), outbox = CommandOutboxState(listOf(record), true, canArchive = true))
        var result: Triple<String, Boolean, Boolean>? = null
        rule.setContent { DshTheme { SessionsScreen(state, {}, {}, {}, {}, {}, onArchive = { e, a, s -> result = Triple(e, a, s) }) } }
        rule.onNodeWithText("消息内容").assertDoesNotExist()
        rule.onNodeWithText("会话详情").performClick()
        rule.onNodeWithText("已归档，仍可读取历史").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("恢复会话").performScrollTo().performClick()
        rule.onNodeWithText("同时请求停止当前活动").assertDoesNotExist()
        rule.onNodeWithText("确认恢复").performClick()
        rule.runOnIdle { assertEquals(Triple(epoch, false, false), result) }
        rule.onNodeWithText("归档操作已确认").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("命令已完成").assertDoesNotExist()
        rule.onNodeWithText("Agent 已入队").assertDoesNotExist()
    }
}
