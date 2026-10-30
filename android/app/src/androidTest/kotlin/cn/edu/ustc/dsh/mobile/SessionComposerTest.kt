package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import androidx.compose.ui.unit.dp
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
    @Test fun compactComposerKeepsModeInputAndSendReachableAtPhoneWidth() {
        rule.setContent { DshTheme { Box(Modifier.size(360.dp, 640.dp)) { SessionsScreen(state(), {}, {}, {}, {}) } } }
        val heightPx = rule.onNodeWithTag("message-composer").fetchSemanticsNode().boundsInRoot.height
        val heightDp = heightPx / rule.density.density
        assertTrue("ordinary input should stay compact: ${heightDp}dp", heightDp <= 128f)
        rule.onNodeWithText("排队发送").assertIsDisplayed()
        rule.onNodeWithText("消息内容").assertIsDisplayed()
        rule.onNodeWithContentDescription("发送").assertIsDisplayed()
        val directory = File(InstrumentationRegistry.getInstrumentation().targetContext.filesDir, "ui-navigation-fixtures").apply { mkdirs() }
        File(directory, "composer-360dp.png").outputStream().use { check(rule.onRoot().captureToImage().asAndroidBitmap().compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)) }
        File(directory, "composer-360dp.txt").writeText("heightDp=$heightDp; density=${rule.density.density}; fontScale=${rule.density.fontScale}; scene=online-no-attachments\n")
    }
    @Test fun attachmentPickerRequiresCurrentNegotiatedCapability() {
        val current = mutableStateOf(state().copy(uploads = SessionUploadState()))
        var picks = 0
        rule.setContent { DshTheme { SessionsScreen(current.value, {}, {}, {}, {}, onPickFile = { _, _, _ -> picks++ }) } }
        rule.onNodeWithText("附件不可用").performClick()
        rule.onNodeWithText("请连接电脑并核对附件上传权限与当前会话能力；未确认前不能上传附件。").assertIsDisplayed()
        rule.runOnIdle { assertEquals(0, picks) }
        rule.onNodeWithText("取消").performClick()
        rule.runOnIdle { current.value = current.value.copy(outbox = CommandOutboxState(connected = true, canAttachFiles = true)) }
        rule.onNodeWithText("添加附件").performClick()
        rule.runOnIdle { assertEquals(1, picks) }
    }
    @Test fun queueAndSteerAreExplicitAndOfflineActionOnlySavesToThisDevice() {
        var submitted: Triple<String, String, Boolean>? = null
        rule.setContent { DshTheme { SessionsScreen(state(false), {}, {}, {}, {}, { mode, text, send -> submitted = Triple(mode, text, send) }) } }
        rule.onNodeWithContentDescription("保存待发送").assertIsNotEnabled()
        rule.onNodeWithText("消息内容").performTextInput("离线草稿🙂")
        rule.onNodeWithText("排队发送").performClick()
        rule.onNodeWithText("补充当前任务").performClick()
        rule.onNodeWithContentDescription("保存待发送").assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(Triple("steer", "离线草稿🙂", false), submitted) }
    }
    @Test fun unsubmittedTextDoesNotEnterSavedInstanceState() {
        val restore = StateRestorationTester(rule)
        restore.setContent { DshTheme { SessionsScreen(state(), {}, {}, {}, {}, { _, _, _ -> }) } }
        rule.onNodeWithText("消息内容").performTextInput("UNSAVED_SENSITIVE_INPUT")
        rule.onNodeWithContentDescription("发送").assertIsEnabled()
        restore.emulateSavedInstanceStateRestore()
        rule.onNodeWithContentDescription("发送").assertIsNotEnabled()
    }
    @Test fun uncertainDeliveryNeverClaimsAgentQueueOrTaskCompletion() {
        val command = CommandIntent.message(id, id, id, "queue", "待核对正文")
        val record = CommandEvolution.begin(CommandEvolution.created(command, 1), 2)
        rule.setContent { DshTheme { SessionsScreen(state().copy(outbox = CommandOutboxState(listOf(record), true, error = "command.delivery_unconfirmed")), {}, {}, {}, {}) } }
        rule.onNodeWithText("尚未核对发送结果，请查询原请求状态；不会自动重复发送。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("会话详情").performClick()
        rule.onNode(hasScrollToIndexAction()).performScrollToNode(hasText("结果待核对"))
        rule.onNodeWithText("结果待核对").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Agent 已入队").assertDoesNotExist()
        rule.onNodeWithText("命令已完成").assertDoesNotExist()
        rule.onNodeWithText("重新转交同一请求").assertDoesNotExist()
    }

    @Test fun savingARequestShowsProgressWithoutClearingTheInputAndModeExplainsItsEffect() {
        val current = mutableStateOf(state())
        var submitted: Triple<String, String, Boolean>? = null
        rule.setContent { DshTheme { SessionsScreen(current.value, {}, {}, {}, {}, { mode, text, send -> submitted = Triple(mode, text, send) }) } }
        rule.onNodeWithText("消息内容").performTextInput("保持中的输入")
        rule.onNodeWithContentDescription("发送").assertIsEnabled()
        rule.runOnIdle { current.value = current.value.copy(submitting = true) }
        rule.onNodeWithText("正在保存请求…").assertIsDisplayed()
        rule.onNodeWithContentDescription("正在保存…").assertIsNotEnabled()
        rule.onNodeWithText("保持中的输入").assertExists()
        rule.onNodeWithText("排队发送").performClick()
        rule.onNodeWithText("等待轮到此消息时处理").assertIsDisplayed()
        rule.onNodeWithText("向电脑当前任务补充内容").assertIsDisplayed()
        rule.runOnIdle { assertEquals(null, submitted) }
    }
}
