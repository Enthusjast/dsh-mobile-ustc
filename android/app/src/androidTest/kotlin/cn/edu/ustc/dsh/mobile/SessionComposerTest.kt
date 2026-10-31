package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.test.platform.app.InstrumentationRegistry
import androidx.compose.ui.text.input.TextFieldValue
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
        val owner = CommandOwner(id, id, "a".repeat(64), id, id)
        return HomeState(HomePhase.READY, presentationOwner = owner, composer = MessageComposerState(ConversationResource(owner, id, id, id)),
            runtimes = listOf(RuntimeRow(id, id, "0.2.1-rc.2", "电脑夹具", access)), selectedRuntimeId = id, selectedSessionId = id,
            reader = SessionReadState(if (online) SessionReadPhase.READY else SessionReadPhase.OFFLINE), outbox = CommandOutboxState(connected = online))
    }
    @Composable
    private fun ComposerFixture(initial: HomeState = state(), current: MutableState<HomeState>? = null,
        onBack: () -> Unit = {}, onSubmit: (MessageSubmission) -> Unit = {}, onPickFile: (String?) -> Unit = {}) {
        val live = current ?: remember { mutableStateOf(initial) }
        SessionsScreen(live.value, onBack, {}, {}, {}, onSubmit = onSubmit, onPickFile = onPickFile,
            onComposerChange = { live.value = live.value.copy(composer = it.copy(revision = it.revision + 1)) })
    }
    @Test fun compactComposerKeepsModeInputAndSendReachableAtPhoneWidth() {
        rule.setContent { DshTheme { Box(Modifier.size(360.dp, 640.dp)) { ComposerFixture() } } }
        val heightPx = rule.onNodeWithTag("message-composer").fetchSemanticsNode().boundsInRoot.height
        val heightDp = heightPx / rule.density.density
        assertTrue("ordinary input should stay compact: ${heightDp}dp", heightDp <= 128f)
        rule.onNodeWithText("排队发送").assertIsDisplayed()
        rule.onNodeWithText("消息内容").assertIsDisplayed()
        rule.onNodeWithContentDescription("发送 · 排队").assertIsDisplayed()
        val directory = File(InstrumentationRegistry.getInstrumentation().targetContext.filesDir, "ui-navigation-fixtures").apply { mkdirs() }
        File(directory, "composer-360dp.png").outputStream().use { check(rule.onRoot().captureToImage().asAndroidBitmap().compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)) }
        File(directory, "composer-360dp.txt").writeText("heightDp=$heightDp; density=${rule.density.density}; fontScale=${rule.density.fontScale}; scene=online-no-attachments\n")
    }
    @Test fun attachmentPickerRequiresCurrentNegotiatedCapability() {
        val current = mutableStateOf(state().copy(uploads = SessionUploadState()))
        var picks = 0
        rule.setContent { DshTheme { ComposerFixture(current = current, onPickFile = { picks++ }) } }
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
        rule.setContent { DshTheme { ComposerFixture(state(false), onSubmit = { submitted = Triple(it.draft.mode, it.draft.value.text, it.sendNow) }) } }
        rule.onNodeWithContentDescription("保存待发送").assertIsNotEnabled()
        rule.onNodeWithText("消息内容").performTextInput("离线草稿🙂")
        rule.onNodeWithText("排队发送").performClick()
        rule.onNodeWithText("补充当前任务").performClick()
        rule.onNodeWithContentDescription("保存待发送").assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(Triple("steer", "离线草稿🙂", false), submitted) }
    }
    @Test fun unsubmittedTextDoesNotEnterSavedInstanceState() {
        val restore = StateRestorationTester(rule)
        restore.setContent { DshTheme { ComposerFixture() } }
        rule.onNodeWithText("消息内容").performTextInput("UNSAVED_SENSITIVE_INPUT")
        rule.onNodeWithContentDescription("发送 · 排队").assertIsEnabled()
        restore.emulateSavedInstanceStateRestore()
        rule.onNodeWithContentDescription("发送 · 排队").assertIsNotEnabled()
    }
    @Test fun uncertainDeliveryNeverClaimsAgentQueueOrTaskCompletion() {
        val command = CommandIntent.message(id, id, id, "queue", "待核对正文")
        val record = CommandEvolution.begin(CommandEvolution.created(command, 1), 2)
        rule.setContent { DshTheme { SessionsScreen(state().copy(outbox = CommandOutboxState(listOf(record), true, error = "command.delivery_unconfirmed")), {}, {}, {}, {}) } }
        rule.onNodeWithText("尚未核对发送结果，请查询原请求状态；不会自动重复发送。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithContentDescription("会话详情").performClick()
        rule.onNodeWithText("原请求记录").performClick()
        rule.onNode(hasScrollToIndexAction()).performScrollToNode(hasText("结果待核对"))
        rule.onNodeWithText("结果待核对").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Agent 已入队").assertDoesNotExist()
        rule.onNodeWithText("命令已完成").assertDoesNotExist()
        rule.onNodeWithText("重新转交同一请求").assertDoesNotExist()
    }

    @Test fun savingARequestShowsProgressWithoutClearingTheInputAndModeExplainsItsEffect() {
        val current = mutableStateOf(state())
        var submitted: Triple<String, String, Boolean>? = null
        rule.setContent { DshTheme { ComposerFixture(current = current, onSubmit = { submitted = Triple(it.draft.mode, it.draft.value.text, it.sendNow) }) } }
        rule.onNodeWithText("消息内容").performTextInput("保持中的输入")
        rule.onNodeWithContentDescription("发送 · 排队").assertIsEnabled()
        rule.runOnIdle { current.value = current.value.copy(submitting = true) }
        rule.onNodeWithText("正在保存请求…").assertIsDisplayed()
        rule.onNodeWithContentDescription("正在保存…").assertIsNotEnabled()
        rule.onNodeWithText("保持中的输入").assertExists()
        rule.onNodeWithText("排队发送").performClick()
        rule.onNodeWithText("等待轮到此消息时处理").assertIsDisplayed()
        rule.onNodeWithText("向电脑当前任务补充内容").assertIsDisplayed()
        rule.runOnIdle { assertEquals(null, submitted) }
    }
    @Test fun anOversizedEditPreservesTheOriginalAndRequiresAValidEditBeforeSending() {
        var submitted: Triple<String, String, Boolean>? = null
        rule.setContent { DshTheme { ComposerFixture(onSubmit = { submitted = Triple(it.draft.mode, it.draft.value.text, it.sendNow) }) } }
        rule.onNodeWithText("消息内容").performTextInput("保留🙂")
        rule.onNodeWithText("消息内容").performTextReplacement("z".repeat(65_537))
        assertEquals("保留🙂", rule.onNodeWithText("消息内容").fetchSemanticsNode().config[SemanticsProperties.EditableText].text)
        rule.onNodeWithText("内容过长，本次输入未接收；原输入未改变。").assertIsDisplayed()
        rule.onNodeWithContentDescription("发送 · 排队").assertIsNotEnabled()
        rule.runOnIdle { assertNull(submitted) }
        rule.onNodeWithText("消息内容").performTextReplacement("修正后的请求")
        rule.onNodeWithText("内容过长，本次输入未接收；原输入未改变。").assertDoesNotExist()
        rule.onNodeWithContentDescription("发送 · 排队").assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(Triple("queue", "修正后的请求", true), submitted) }
    }
    @Test fun fullscreenUsesTheSameDraftAndEnterOnlyInsertsText() {
        val current = mutableStateOf(state())
        var submitted: MessageSubmission? = null
        rule.setContent { DshTheme { ComposerFixture(current = current, onSubmit = { submitted = it }) } }
        rule.onNodeWithText("消息内容").performTextInput("首行\n候选🙂")
        rule.onNodeWithText("排队发送").performClick()
        rule.onNodeWithText("补充当前任务").performClick()
        val revision = current.value.composer!!.revision
        rule.onNodeWithText("展开编辑").performClick()
        rule.onNodeWithText("首行\n候选🙂").assertExists()
        rule.onNodeWithContentDescription("发送 · 补充").assertIsDisplayed()
        rule.onNodeWithText("消息内容").performTextInput("\n下一行")
        rule.onNodeWithText("收起编辑").performClick()
        rule.onNodeWithText("首行\n候选🙂\n下一行").assertExists()
        rule.runOnIdle {
            assertTrue(current.value.composer!!.revision > revision)
            assertEquals("steer", current.value.composer!!.mode)
            assertNull(submitted)
        }
        rule.onNodeWithContentDescription("发送 · 补充").performClick()
        rule.runOnIdle { assertEquals(current.value.composer, submitted!!.draft) }
    }
    @Test fun failedOriginalRequiresConfirmationBeforeReplacingNewInputAndNeverSendsIt() {
        val drafts = ConversationDrafts()
        val base = state()
        val original = drafts.edit(drafts.open(base.composer!!.resource).copy(value = TextFieldValue("先前输入"), mode = "steer"))!!
        val newer = drafts.edit(original.copy(value = TextFieldValue("继续编辑的新稿"), mode = "queue"))!!
        val current = mutableStateOf(base.copy(composer = newer, failedInput = drafts.retainFailed(original)))
        var submitted = false
        rule.setContent { DshTheme {
            SessionsScreen(current.value, {}, {}, {}, {}, onSubmit = { submitted = true },
                onComposerChange = { candidate -> drafts.edit(candidate)?.let { current.value = current.value.copy(composer = it) } },
                onResolveFailedInput = { failed, restore -> drafts.resolveFailure(failed, restore)?.let { current.value = current.value.copy(composer = it, failedInput = null) } })
        } }
        rule.onNodeWithText("取回原输入").performScrollTo().performClick()
        rule.onNodeWithText("继续编辑的新稿").assertExists()
        rule.onNodeWithText("取消").performClick()
        rule.runOnIdle { assertEquals(newer, current.value.composer); assertFalse(submitted) }
        rule.onNodeWithText("取回原输入").performScrollTo().performClick()
        rule.onNodeWithText("确认取回").performClick()
        rule.onNodeWithText("先前输入").assertIsDisplayed()
        rule.onNodeWithContentDescription("发送 · 补充").assertIsEnabled()
        rule.runOnIdle { assertTrue(current.value.composer!!.revision > newer.revision); assertFalse(submitted); assertNull(current.value.failedInput) }
    }
}
