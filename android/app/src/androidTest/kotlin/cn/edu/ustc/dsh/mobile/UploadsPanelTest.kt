package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.test.core.app.ActivityScenario
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.height
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.ui.DshTheme
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import java.io.File
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

@RunWith(AndroidJUnit4::class)
class UploadsPanelTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private val id = "11111111-1111-4111-8111-111111111111"
    private val fileId = "22222222-2222-4222-8222-222222222222"
    private fun row(phase: UploadPhase, requestId: String = id, remoteId: String = fileId, name: String = "研究资料.txt"): UploadView {
        val now = System.currentTimeMillis()
        fun time(offset: Long) = Instant.ofEpochMilli(now + offset).toString().json()
        val manifest = FileManifest(name, 3, "a".repeat(64))
        val status = RemoteFileStatus.parse(jsonObject("file_id" to remoteId.json(), "runtime_id" to id.json(), "session_id" to id.json(), "direction" to "to_host".json(), "name" to manifest.name.json(),
            "size_bytes" to 3L.json(), "sha256" to manifest.sha256.json(), "state" to "clean".json(), "created_at" to time(-1000), "upload_expires_at" to time(60_000), "expires_at" to time(300_000),
            "delivery" to if (phase == UploadPhase.READY) jsonObject("state" to "ready".json(), "expires_at" to time(240_000)) else jsonObject("state" to "waiting".json())))
        return UploadView(StoredFileUpload(FileUploadIntent(requestId, id, id, null, manifest), remoteId, null, now, now), phase, status)
    }
    private fun base(): HomeState {
        val access = RuntimeDirectoryEntry.parse(jsonObject("id" to id.json(), "host_id" to id.json(), "organization_id" to id.json(), "protocol_version" to 1L.json(), "access" to jsonObject("role" to "operator".json(),
            "grant_version" to 1L.json(), "scope" to RelayScope(listOf("session.list", "session.read", "message.submit", "command.status", "file.upload"), emptyList(), listOf(id)).json())))
        return HomeState(HomePhase.READY, runtimes = listOf(RuntimeRow(id, id, "0.2.1-rc.2", "电脑夹具", access)), selectedRuntimeId = id, selectedSessionId = id,
            reader = SessionReadState(SessionReadPhase.READY), outbox = CommandOutboxState(connected = true, canAttachFiles = true))
    }
    @Test fun aCleanWaitingFileCannotBeSelectedOrClaimedAsAgentAdmission() {
        val state = base().copy(uploads = SessionUploadState(listOf(row(UploadPhase.WAITING))))
        rule.setContent { DshTheme { Column(Modifier.verticalScroll(rememberScrollState())) { UploadsPanel(state.uploads!!, true, {}, {}, {}, {}, {}) } } }
        rule.onNodeWithText("检查通过，等待电脑接收。").performScrollTo().assertIsDisplayed()
        captureUiFixture(rule, "upload-waiting")
        rule.onNodeWithText("加入下一条消息").assertDoesNotExist()
        rule.onAllNodes(isToggleable()).assertCountEquals(0)
        rule.onNodeWithText("Agent 已入队").assertDoesNotExist()
    }
    @Test fun readyFileOnlyMessagesUseTheExistingComposerWithoutInventingText() {
        var sent: Triple<String, String, Boolean>? = null
        rule.setContent { DshTheme {
            SessionsScreen(base().copy(uploads = SessionUploadState(listOf(row(UploadPhase.READY)), setOf(id))), {}, {}, {}, {}, { mode, text, online -> sent = Triple(mode, text, online) })
        } }
        rule.onNodeWithText("已选择 1 个附件，发送时仍需电脑确认。").assertExists()
        rule.onNodeWithContentDescription("发送").assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(Triple("queue", "", true), sent) }
    }
    @Test fun boundFilesDisplayTheOriginalIntentWithoutCallingTheTaskComplete() {
        rule.setContent { DshTheme { Column(Modifier.verticalScroll(rememberScrollState())) { UploadsPanel(SessionUploadState(listOf(row(UploadPhase.BOUND))), true, {}, {}, {}, {}, {}) } } }
        rule.onNodeWithText("已加入原请求，请核对发送记录；不代表任务完成。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("加入下一条消息").assertDoesNotExist()
        rule.onNodeWithText("任务已完成").assertDoesNotExist()
    }
    @Test fun cancellingASelectionKeepsTheUploadRecordAndDeletingRequiresConfirmation() {
        val state = mutableStateOf(SessionUploadState(listOf(row(UploadPhase.READY)), setOf(id)))
        var deleted: String? = null
        rule.setContent { DshTheme { Column(Modifier.verticalScroll(rememberScrollState())) {
            UploadsPanel(state.value, true, {}, { selected ->
                state.value = state.value.copy(selected = state.value.selected - selected)
            }, {}, { removed ->
                deleted = removed
                state.value = state.value.copy(rows = state.value.rows.filterNot { it.stored.intent.requestId == removed })
            }, {})
        } } }
        rule.onNodeWithText("取消选择").performScrollTo().performClick()
        rule.onNodeWithText("本次选择（0）").assertExists()
        rule.onNodeWithText("研究资料.txt").performScrollTo().assertIsDisplayed()
        rule.runOnIdle { assertNull(deleted) }
        rule.onNodeWithText("查看详情").performScrollTo().performClick()
        rule.onNodeWithText("删除本机记录").performScrollTo().performClick()
        rule.onNodeWithText("删除上传记录？").assertIsDisplayed()
        rule.onNodeWithText("保留记录").performClick()
        rule.runOnIdle { assertNull(deleted) }
        rule.onNodeWithText("删除本机记录").performScrollTo().performClick()
        rule.onAllNodesWithText("删除本机记录").filterToOne(hasAnyAncestor(isDialog())).performClick()
        rule.onNodeWithText("还没有上传记录。").performScrollTo().assertIsDisplayed()
        rule.runOnIdle { assertEquals(id, deleted) }
    }

    @Test fun aReadyPhaseWithoutCurrentStagingCannotBeSelected() {
        val stale = row(UploadPhase.READY).copy(status = row(UploadPhase.WAITING).status)
        rule.setContent { DshTheme { Column(Modifier.verticalScroll(rememberScrollState())) {
            UploadsPanel(SessionUploadState(listOf(stale)), true, {}, { fail("Unready attachment selected") }, {}, {}, {})
        } } }
        rule.onNodeWithText("暂存状态需重新核对，当前不可发送。").performScrollTo().assertIsDisplayed()
        rule.onAllNodes(isToggleable()).assertCountEquals(0)
        rule.onNodeWithText("加入下一条消息").assertDoesNotExist()
    }

    @Test fun losingStagingOnTheSameRecordRemovesTheSelectionControl() {
        val state = mutableStateOf(SessionUploadState(listOf(row(UploadPhase.READY))))
        rule.setContent { DshTheme { Column(Modifier.verticalScroll(rememberScrollState())) {
            UploadsPanel(state.value, true, {}, { fail("Unexpected toggle") }, {}, {}, {})
        } } }
        rule.onAllNodes(isToggleable()).assertCountEquals(1)
        rule.runOnIdle { state.value = state.value.copy(rows = listOf(row(UploadPhase.WAITING))) }
        rule.onAllNodes(isToggleable()).assertCountEquals(0)
        rule.onNodeWithText("检查通过，等待电脑接收。").performScrollTo().assertIsDisplayed()
    }

    @Test fun transferringAndUnknownResultsDoNotOfferMessageSelection() {
        val state = mutableStateOf(SessionUploadState(listOf(row(UploadPhase.UPLOADING).copy(bytes = 1)), busy = true))
        rule.setContent { DshTheme { Column(Modifier.verticalScroll(rememberScrollState())) {
            UploadsPanel(state.value, true, {}, { fail("Unready attachment selected") }, {}, {}, {})
        } } }
        rule.onNodeWithText("正在上传：", substring = true).performScrollTo().assertIsDisplayed()
        rule.onAllNodes(isToggleable()).assertCountEquals(0)
        rule.runOnIdle { state.value = SessionUploadState(listOf(row(UploadPhase.ERROR))) }
        rule.onNodeWithText("上传结果待核对；不会自动创建新上传。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("重选原文件").performScrollTo().assertIsEnabled()
        rule.onAllNodes(isToggleable()).assertCountEquals(0)
    }

    @Test fun attachmentStripKeepsFullNamesReachableAndRemovalDistinctFromDetails() {
        val secondId = "33333333-3333-4333-8333-333333333333"
        val files = mutableStateOf(SessionUploadState(listOf(row(UploadPhase.READY),
            row(UploadPhase.READY, secondId, "44444444-4444-4444-8444-444444444444", "待分析日志.txt")), setOf(id, secondId)))
        var toggled: String? = null
        rule.setContent { DshTheme {
            SessionsScreen(base().copy(uploads = files.value), {}, {}, {}, {}, onToggleFile = { selected ->
                toggled = selected
                files.value = files.value.copy(selected = files.value.selected - selected)
            }, onRemoveFile = { fail("Removing a message selection must not delete an upload record") })
        } }
        rule.onNodeWithContentDescription("查看附件详情：研究资料.txt").performClick()
        rule.onNode(hasText("研究资料.txt") and hasAnyAncestor(isDialog())).assertIsDisplayed()
        rule.onNodeWithText("关闭").performClick()
        rule.onNodeWithContentDescription("移出本次消息：研究资料.txt").performClick()
        rule.runOnIdle { assertEquals(id, toggled) }
        rule.onNodeWithContentDescription("移出本次消息：研究资料.txt").assertDoesNotExist()
        rule.onNodeWithContentDescription("移出本次消息：待分析日志.txt").assertExists()
        rule.onNodeWithText("查看附件").performClick()
        rule.onNodeWithText("会话附件").assertIsDisplayed()
        rule.onNodeWithContentDescription("核对上传状态：研究资料.txt").performScrollTo().assertIsEnabled()
        rule.onNodeWithContentDescription("查看文件详情：研究资料.txt").performScrollTo().performClick()
        assertEquals("已展开", rule.onNodeWithContentDescription("收起文件详情：研究资料.txt").fetchSemanticsNode().config[SemanticsProperties.StateDescription])
        rule.onNodeWithText("原请求：$id").performScrollTo().assertIsDisplayed()
        rule.onNodeWithContentDescription("返回消息").assertIsDisplayed()
    }
    @Test fun aLongAttachmentNameCanBeReadAndClosedAtLargeTextWithoutChangingSelection() {
        val name = "研究资料".repeat(10) + ".txt"
        val fontScale = 2f
        val files = SessionUploadState(listOf(row(UploadPhase.READY, name = name)), setOf(id))
        ActivityScenario.launch(LargeTextUiFixtureActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertEquals(fontScale, activity.resources.configuration.fontScale, 0f)
                activity.setContent { DshTheme(darkTheme = true) { Box(Modifier.width(320.dp).height(480.dp)) {
                    SessionsScreen(base().copy(uploads = files), {}, {}, {}, {},
                        onToggleFile = { fail("Reading attachment details must not change message selection") })
                } } }
            }
            val back = rule.onNodeWithContentDescription("返回会话列表").assertIsDisplayed().fetchSemanticsNode().boundsInRoot
            val composer = rule.onNodeWithTag("message-composer").fetchSemanticsNode().boundsInRoot
            assertTrue("The attachment composer must not cover the title-bar back action", back.bottom <= composer.top)
            rule.onNodeWithText("消息内容").assertIsDisplayed()
            rule.onNodeWithContentDescription("发送").assertIsDisplayed().assertIsEnabled()
            fun revealFileActions() {
                val options = rule.onNode(SemanticsMatcher.keyIsDefined(SemanticsProperties.VerticalScrollAxisRange) and
                    hasAnyDescendant(hasContentDescription("查看附件详情：$name")))
                val maximum = options.fetchSemanticsNode().config[SemanticsProperties.VerticalScrollAxisRange].maxValue()
                options.performSemanticsAction(SemanticsActions.ScrollBy) { it(0f, maximum) }
            }
            revealFileActions()
            rule.onNodeWithContentDescription("查看附件详情：$name").assertIsDisplayed().performClick()
            val appliedFontScale = rule.onNode(hasText(name) and hasAnyAncestor(isDialog())).performScrollTo()
                .assertIsDisplayed().fetchSemanticsNode().layoutInfo.density.fontScale
            assertEquals(fontScale, appliedFontScale, 0f)
            rule.onNodeWithText("关闭").assertIsDisplayed()
            captureUiFixture(rule, "details-long-attachment-dialog", dialog = true, darkTheme = true)
            rule.onNodeWithText("关闭").performClick()
            revealFileActions()
            rule.onNodeWithContentDescription("移出本次消息：$name").assertIsDisplayed()
            captureUiFixture(rule, "details-long-attachment-strip", dialog = true, darkTheme = true)
            for (scene in listOf("details-long-attachment-dialog", "details-long-attachment-strip")) {
                val metadata = File(InstrumentationRegistry.getInstrumentation().targetContext.filesDir,
                    "ui-navigation-fixtures/$scene.json")
                metadata.writeText(JSONObject(metadata.readText()).put("fontScale", appliedFontScale).toString(2))
            }
        }
    }
}
