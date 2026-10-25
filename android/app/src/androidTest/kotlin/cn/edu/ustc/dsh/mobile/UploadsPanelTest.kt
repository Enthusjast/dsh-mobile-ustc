package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.*
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
import java.time.Instant

@RunWith(AndroidJUnit4::class)
class UploadsPanelTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private val id = "11111111-1111-4111-8111-111111111111"
    private val fileId = "22222222-2222-4222-8222-222222222222"
    private fun row(phase: UploadPhase): UploadView {
        val now = System.currentTimeMillis()
        fun time(offset: Long) = Instant.ofEpochMilli(now + offset).toString().json()
        val manifest = FileManifest("研究资料.txt", 3, "a".repeat(64))
        val status = RemoteFileStatus.parse(jsonObject("file_id" to fileId.json(), "runtime_id" to id.json(), "session_id" to id.json(), "direction" to "to_host".json(), "name" to manifest.name.json(),
            "size_bytes" to 3L.json(), "sha256" to manifest.sha256.json(), "state" to "clean".json(), "created_at" to time(-1000), "upload_expires_at" to time(60_000), "expires_at" to time(300_000),
            "delivery" to if (phase == UploadPhase.READY) jsonObject("state" to "ready".json(), "expires_at" to time(4000)) else jsonObject("state" to "waiting".json())))
        return UploadView(StoredFileUpload(FileUploadIntent(id, id, id, null, manifest), fileId, null, now, now), phase, status)
    }
    private fun base(): HomeState {
        val access = RuntimeDirectoryEntry.parse(jsonObject("id" to id.json(), "host_id" to id.json(), "organization_id" to id.json(), "protocol_version" to 1L.json(), "access" to jsonObject("role" to "operator".json(),
            "grant_version" to 1L.json(), "scope" to RelayScope(listOf("session.list", "session.read", "message.submit", "command.status", "file.upload"), emptyList(), listOf(id)).json())))
        return HomeState(HomePhase.READY, runtimes = listOf(RuntimeRow(id, id, "0.2.1-rc.2", "电脑夹具", access)), selectedRuntimeId = id, selectedSessionId = id,
            reader = SessionReadState(SessionReadPhase.READY), outbox = CommandOutboxState(connected = true, canAttachFiles = true))
    }
    @Test fun aCleanWaitingFileCannotBeSelectedOrClaimedAsAgentAdmission() {
        val state = base().copy(uploads = SessionUploadState(listOf(row(UploadPhase.WAITING))))
        rule.setContent { DshTheme { SessionsScreen(state, {}, {}, {}, {}, {}, {}) } }
        rule.onNodeWithText("检查通过，等待电脑接收。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("加入下一条消息").assertDoesNotExist()
        rule.onNodeWithText("发送").assertIsNotEnabled()
        rule.onNodeWithText("Agent 已入队").assertDoesNotExist()
    }
    @Test fun readyFileOnlyMessagesUseTheExistingComposerWithoutInventingText() {
        var sent: Triple<String, String, Boolean>? = null
        rule.setContent { DshTheme {
            SessionsScreen(base().copy(uploads = SessionUploadState(listOf(row(UploadPhase.READY)), setOf(id))), {}, {}, {}, {}, {}, {}, { mode, text, online -> sent = Triple(mode, text, online) })
        } }
        rule.onNodeWithText("已选择 1 个附件，发送时仍需电脑确认。").assertExists()
        rule.onNodeWithText("发送").assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(Triple("queue", "", true), sent) }
    }
    @Test fun boundFilesDisplayTheOriginalIntentWithoutCallingTheTaskComplete() {
        rule.setContent { DshTheme { UploadsPanel(SessionUploadState(listOf(row(UploadPhase.BOUND))), true, {}, {}, {}, {}, {}) } }
        rule.onNodeWithText("已加入原请求，请核对发送记录；不代表任务完成。").assertIsDisplayed()
        rule.onNodeWithText("加入下一条消息").assertDoesNotExist()
        rule.onNodeWithText("任务已完成").assertDoesNotExist()
    }
}
