package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
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
class ExportsPanelTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private val id = "11111111-1111-4111-8111-111111111111"
    private val fileId = "22222222-2222-4222-8222-222222222222"
    private val name = "public-export-fixture.txt"
    private fun row(state: String? = null, error: String? = null, expired: Boolean = false): ExportView {
        val now = System.currentTimeMillis()
        fun time(offset: Long) = Instant.ofEpochMilli(now + offset).toString().json()
        val intent = FileExportIntent(id, id, id, id, id, null, ExportOrigin.SESSION_ATTACHMENT, name, 3)
        val status = state?.let { RemoteExportStatus.parse(jsonObject(
            "file_id" to fileId.json(), "runtime_id" to id.json(), "session_id" to id.json(), "direction" to "from_host".json(),
            "name" to name.json(), "size_bytes" to 3L.json(), "sha256" to "a".repeat(64).json(), "state" to it.json(),
            "created_at" to time(-1000), "upload_expires_at" to time(60_000), "expires_at" to time(if (expired) -1 else 3_600_000),
        )) }
        return ExportView(StoredFileExport(intent, status?.id, status?.manifest, now, now), status, error)
    }
    private fun page(unavailable: Boolean = false, stale: Boolean = false): ExportPage {
        val fields = linkedMapOf<String, JsonValue>(
            "source_id" to id.json(), "kind" to "file".json(), "origin" to "session_attachment".json(), "name" to name.json(),
            "size_bytes" to (if (unavailable) 2_000_000_001L else 3L).json(),
            "expires_at" to Instant.now().plusSeconds(if (stale) -1 else 3600).toString().json(),
        )
        if (unavailable) fields["unavailable"] = "file.too_large".json()
        return ExportPage.parse(jsonObject("items" to JsonArray(listOf(JsonObject(fields))), "directory_id" to JsonNull, "cursor" to JsonNull))
    }
    private fun content(body: @Composable () -> Unit) {
        rule.setContent { DshTheme { Column(Modifier.verticalScroll(rememberScrollState())) { body() } } }
    }

    @Test fun unknownAndTransferringRecordsNeverOfferSaveAndCleanStillDoesNotClaimSaved() {
        val state = mutableStateOf(SessionExportState(connected = true, rows = listOf(row())))
        content { ExportsPanel(state.value, { _, _ -> }, {}, {}, {}, {}, { fail("Unexpected save") }) }
        rule.onNodeWithText("原请求结果待核对；不会自动重新导出").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("保存到文档").assertDoesNotExist()
        rule.runOnIdle { state.value = state.value.copy(rows = listOf(row("uploading"))) }
        rule.onNodeWithText("电脑正在上传原文件").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("保存到文档").assertDoesNotExist()
        rule.runOnIdle { state.value = state.value.copy(rows = listOf(row("scanning"))) }
        rule.onNodeWithText("正在安全检查").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("保存到文档").assertDoesNotExist()
        rule.runOnIdle { state.value = state.value.copy(rows = listOf(row("clean"))) }
        rule.onNodeWithText("检查通过，可选择保存位置；尚未保存到文档。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("保存到文档").performScrollTo().assertIsEnabled()
        rule.onNodeWithText("文件已保存，回读校验通过。").assertDoesNotExist()
    }

    @Test fun savingDisablesDuplicateSaveAndCleanupFailureNeverClaimsSuccess() {
        val state = mutableStateOf(SessionExportState(rows = listOf(row("clean"))))
        val saving = mutableStateOf(false)
        var saves = 0
        content { ExportsPanel(state.value, { _, _ -> }, {}, {}, {}, {}, { saves++; saving.value = true }, saving.value) }
        rule.onNodeWithContentDescription("保存到文档：$name").performScrollTo().performClick()
        rule.onNodeWithContentDescription("保存到文档：$name").assertIsNotEnabled()
        rule.onNodeWithText("正在处理保存；下载校验与目标文档回读全部通过后才算保存成功。").performScrollTo().assertIsDisplayed()
        rule.runOnIdle {
            assertEquals(1, saves)
            saving.value = false
            state.value = state.value.copy(error = "file.save_cleanup_required")
        }
        rule.onNodeWithText("保存失败，目标文档可能不完整，请在所选位置删除。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("文件已保存，回读校验通过。").assertDoesNotExist()
        rule.onNodeWithText("保存到文档").performScrollTo().assertIsEnabled()
    }

    @Test fun deletingARecordNeedsConfirmationAndNeverCancelsTheExport() {
        val state = mutableStateOf(SessionExportState(connected = true, rows = listOf(row("uploading"))))
        var cancelled = false
        var removed: String? = null
        content { ExportsPanel(state.value, { _, _ -> }, {}, {}, { cancelled = true }, {
            removed = it
            state.value = state.value.copy(rows = emptyList())
        }) }
        rule.onNodeWithText("查看详情").performScrollTo().performClick()
        rule.onNodeWithText("删除本机记录").performScrollTo().performClick()
        rule.onNodeWithText("删除导出记录？").assertIsDisplayed()
        rule.runOnIdle { assertNull(removed); assertFalse(cancelled) }
        rule.onNodeWithText("保留记录").performClick()
        rule.onNodeWithText("电脑正在上传原文件").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("删除本机记录").performScrollTo().performClick()
        rule.onAllNodesWithText("删除本机记录").filterToOne(hasAnyAncestor(isDialog())).performClick()
        rule.onNodeWithText("还没有导出记录。").performScrollTo().assertIsDisplayed()
        rule.runOnIdle { assertEquals(id, removed); assertFalse(cancelled) }
    }

    @Test fun unavailableAndStaleSourcesExplainWhyTheyCannotBeExported() {
        val state = mutableStateOf(SessionExportState(connected = true, page = page(unavailable = true)))
        content { ExportsPanel(state.value, { _, _ -> }, { fail("Unavailable source exported") }, {}, {}, {}) }
        rule.onNodeWithText("超过 2 GB 上限，不能导出。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("准备导出").assertIsNotEnabled()
        rule.runOnIdle { state.value = state.value.copy(page = page(stale = true)) }
        rule.onNodeWithText("来源已失效，请重新浏览。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("准备导出").assertIsNotEnabled()
    }

    @Test fun aCleanButExpiredRecordCannotBeSavedAndScanFailuresHaveAnExplicitReason() {
        val state = mutableStateOf(SessionExportState(rows = listOf(row("clean", expired = true))))
        content { ExportsPanel(state.value, { _, _ -> }, {}, {}, {}, {}, { fail("Expired export saved") }) }
        rule.onNodeWithText("导出已过期，请核对原记录。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("保存到文档").assertDoesNotExist()
        rule.runOnIdle { state.value = state.value.copy(rows = listOf(row("scanning", "scan_unavailable"))) }
        rule.onNodeWithText("检查服务暂时不可用，请稍后核对原请求。").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("保存到文档").assertDoesNotExist()
    }

    @Test fun preparingAnAuthorizedSourcePassesTheOriginalOpaqueSourceWithoutInventingAPath() {
        val sources = page()
        var selected: ExportSource? = null
        content { ExportsPanel(SessionExportState(connected = true, page = sources), { _, _ -> }, { selected = it }, {}, {}, {}) }
        rule.onNodeWithText("导出来源").assertExists()
        rule.onNodeWithText("导出记录").assertExists()
        rule.onNodeWithText("准备导出").performScrollTo().performClick()
        rule.runOnIdle { assertSame(sources.items.single(), selected) }
    }
}
