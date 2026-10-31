package cn.edu.ustc.dsh.mobile

import android.graphics.Bitmap
import android.view.WindowManager
import android.view.inspector.WindowInspector
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import cn.edu.ustc.dsh.command.FileUploadIntent
import cn.edu.ustc.dsh.command.StoredFileUpload
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

@RunWith(AndroidJUnit4::class)
class SessionImagesPanelTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private val request = "11111111-1111-4111-8111-111111111111"
    private val file = "22222222-2222-4222-8222-222222222222"
    private fun row(phase: UploadPhase, image: Boolean = true, name: String = "待分析照片.png"): UploadView {
        val now = System.currentTimeMillis()
        fun time(offset: Long) = Instant.ofEpochMilli(now + offset).toString().json()
        val manifest = FileManifest(name, 3, "a".repeat(64))
        val intent = FileUploadIntent(request, request, request, null, manifest,
            if (image) ImageUploadMetadata("image/png", 8, 8) else null)
        val status = RemoteFileStatus.parse(jsonObject(
            "file_id" to file.json(), "runtime_id" to request.json(), "session_id" to request.json(),
            "direction" to "to_host".json(), "name" to name.json(), "size_bytes" to 3L.json(),
            "sha256" to manifest.sha256.json(), "state" to "clean".json(),
            "created_at" to time(-1000), "upload_expires_at" to time(60_000), "expires_at" to time(300_000),
            "delivery" to if (phase == UploadPhase.READY) jsonObject("state" to "ready".json(), "expires_at" to time(240_000))
                else jsonObject("state" to "waiting".json()),
        ))
        return UploadView(StoredFileUpload(intent, file, null, now, now), phase, status)
    }

    @Test fun unsupportedPeerExplainsVisionAndDisablesBothExplicitEntryPoints() {
        rule.setContent { DshTheme { Column(Modifier.verticalScroll(rememberScrollState())) {
            SessionImagesPanel(SessionImageState(), null, false,
                { fail("Gallery must be disabled") }, { fail("Camera must be disabled") }, {}, {}, {}, {}, {})
        } } }
        rule.onNodeWithText("当前电脑、模型或授权尚未确认支持原生图片输入。仍可通过普通附件发送文件，但这不代表模型能够看图。").assertExists()
        rule.onNodeWithText("从系统照片选择").assertIsNotEnabled().assertHeightIsAtLeast(48.dp)
        rule.onNodeWithText("使用系统相机拍照").assertIsNotEnabled().assertHeightIsAtLeast(48.dp)
    }

    @Test fun imageFilenameAloneNeverCreatesAVisualImageRow() {
        rule.setContent { DshTheme { Column(Modifier.verticalScroll(rememberScrollState())) {
            SessionImagesPanel(SessionImageState(), SessionUploadState(listOf(row(UploadPhase.READY, image = false))), true,
                {}, {}, { fail("Generic file must not become image") }, {}, {}, {}, {})
        } } }
        rule.onNodeWithText("待分析照片.png").assertDoesNotExist()
        rule.onNodeWithText("还没有图片上传记录。").assertExists()
        rule.onAllNodes(isToggleable()).assertCountEquals(0)
    }

    @Test fun scannerAndNativeReadinessAreDistinctAndOnlyReadyImageCanBeSelected() {
        val uploads = mutableStateOf(SessionUploadState(listOf(row(UploadPhase.SCANNING))))
        var toggled: String? = null
        rule.setContent { DshTheme { Column(Modifier.verticalScroll(rememberScrollState())) {
            SessionImagesPanel(SessionImageState(), uploads.value, true, {}, {}, { toggled = it }, {}, {}, {}, {})
        } } }
        rule.onNodeWithText("正在进行安全检查；尚未交给模型。").performScrollTo().assertIsDisplayed()
        rule.onAllNodes(isToggleable()).assertCountEquals(0)
        rule.runOnIdle { uploads.value = SessionUploadState(listOf(row(UploadPhase.WAITING))) }
        rule.onNodeWithText("检查通过，等待电脑暂存图片文件；发送时仍须原生图片校验。").performScrollTo().assertIsDisplayed()
        rule.onAllNodes(isToggleable()).assertCountEquals(0)
        rule.runOnIdle { uploads.value = SessionUploadState(listOf(row(UploadPhase.READY))) }
        rule.onNodeWithContentDescription("将图片加入下一条消息：待分析照片.png").performScrollTo().performClick()
        rule.runOnIdle { assertEquals(request, toggled) }
    }

    @Test fun staleSelectionCanBeRemovedAndDeletingLocalRecordNeedsConfirmation() {
        val uploads = mutableStateOf(SessionUploadState(listOf(row(UploadPhase.WAITING)), setOf(request)))
        var deleted: String? = null
        rule.setContent { DshTheme { Column(Modifier.verticalScroll(rememberScrollState())) {
            SessionImagesPanel(SessionImageState(), uploads.value, false, {}, {}, {
                uploads.value = uploads.value.copy(selected = emptySet())
            }, {}, { deleted = it }, {}, {})
        } } }
        rule.onNodeWithContentDescription("移出本次消息的图片：待分析照片.png").performScrollTo().performClick()
        rule.onAllNodes(isToggleable()).assertCountEquals(0)
        rule.onNodeWithContentDescription("删除图片本机记录：待分析照片.png").performScrollTo().performClick()
        rule.runOnIdle { assertNull(deleted) }
        rule.onNodeWithText("保留记录").performClick()
        rule.runOnIdle { assertNull(deleted) }
        rule.onNodeWithContentDescription("删除图片本机记录：待分析照片.png").performScrollTo().performClick()
        rule.onNode(hasText("删除本机记录") and hasAnyAncestor(isDialog())).performClick()
        rule.runOnIdle { assertEquals(request, deleted) }
    }

    @Test fun originalImageReselectKeepsRequestIdAndRequiresCurrentCapabilityIdleAndCallback() {
        val uploads = mutableStateOf(SessionUploadState(listOf(row(UploadPhase.NEEDS_SOURCE))))
        val canAttach = mutableStateOf(true)
        val hasCallback = mutableStateOf(true)
        var resumed: String? = null
        rule.setContent { DshTheme { Column(Modifier.verticalScroll(rememberScrollState())) {
            SessionImagesPanel(SessionImageState(), uploads.value, canAttach.value, {}, {}, {}, {}, {}, {}, {},
                onReselect = if (hasCallback.value) { id -> resumed = id } else null)
        } } }
        val action = "重新选择原图片继续：待分析照片.png"
        rule.onNodeWithContentDescription(action).performScrollTo().assertIsEnabled().assertHeightIsAtLeast(48.dp).performClick()
        rule.runOnIdle {
            assertEquals(request, resumed)
            uploads.value = uploads.value.copy(busy = true)
        }
        rule.onNodeWithContentDescription(action).assertIsNotEnabled()
        rule.runOnIdle {
            uploads.value = SessionUploadState(listOf(row(UploadPhase.ERROR)))
            canAttach.value = false
        }
        rule.onNodeWithContentDescription(action).assertIsNotEnabled()
        rule.runOnIdle { canAttach.value = true; hasCallback.value = false }
        rule.onNodeWithContentDescription(action).assertIsNotEnabled()
        rule.runOnIdle { hasCallback.value = true }
        rule.onNodeWithContentDescription(action).assertIsEnabled()
        rule.runOnIdle {
            val original = row(UploadPhase.ERROR)
            uploads.value = SessionUploadState(listOf(original.copy(stored = StoredFileUpload(
                original.stored.intent, file, request, original.stored.createdAt, original.stored.updatedAt))))
        }
        rule.onNodeWithContentDescription(action).assertDoesNotExist()
        rule.runOnIdle { uploads.value = SessionUploadState(listOf(row(UploadPhase.READY))) }
        rule.onNodeWithContentDescription(action).assertDoesNotExist()
        rule.runOnIdle { uploads.value = SessionUploadState(listOf(row(UploadPhase.ERROR, image = false))) }
        rule.onNodeWithContentDescription(action).assertDoesNotExist()
    }

    @Test
    @SdkSuppress(minSdkVersion = 29)
    fun previewRequiresExplicitRequestRendersBitmapAndSecuresItsOwnWindow() {
        val bitmap = Bitmap.createBitmap(8, 8, Bitmap.Config.ARGB_8888)
        val state = mutableStateOf(SessionImageState(preview = ImagePreviewState(bitmap, "私密照片.png", true)))
        rule.setContent { DshTheme { MessageMediaPreview(state.value) { state.value = SessionImageState() } } }
        rule.onNode(isDialog()).assertDoesNotExist()
        rule.runOnIdle { state.value = state.value.copy(previewRequested = true) }
        rule.onNodeWithTag("media-preview-bitmap").assertIsDisplayed()
        rule.onNodeWithContentDescription("图片预览：私密照片.png").assertIsDisplayed()
        rule.onNodeWithText("历史消息图片 · 仅本次授权预览").assertExists()
        rule.runOnIdle {
            assertTrue(WindowInspector.getGlobalWindowViews().any {
                val flags = (it.layoutParams as? WindowManager.LayoutParams)?.flags ?: 0
                flags and WindowManager.LayoutParams.FLAG_SECURE != 0
            })
        }
        rule.onNodeWithText("关闭图片预览").assertHeightIsAtLeast(48.dp).performClick()
        rule.onNode(isDialog()).assertDoesNotExist()
        rule.runOnIdle { bitmap.recycle() }
    }

    @Test fun requestedPreviewKeepsLoadingErrorsAndRecycledBitmapSafeAndDismissible() {
        val bitmap = Bitmap.createBitmap(8, 8, Bitmap.Config.ARGB_8888).apply { recycle() }
        val state = mutableStateOf(SessionImageState(previewRequested = true, previewLoading = true))
        rule.setContent { DshTheme { MessageMediaPreview(state.value) { state.value = SessionImageState() } } }
        rule.onNodeWithText("正在校验授权并读取图片…").assertExists()
        rule.onNodeWithTag("media-preview-bitmap").assertDoesNotExist()
        rule.runOnIdle { state.value = SessionImageState(previewRequested = true, error = "access.denied") }
        rule.onNodeWithText("图片授权或会话内容已变化，请重新打开当前会话。").assertExists()
        rule.runOnIdle { state.value = SessionImageState(previewRequested = true, preview = ImagePreviewState(bitmap, "失效图片.png", false)) }
        rule.onNodeWithText("图片预览已失效，请关闭后重新打开。").assertExists()
        rule.onNodeWithTag("media-preview-bitmap").assertDoesNotExist()
        rule.onNodeWithText("关闭图片预览").performClick()
        rule.onNode(isDialog()).assertDoesNotExist()
    }
}
