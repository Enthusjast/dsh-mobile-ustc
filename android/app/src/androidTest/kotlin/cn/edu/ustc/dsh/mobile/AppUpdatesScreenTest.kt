package cn.edu.ustc.dsh.mobile

import android.content.pm.ActivityInfo
import android.content.res.Configuration
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class AppUpdatesScreenTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private fun release() = AppRelease.parse(jsonObject("release_id" to "11111111-1111-4111-8111-111111111111".json(), "version_code" to 2L.json(),
        "version_name" to "0.2.0".json(), "package_name" to "cn.edu.ustc.dsh.mobile".json(), "sha256" to "a".repeat(64).json(), "size_bytes" to 12_582_912L.json(),
        "signing_cert_sha256" to "b".repeat(64).json(), "download_url" to "https://updates.example.invalid/app.apk".json(), "minimum_protocol_version" to 1L.json(),
        "maximum_protocol_version" to 1L.json(), "minimum_android_api" to 26L.json(), "rollout_basis_points" to 10000L.json(), "release_notes" to "修复会话恢复问题。\n改进文件下载与通知。".json()))
    @Test fun permissionAndDownloadAreSeparateExplicitActions() {
        var state by mutableStateOf(AppUpdateUiState(phase = AppUpdatePhase.AVAILABLE, installedVersion = 1, release = release()))
        var permissions = 0; var downloads = 0; var installs = 0
        rule.setContent { DshTheme { AppUpdatesScreen(state, {}, { downloads++ }, { installs++ }, { permissions++ }, {}, {}, {}) } }
        rule.onNodeWithText("下载并校验").assertDoesNotExist()
        rule.onNodeWithText("允许本应用安装").performScrollTo().performClick()
        rule.runOnIdle { assertEquals(1, permissions); assertEquals(0, downloads); assertEquals(0, installs); state = state.copy(canInstall = true) }
        rule.onNodeWithText("下载并校验").performScrollTo().assertHeightIsAtLeast(48.dp).performClick()
        rule.runOnIdle { assertEquals(1, downloads); assertEquals(0, installs) }
        rule.runOnIdle { state = state.copy(phase = AppUpdatePhase.PREPARED) }
        rule.onNodeWithText("安装包已校验").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("已核对当前安装版本").assertDoesNotExist()
        rule.onNodeWithText("下载并校验").assertDoesNotExist()
        rule.onNodeWithText("打开系统安装确认").performScrollTo().assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(1, installs); assertEquals(1, downloads) }
    }
    @Test fun unknownOutcomeOnlyOffersReconciliationAndCleanupNeedsExplicitConfirmation() {
        var reads = 0; var installs = 0; var cleanups = 0
        rule.setContent { DshTheme { AppUpdatesScreen(AppUpdateUiState(viewId = "first", phase = AppUpdatePhase.UNKNOWN, installedVersion = 1, canCleanup = true, cleanupToken = "first"),
            { reads++ }, {}, { installs++ }, {}, { cleanups++ }, {}, {}) } }
        rule.onNodeWithText("打开系统安装确认").assertDoesNotExist(); rule.onNodeWithText("继续系统安装").assertDoesNotExist()
        rule.onNodeWithText("核对安装结果").performScrollTo().performClick()
        rule.onNodeWithText("放弃待处理更新").performScrollTo().performClick()
        rule.runOnIdle { assertEquals(1, reads); assertEquals(0, installs); assertEquals(0, cleanups) }
        rule.onNodeWithText("保留更新").performClick(); rule.runOnIdle { assertEquals(0, cleanups) }
        rule.onNodeWithText("放弃待处理更新").performScrollTo().performClick()
        rule.onNodeWithText("确认放弃").performClick(); rule.runOnIdle { assertEquals(1, cleanups) }
    }
    @Test fun changingTheViewDiscardsAnOldCleanupDialogAndSmallDarkLargeTextRemainsUsable() {
        var state by mutableStateOf(AppUpdateUiState(viewId = "old", phase = AppUpdatePhase.WAITING_USER, installedVersion = 1, release = release(), canInstall = true, canCleanup = true, cleanupToken = "old"))
        var installs = 0; var cleanups = 0
        rule.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, 2f)) {
                DshTheme(darkTheme = true) { Box(Modifier.width(320.dp)) { AppUpdatesScreen(state, {}, {}, { installs++ }, {}, { cleanups++ }, {}, {}) } }
            }
        }
        rule.onNodeWithText("放弃待处理更新").performScrollTo().performClick()
        rule.runOnIdle { state = state.copy(cleanupToken = "replacement") }
        rule.onNodeWithText("确认放弃").assertDoesNotExist()
        rule.onNodeWithText("放弃待处理更新").performScrollTo().performClick()
        rule.runOnIdle { state = state.copy(viewId = "new") }
        rule.onNodeWithText("确认放弃").assertDoesNotExist()
        rule.onNodeWithText("继续系统安装").performScrollTo().assertIsDisplayed().assertHeightIsAtLeast(48.dp).performClick()
        rule.runOnIdle { assertEquals(1, installs); assertEquals(0, cleanups) }
        val bitmap = rule.onRoot().captureToImage().asAndroidBitmap()
        val directory = File(InstrumentationRegistry.getInstrumentation().targetContext.filesDir, "ui-fixtures").apply { mkdirs() }
        File(directory, "app-updates-dark-small.png").outputStream().use { assertTrue(bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)) }
    }
    @Test fun landscapeLargeTextKeepsReadAndBackReachableWithoutOfferingAnotherInstall() {
        rule.runOnUiThread { rule.activity.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE }
        rule.waitUntil(10_000) { rule.activity.resources.configuration.orientation == Configuration.ORIENTATION_LANDSCAPE }
        var reads = 0; var backs = 0
        rule.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density * .7f, 1.8f)) {
                DshTheme(darkTheme = false) { AppUpdatesScreen(AppUpdateUiState(phase = AppUpdatePhase.UNKNOWN, installedVersion = 1), { reads++ }, {}, {}, {}, {}, {}, { backs++ }) }
            }
        }
        rule.onNodeWithText("核对安装结果").performScrollTo().assertIsDisplayed().performClick()
        rule.onNodeWithText("返回").performScrollTo().assertIsDisplayed().performClick()
        rule.runOnIdle { assertEquals(1, reads); assertEquals(1, backs) }
        rule.onNodeWithText("打开系统安装确认").assertDoesNotExist()
    }
}
