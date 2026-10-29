package cn.edu.ustc.dsh.mobile

import android.content.pm.ActivityInfo
import android.content.res.Configuration
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.auth.HostBindingDetails
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class HostBindingScreenTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private val id = "11111111-1111-4111-8111-111111111111"
    private val code = "L".repeat(42) + "A"
    private fun details() = HostBindingDetails.parse(jsonObject("enrollment_id" to id.json(), "request_id" to id.json(), "organization_id" to id.json(), "organization_name" to "学校夹具".json(),
        "host_id" to id.json(), "host_alias" to "实验室电脑".json(), "installation_id" to id.json(), "installation_key_jkt" to "A".repeat(43).json(), "runtime_id" to id.json(),
        "profile_ref" to "research".json(), "protocol_version" to 1L.json(), "state" to "pending".json(), "expires_at" to Contract.timestamp(System.currentTimeMillis() + 300_000).json(),
        "host_confirmed" to JsonBoolean(false), "user_confirmed" to JsonBoolean(false), "user_confirmed_by_me" to JsonBoolean(false), "workspaces" to JsonArray(listOf(jsonObject("reference" to "project".json(), "workspace_id" to id.json())))), id, id)
    @Test fun confirmationRequiresAnExplicitFullFingerprintCheckOnASmallLargeTextScreen() {
        var confirmations = 0
        val public = details()
        lateinit var clipboard: androidx.compose.ui.platform.ClipboardManager
        rule.setContent {
            val density = LocalDensity.current
            clipboard = LocalClipboardManager.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, 2f)) {
                DshTheme(darkTheme = true) { Box(Modifier.width(320.dp)) { HostBindingScreen(HostBindingState(HostBindingPhase.REVIEW, id, public), "fixture-account", { _, _ -> }, {}, { confirmations++ }, {}, {}, {}, {}) } }
            }
        }
        rule.onNodeWithText("确认绑定这台电脑").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText(public.keyThumbprint.chunked(8).joinToString(" ")).performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("复制完整安装密钥指纹").performScrollTo().assertHeightIsAtLeast(48.dp).performClick()
        rule.runOnIdle { assertEquals(public.keyThumbprint, clipboard.getText()?.text); assertEquals(0, confirmations) }
        rule.onNodeWithText("确认绑定这台电脑").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("我已在电脑上核对以上信息和完整指纹").performScrollTo().performClick()
        rule.onNodeWithText("确认绑定这台电脑").performScrollTo().assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(1, confirmations) }
    }
    @Test fun capabilityCodeIsNeverRestoredFromSavedInstanceState() {
        val restore = StateRestorationTester(rule)
        restore.setContent { DshTheme { HostBindingScreen(HostBindingState(id = id), "fixture-account", { _, _ -> }, {}, {}, {}, {}, {}, {}) } }
        rule.onNodeWithText("核对电脑信息").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("电脑显示的绑定码").performScrollTo().performTextInput(code)
        rule.onNodeWithText("核对电脑信息").performScrollTo().assertIsEnabled()
        restore.emulateSavedInstanceStateRestore()
        rule.onNodeWithText("核对电脑信息").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("绑定申请编号").performScrollTo().assertTextContains(id)
    }
    @Test fun unknownConfirmationExposesAStatusReadAndNeverAnotherConfirmationButton() {
        var queries = 0
        rule.setContent { DshTheme { HostBindingScreen(HostBindingState(HostBindingPhase.UNKNOWN, id, details(), "network.unavailable"), "fixture-account", { _, _ -> }, {}, {}, { queries++ }, {}, {}, {}) } }
        rule.onNodeWithText("绑定结果待核对").assertIsDisplayed()
        rule.onNodeWithText("确认绑定这台电脑").assertDoesNotExist()
        rule.onNodeWithText("查询绑定状态").performScrollTo().performClick()
        rule.runOnIdle { assertEquals(1, queries) }
    }
    @Test fun unknownWithoutReviewFactsRetainsTheOriginalPublicIdentifierWithoutASecretForm() {
        var queries = 0
        rule.setContent { DshTheme { HostBindingScreen(HostBindingState(HostBindingPhase.UNKNOWN, id), "fixture-account", { _, _ -> }, {}, {}, { queries++ }, {}, {}, {}) } }
        rule.onNodeWithText(id).performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("绑定申请编号").assertDoesNotExist()
        rule.onNodeWithText("电脑显示的绑定码").assertDoesNotExist()
        rule.onNodeWithText("确认绑定这台电脑").assertDoesNotExist()
        rule.onNodeWithText("查询绑定状态").performScrollTo().assertHeightIsAtLeast(48.dp).performClick()
        rule.runOnIdle { assertEquals(1, queries) }
    }
    @Test fun alreadyConfirmedRequestsCanBeQueriedWithOnlyTheirPublicIdentifier() {
        var queried: String? = null; var previews = 0
        rule.setContent { DshTheme { HostBindingScreen(HostBindingState(id = id), "fixture-account", { _, _ -> previews++ }, { queried = it }, {}, {}, {}, {}, {}) } }
        rule.onNodeWithText("核对电脑信息").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("仅查询已确认申请").performScrollTo().assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(id, queried); assertEquals(0, previews) }
    }
    @Test fun landscapeTabletLayoutWithLargeTextKeepsRecoveryAndBackActionsReachable() {
        rule.runOnUiThread { rule.activity.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE }
        rule.waitUntil(10_000) { rule.activity.resources.configuration.orientation == Configuration.ORIENTATION_LANDSCAPE }
        var queries = 0; var backs = 0
        val public = details()
        rule.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density * 0.7f, 1.8f)) {
                DshTheme(darkTheme = false) { HostBindingScreen(HostBindingState(HostBindingPhase.UNKNOWN, id, public), "fixture-account", { _, _ -> }, {}, {}, { queries++ }, {}, { backs++ }, {}) }
            }
        }
        rule.onNodeWithText("查询绑定状态").performScrollTo().assertIsEnabled().performClick()
        rule.onNodeWithText("返回电脑列表").performScrollTo().performClick()
        rule.runOnIdle { assertEquals(1, queries); assertEquals(1, backs) }
        // Export only synthetic public UI state; the live activity remains secure.
        val bitmap = rule.onRoot().captureToImage().asAndroidBitmap()
        val directory = File(InstrumentationRegistry.getInstrumentation().targetContext.filesDir, "ui-fixtures").apply { mkdirs() }
        File(directory, "binding-landscape.png").outputStream().use { check(bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)) }
    }
}
