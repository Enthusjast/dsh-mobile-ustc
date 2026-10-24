package cn.edu.ustc.dsh.mobile

import android.content.Intent
import android.net.Uri
import android.content.pm.ActivityInfo
import android.content.res.Configuration
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeFalse
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class HomeScreenTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()

    @Test fun unconfiguredSmallScreenKeepsLargeTextAndDisabledLoginAccessible() {
        rule.setContent {
            val density = LocalDensity.current.density
            CompositionLocalProvider(LocalDensity provides Density(density, 2f)) {
                DshTheme(darkTheme = false) {
                    Box(Modifier.width(375.dp)) { HomeScreen(HomeState(HomePhase.UNCONFIGURED), {}, {}, {}, {}, {}) }
                }
            }
        }
        rule.onNodeWithText("等待学校配置").performScrollTo().assertIsDisplayed().assertIsNotEnabled()
        rule.onNodeWithText("请联系管理员获取配置了学校登录的安装包。").assertExists()
        save("unconfigured-large-text")
    }

    @Test fun darkLoginShowsTrustedIssuerAndOneExplicitLoginAction() {
        var requests = 0
        rule.setContent {
            DshTheme(darkTheme = true) {
                HomeScreen(HomeState(HomePhase.SIGNED_OUT, "https://id.example.edu"), { requests++ }, {}, {}, {}, {})
            }
        }
        rule.onNodeWithText("https://id.example.edu").assertIsDisplayed()
        rule.onNodeWithText("使用学校账号登录").assertHasClickAction().performClick()
        rule.runOnIdle { assertEquals(1, requests) }
        save("login-dark")
    }

    @Test fun landscapeRegistrationKeepsNameAndConfirmationReachable() {
        rule.runOnUiThread { rule.activity.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE }
        rule.waitUntil(10_000) { rule.activity.resources.configuration.orientation == Configuration.ORIENTATION_LANDSCAPE }
        var submitted: String? = null
        rule.setContent {
            DshTheme(darkTheme = false) {
                HomeScreen(HomeState(HomePhase.ENROLL, "https://id.example.edu", subject = "verified-school-user"), {}, { submitted = it }, {}, {}, {})
            }
        }
        rule.onNodeWithText("设备名称").performScrollTo().performTextClearance()
        rule.onNodeWithText("设备名称").performTextInput("校园备用手机")
        rule.onNodeWithText("确认并登记设备").performScrollTo().assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals("校园备用手机", submitted) }
        save("registration-landscape")
    }

    private fun save(name: String) {
        // Only public synthetic state in this test host, never the secure live activity.
        val bitmap = rule.onRoot().captureToImage().asAndroidBitmap()
        val directory = File(InstrumentationRegistry.getInstrumentation().targetContext.filesDir, "ui-fixtures").apply { mkdirs() }
        val temporary = File(directory, "$name.part")
        temporary.outputStream().use { check(bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)) }
        check(temporary.renameTo(File(directory, "$name.png")))
    }
}

@RunWith(AndroidJUnit4::class)
class MainStartupTest {
    @get:Rule val rule = createAndroidComposeRule<MainActivity>()
    @Test fun actualHiltApplicationKeepsLoginDisabledWithoutSchoolConfigurationAndIgnoresUnsolicitedCallback() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assumeFalse(context.assets.list("")!!.contains("deployment.json"))
        rule.waitUntil(10_000) { rule.onAllNodesWithText("等待学校配置").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithText("等待学校配置").assertIsNotEnabled()
        rule.activity.startActivity(Intent(context, LoginRedirectActivity::class.java).setData(Uri.parse("cn.edu.ustc.dsh.mobile:/oauth2redirect?code=unsolicited&state=wrong")))
        rule.waitForIdle()
        rule.onNodeWithText("等待学校配置").assertIsNotEnabled()
    }
}
