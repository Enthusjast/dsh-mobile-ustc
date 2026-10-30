package cn.edu.ustc.dsh.mobile

import android.view.View
import android.view.WindowManager
import androidx.compose.ui.platform.ViewRootForTest
import androidx.compose.ui.test.isRoot
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.isPopup
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.junit4.ComposeContentTestRule
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import java.io.File

/** Public synthetic ComponentActivity state only; never captures the secure production activity. */
internal fun captureUiFixture(rule: ComposeContentTestRule, name: String, dialog: Boolean = false, darkTheme: Boolean? = null) {
    val instrumentation = InstrumentationRegistry.getInstrumentation()
    val config = instrumentation.targetContext.resources.configuration
    val dark = darkTheme ?: ((config.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) == android.content.res.Configuration.UI_MODE_NIGHT_YES)
    val theme = if (dark) "dark" else "light"
    val bitmap = if (dialog) {
        val roots = rule.onAllNodes(isDialog() or isPopup()).fetchSemanticsNodes().ifEmpty {
            rule.onAllNodes(isRoot()).fetchSemanticsNodes()
        }
        var focused: View? = null
        rule.waitUntil(10_000) {
            focused = rule.runOnIdle {
                roots.firstNotNullOfOrNull { node ->
                    (node.root as? ViewRootForTest)?.view?.takeIf { it.hasWindowFocus() }
                }
            }
            focused != null
        }
        val publicFocusedWindow = rule.runOnIdle {
            val parameters = focused?.rootView?.layoutParams as? WindowManager.LayoutParams
            focused?.hasWindowFocus() == true && parameters != null &&
                parameters.flags and WindowManager.LayoutParams.FLAG_SECURE == 0
        }
        check(publicFocusedWindow) { "Native fixture capture requires a focused, non-secure Compose window" }
        checkNotNull(instrumentation.uiAutomation.takeScreenshot())
    } else rule.onRoot().captureToImage().asAndroidBitmap()
    val directory = File(instrumentation.targetContext.filesDir, "ui-navigation-fixtures").apply { check(isDirectory || mkdirs()) }
    File(directory, "$name.png").outputStream().use { check(bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)) }
    File(directory, "$name.json").writeText(JSONObject().put("scene", name).put("synthetic", true)
        .put("density", rule.density.density).put("fontScale", rule.density.fontScale)
        .put("widthPx", bitmap.width).put("heightPx", bitmap.height)
        .put("api", android.os.Build.VERSION.SDK_INT).put("build", BuildConfig.BUILD_TYPE).put("version", BuildConfig.VERSION_NAME).put("theme", theme).toString(2))
}
