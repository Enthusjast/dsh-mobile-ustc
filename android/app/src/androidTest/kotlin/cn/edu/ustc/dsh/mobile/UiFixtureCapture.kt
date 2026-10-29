package cn.edu.ustc.dsh.mobile

import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.junit4.ComposeContentTestRule
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import java.io.File

/** Public synthetic ComponentActivity state only; never captures the secure production activity. */
internal fun captureUiFixture(rule: ComposeContentTestRule, name: String, dialog: Boolean = false) {
    val instrumentation = InstrumentationRegistry.getInstrumentation()
    val config = instrumentation.targetContext.resources.configuration
    val theme = if ((config.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) == android.content.res.Configuration.UI_MODE_NIGHT_YES) "dark" else "light"
    val bitmap = if (dialog) checkNotNull(instrumentation.uiAutomation.takeScreenshot()) else rule.onRoot().captureToImage().asAndroidBitmap()
    val directory = File(instrumentation.targetContext.filesDir, "ui-navigation-fixtures").apply { check(isDirectory || mkdirs()) }
    File(directory, "$name.png").outputStream().use { check(bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)) }
    File(directory, "$name.json").writeText(JSONObject().put("scene", name).put("synthetic", true)
        .put("density", rule.density.density).put("fontScale", rule.density.fontScale)
        .put("widthPx", bitmap.width).put("heightPx", bitmap.height)
        .put("api", android.os.Build.VERSION.SDK_INT).put("build", BuildConfig.BUILD_TYPE).put("version", BuildConfig.VERSION_NAME).put("theme", theme).toString(2))
}
