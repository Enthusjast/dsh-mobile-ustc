package cn.edu.ustc.dsh.mobile

import android.content.pm.ActivityInfo
import android.content.res.Configuration
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.network.RuntimeDirectoryEntry
import cn.edu.ustc.dsh.network.SessionDirectoryEntry
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.json.JSONObject
import java.io.File

/** Synthetic presentation fixtures only; no real credentials, readers or authentication bypass. */
@RunWith(AndroidJUnit4::class)
class DshAppShellTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private var fixtureDensity = Density(1f)
    private val runtimeA = "11111111-1111-4111-8111-111111111111"
    // Deliberately share the alias AND first eight characters: short runtime IDs are ambiguous.
    private val runtimeB = "11111111-1111-4111-8111-222222222222"
    private val sessionA = "33333333-3333-4333-8333-333333333333"
    private val sessionB = "44444444-4444-4444-8444-444444444444"
    private val workspace = "55555555-5555-4555-8555-555555555555"

    private fun runtime(id: String, actions: List<String> = listOf("session.list", "session.read"), alias: String = "同名电脑"): RuntimeRow {
        val grant = RuntimeDirectoryEntry.parse(jsonObject(
            "id" to id.json(), "host_id" to workspace.json(), "organization_id" to workspace.json(),
            "protocol_version" to 1L.json(), "dsh_version" to "0.2.1".json(),
            "access" to jsonObject("role" to "owner".json(), "grant_version" to 1L.json(),
                "scope" to RelayScope(actions, listOf(workspace), listOf(sessionA, sessionB)).json()),
        ))
        return RuntimeRow(id, workspace, "0.2.1", alias, grant)
    }

    private fun session(id: String) = SessionDirectoryEntry.parse(jsonObject(
        "session_id" to id.json(), "workspace_id" to workspace.json(), "state" to "available".json(),
        "last_persisted_seq" to 0L.json(), "updated_at" to "2026-10-25T00:00:00Z".json(),
    ))

    private fun state(rows: List<RuntimeRow> = listOf(runtime(runtimeA))) = HomeState(
        phase = HomePhase.READY, issuer = "https://id.example.edu", subject = "synthetic-student",
        deviceId = runtimeB, deviceName = "合成测试手机", runtimes = rows,
        selectedRuntimeId = runtimeA, sessions = listOf(session(sessionA)),
    )

    private fun navigation(destination: HomeDestination = HomeDestination.SESSIONS) = HomeNavigation().apply {
        this.destination = destination
        selectRuntime(runtimeA)
    }

    @Composable
    private fun Shell(
        state: HomeState,
        navigation: HomeNavigation,
        onRuntime: (String) -> Unit = {},
        onSession: (String) -> Unit = {},
        onCreate: (String) -> Unit = {},
        onBinding: () -> Unit = {},
        onNotifications: () -> Unit = {},
        onAppUpdates: () -> Unit = {},
        onExit: () -> Unit = {},
    ) {
        val density = LocalDensity.current
        SideEffect { fixtureDensity = density }
        DshAppShell(state, navigation, { navigation.destination = it }, onRuntime, onSession,
            {}, {}, onCreate, onBinding, onNotifications, onAppUpdates, onExit,
            { navigation.destination = HomeDestination.COMPUTERS })
    }

    @Test fun listOnlyDirectoryHasNoBodyReadAction() {
        var reads = 0
        rule.setContent {
            DshTheme { Shell(state(listOf(runtime(runtimeA, listOf("session.list")))), navigation(), onSession = { reads++ }) }
        }
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionA"))
        rule.onNodeWithTag("session-$sessionA").assertHasNoClickAction()
        rule.onNodeWithTag("session-$sessionA").performTouchInput { click() }
        rule.onNodeWithText("当前授权仅可查看目录，不能读取正文。").assertIsDisplayed()
        rule.runOnIdle { assertEquals(0, reads) }
    }

    @Test fun readableSessionHasExactlyOneWholeRowAction() {
        val opened = mutableListOf<String>()
        rule.setContent { DshTheme(darkTheme = false) { Shell(state(), navigation(), onSession = { opened += it }) } }
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionA"))
        rule.onAllNodes(hasTestTag("session-$sessionA") and hasClickAction()).assertCountEquals(1)
        saveFixture("session-directory-light", dark = false)
        rule.onNodeWithTag("session-$sessionA").assertHasClickAction().performClick()
        rule.onNodeWithText("读取会话").assertDoesNotExist()
        rule.runOnIdle { assertEquals(listOf(sessionA), opened) }
    }

    @Test fun runtimeFilterDistinguishesSameAliasAndPrefixAndChangesOnlySelectedDirectory() {
        val nav = navigation()
        val rows = listOf(runtime(runtimeA), runtime(runtimeB), runtime(workspace, listOf("session.read")))
        var current by mutableStateOf(state(rows))
        val selected = mutableListOf<String>()
        rule.setContent {
            DshTheme(darkTheme = true) { Shell(current, nav, onRuntime = { id ->
                selected += id
                nav.selectRuntime(id)
                current = current.copy(selectedRuntimeId = id, sessions = listOf(session(sessionB)))
            }) }
        }
        rule.onNodeWithTag("runtime-filter").performClick()
        rule.onNodeWithTag("runtime-filter-$runtimeA").assertExists()
        rule.onNodeWithTag("runtime-filter-$runtimeB").assertExists()
        rule.onNodeWithTag("runtime-filter-$workspace").assertDoesNotExist()
        rule.onNodeWithTag("runtime-filter-$runtimeB").performScrollTo().performClick()
        rule.onNodeWithTag("runtime-filter").assertTextContains("运行环境 ${runtimeB.take(8)}…${runtimeB.takeLast(4)}", substring = true)
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionB"))
        rule.onNodeWithTag("session-$sessionB").assertExists()
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
        rule.runOnIdle { assertEquals(listOf(runtimeB), selected) }
        saveFixture("session-directory-filtered-dark", dark = true)
    }

    @Test fun collidingRuntimeAbbreviationsShowTheFullSelectedIdentifier() {
        val collision = "11111111-2222-4222-8222-222222221111"
        val nav = navigation()
        rule.setContent { DshTheme { Shell(state(listOf(runtime(runtimeA), runtime(collision))), nav) } }
        rule.onNodeWithTag("runtime-filter").assertTextContains(runtimeA, substring = true)
        rule.onNodeWithTag("runtime-filter").performClick()
        rule.onNodeWithTag("runtime-filter-$runtimeA").assertExists()
        rule.onNodeWithTag("runtime-filter-$collision").assertExists()
    }

    @Test fun staleLoadingDeniedAndRevokedScopesNeverShowRetainedSessionRows() {
        val nav = navigation()
        var current by mutableStateOf(state())
        rule.setContent { DshTheme { Shell(current, nav) } }
        rule.runOnIdle { nav.selectRuntime(runtimeB) }
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
        rule.onNodeWithText("所选电脑的目录授权已变化，请重新选择电脑或刷新核对。").assertExists()
        rule.runOnIdle { nav.selectRuntime(runtimeA); current = current.copy(loadingSessions = true) }
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
        rule.onNodeWithText("正在读取会话目录").assertExists()
        rule.runOnIdle { current = current.copy(loadingSessions = false, sessionError = "access.denied") }
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
        rule.onNodeWithText("当前授权无法读取会话目录，请核对授权后刷新。").assertExists()
        rule.onNodeWithText("当前授权范围内没有会话。").assertDoesNotExist()
        rule.runOnIdle { current = current.copy(sessionError = null, runtimes = listOf(runtime(runtimeA, listOf("session.read")))) }
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
    }

    @Test fun settingsRequireLogoutConfirmationAndCancelDoesNotExit() {
        var exits = 0
        val nav = navigation(HomeDestination.SETTINGS)
        rule.setContent { DshTheme(darkTheme = false) { Shell(state(), nav, onExit = { exits++ }) } }
        saveFixture("settings-light", dark = false)
        clickSettingsItem("退出本机登录")
        rule.onNodeWithText("退出这部手机上的账号？").assertIsDisplayed()
        rule.runOnIdle { assertEquals(0, exits) }
        rule.onNodeWithText("取消").performClick()
        rule.runOnIdle { assertEquals(0, exits) }
        clickSettingsItem("退出本机登录")
        rule.onNode(hasText("退出本机登录") and hasAnyAncestor(isDialog())).performClick()
        rule.runOnIdle { assertEquals(1, exits) }
    }

    @Test fun narrowLargeTextComputerActionsAndFullIdentifiersRemainReachable() {
        val nav = navigation(HomeDestination.COMPUTERS)
        val longAlias = "合成长名称".repeat(32)
        var creates = 0
        var bindings = 0
        rule.setContent {
            val density = LocalDensity.current.density
            CompositionLocalProvider(LocalDensity provides Density(density, 2f)) {
                DshTheme(darkTheme = false) {
                    Box(Modifier.width(320.dp).height(480.dp)) {
                        Shell(state(listOf(runtime(runtimeA, listOf("session.list", "session.read", "session.create", "command.status"), longAlias))), nav,
                            onCreate = { creates++ }, onBinding = { bindings++ })
                    }
                }
            }
        }
        rule.onNodeWithText("绑定电脑").performScrollTo().assertIsDisplayed().performClick()
        rule.onNodeWithText("新建会话").performScrollTo().assertIsDisplayed().performClick()
        saveFixture("computers-narrow-large-text", dark = false)
        rule.onNodeWithText("电脑详情").performScrollTo().assertIsDisplayed().performClick()
        rule.onNode(hasText(longAlias) and hasAnyAncestor(isDialog())).performScrollTo().assertIsDisplayed()
        rule.onNodeWithText(runtimeA).performScrollTo().assertIsDisplayed()
        saveFixture("computer-detail-narrow-large-text", dark = false, dialog = true)
        rule.onNodeWithText("关闭").assertIsDisplayed().performClick()
        rule.runOnIdle { assertEquals(1, creates); assertEquals(1, bindings) }
    }

    @Test fun shortLandscapeLargeTextSettingsActionsRemainReachable() {
        rule.runOnUiThread { rule.activity.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE }
        rule.waitUntil(10_000) { rule.activity.resources.configuration.orientation == Configuration.ORIENTATION_LANDSCAPE }
        val nav = navigation(HomeDestination.SETTINGS)
        var notifications = 0
        var updates = 0
        rule.setContent {
            val density = LocalDensity.current.density
            CompositionLocalProvider(LocalDensity provides Density(density, 2f)) {
                DshTheme(darkTheme = true) {
                    Box(Modifier.width(640.dp).height(320.dp)) {
                        Shell(state(), nav, onNotifications = { notifications++ }, onAppUpdates = { updates++ })
                    }
                }
            }
        }
        clickSettingsItem("通知与待核对提醒")
        saveFixture("settings-landscape-large-text-dark", dark = true)
        clickSettingsItem("应用更新")
        clickSettingsItem("退出本机登录")
        rule.onNodeWithText("取消").assertIsDisplayed().performClick()
        rule.runOnIdle { assertEquals(1, notifications); assertEquals(1, updates) }
    }
    private fun clickSettingsItem(label: String) {
        rule.onNodeWithTag("settings-list").performScrollToNode(hasText(label))
        rule.onNodeWithText(label).assertIsDisplayed().performClick()
    }


    /** Captures only this synthetic ComponentActivity, never the FLAG_SECURE production activity. */
    private fun saveFixture(scene: String, dark: Boolean, dialog: Boolean = false) {
        val root = if (dialog) rule.onNode(isDialog()) else rule.onRoot()
        val rootBounds = root.fetchSemanticsNode().boundsInRoot
        val useDisplayCapture = dialog && android.os.Build.VERSION.SDK_INT < 28
        val bitmap = if (useDisplayCapture) {
            checkNotNull(InstrumentationRegistry.getInstrumentation().uiAutomation.takeScreenshot()) {
                "Cannot capture the synthetic dialog host"
            }
        } else {
            root.captureToImage().asAndroidBitmap()
        }
        val density = fixtureDensity
        val directory = File(
            InstrumentationRegistry.getInstrumentation().targetContext.filesDir,
            "ui-navigation-fixtures",
        ).apply { check(isDirectory || mkdirs()) }
        val image = File(directory, "$scene.png.part")
        image.outputStream().use { check(bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)) }
        check(image.renameTo(File(directory, "$scene.png")))
        val metadata = JSONObject()
            .put("scene", scene)
            .put("density", density.density)
            .put("fontScale", density.fontScale)
            .put("dark", dark)
            .put("captureMethod", if (useDisplayCapture) "uiAutomation-display" else "compose-root")
            .put("rootSize", JSONObject()
                .put("widthPx", rootBounds.width)
                .put("heightPx", rootBounds.height)
                .put("widthDp", rootBounds.width / density.density)
                .put("heightDp", rootBounds.height / density.density))
            .put("imageSize", JSONObject()
                .put("widthPx", bitmap.width)
                .put("heightPx", bitmap.height))
            .put("build", JSONObject()
                .put("applicationId", BuildConfig.APPLICATION_ID)
                .put("versionName", BuildConfig.VERSION_NAME)
                .put("versionCode", BuildConfig.VERSION_CODE)
                .put("buildType", BuildConfig.BUILD_TYPE))
        val metadataFile = File(directory, "$scene.json.part")
        metadataFile.writeText(metadata.toString(2))
        check(metadataFile.renameTo(File(directory, "$scene.json")))
    }
}
