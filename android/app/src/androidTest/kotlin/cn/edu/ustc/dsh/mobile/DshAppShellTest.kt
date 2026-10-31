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
import cn.edu.ustc.dsh.network.SessionReadPhase
import cn.edu.ustc.dsh.network.SessionReadState
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.command.CommandOwner
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.json.JSONObject
import java.io.File
import android.graphics.BitmapFactory
import android.os.ParcelFileDescriptor
import android.view.WindowManager

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

    private fun runtime(
        id: String,
        actions: List<String> = listOf("session.list", "session.read"),
        alias: String = "同名电脑",
        workspaces: List<String> = listOf(workspace),
        sessions: List<String> = listOf(sessionA, sessionB),
    ): RuntimeRow {
        val grant = RuntimeDirectoryEntry.parse(jsonObject(
            "id" to id.json(), "host_id" to workspace.json(), "organization_id" to workspace.json(),
            "protocol_version" to 1L.json(), "dsh_version" to "0.2.1".json(),
            "access" to jsonObject("role" to "owner".json(), "grant_version" to 1L.json(),
                "scope" to RelayScope(actions, workspaces, sessions).json()),
        ))
        return RuntimeRow(id, workspace, "0.2.1", alias, grant)
    }

    private fun session(id: String, workspaceId: String? = workspace, state: String = "available") = SessionDirectoryEntry.parse(jsonObject(
        "session_id" to id.json(), "workspace_id" to (workspaceId?.json() ?: JsonNull), "state" to state.json(),
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
        onAppearance: () -> Unit = {},
        onAppUpdates: () -> Unit = {},
        onExit: () -> Unit = {},
        onRefreshSessions: () -> Unit = {},
    ) {
        val density = LocalDensity.current
        SideEffect { fixtureDensity = density }
        DshAppShell(state, navigation, { navigation.destination = it }, onRuntime, onSession,
            {}, onRefreshSessions, onCreate, onBinding, onNotifications, onAppearance, onAppUpdates, onExit,
            { navigation.destination = HomeDestination.COMPUTERS })
    }

    @Test fun semanticNamesRemainGrantBoundAndKeepStableIdsAndStateFilters() {
        fun named(id: String, state: String) = SessionDirectoryEntry.parse(jsonObject(
            "session_id" to id.json(), "workspace_id" to workspace.json(), "state" to state.json(),
            "last_persisted_seq" to 7L.json(), "updated_at" to "2026-10-30T12:00:00Z".json(),
            "metadata" to jsonObject("v" to 1L.json(), "title" to "同名原生会话".json(), "workspace_title" to "原生工作区".json(),
                "title_source" to "cached".json(), "title_as_of_seq" to 4L.json())), namesProjection = true)
        val nav = navigation()
        var current by mutableStateOf(state(listOf(runtime(runtimeA, listOf("session.list", "session.read", "session.metadata.read"))))
            .copy(sessions = listOf(named(sessionA, "available"), named(sessionB, "archived"))))
        rule.setContent { DshTheme { Shell(current, nav) } }
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionA"))
        rule.onNodeWithTag("session-$sessionA").assertTextContains("同名原生会话", substring = true)
        rule.onNodeWithTag("session-$sessionA").assertTextContains(sessionA.take(8), substring = true)
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("directory-open-search"))
        rule.onNodeWithTag("directory-open-search").performClick()
        rule.onNodeWithTag("directory-search").performTextInput("原生工作区")
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionB"))
        rule.onNodeWithTag("session-$sessionB").assertExists()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("directory-status-ACTIVE"))
        rule.onNodeWithTag("directory-status-ACTIVE").performClick()
        rule.onNodeWithTag("session-$sessionB").assertDoesNotExist()
        rule.runOnIdle { current = current.copy(runtimes = listOf(runtime(runtimeA))) }
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
        rule.onNodeWithTag("directory-search").performTextClearance()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionA"))
        rule.onNodeWithTag("session-$sessionA").assertExists().assert(!hasText("同名原生会话", substring = true))
        rule.onNodeWithTag("session-$sessionB").assertDoesNotExist()
        rule.runOnIdle { assertEquals(DirectorySessionFilter.ACTIVE, nav.directorySessionFilter) }
    }

    @Test fun listOnlyDirectoryHasNoBodyReadAction() {
        var reads = 0
        rule.setContent {
            DshTheme { Shell(state(listOf(runtime(runtimeA, listOf("session.list")))), navigation(), onSession = { reads++ }) }
        }
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionA"))
        rule.onNodeWithTag("session-$sessionA").assertHasNoClickAction()
        rule.onNodeWithTag("session-$sessionA").assertIsNotEnabled()
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

    @Test fun refreshRetainsDisabledRowsButStaleDeniedAndRevokedScopesNeverDo() {
        val nav = navigation()
        var current by mutableStateOf(state())
        rule.setContent { DshTheme { Shell(current, nav) } }
        rule.runOnIdle { nav.selectRuntime(runtimeB) }
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
        rule.onNodeWithText("所选电脑的目录授权已变化，请重新选择电脑或刷新核对。").assertExists()
        rule.runOnIdle { nav.selectRuntime(runtimeA); current = current.copy(loadingSessions = true) }
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionA"))
        rule.onNodeWithTag("session-$sessionA").assertIsNotEnabled().assertHasNoClickAction()
        rule.onNodeWithText("正在读取会话目录").assertExists()
        rule.runOnIdle { current = current.copy(loadingSessions = false, sessionError = "access.denied") }
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
        rule.onNodeWithText("当前授权无法读取会话目录，请核对授权后刷新。").assertExists()
        rule.onNodeWithText("当前授权范围内没有会话。").assertDoesNotExist()
        rule.runOnIdle { current = current.copy(sessionError = null, runtimes = listOf(runtime(runtimeA, listOf("session.read")))) }
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
    }

    @Test fun localSearchUsesOnlyAcquiredRowsInsideTheCurrentResourceGrant() {
        val nav = navigation()
        val restricted = runtime(runtimeA, workspaces = emptyList(), sessions = listOf(sessionA))
        // Keep wider acquired rows after revocation to prove search does not trust retained data.
        var current by mutableStateOf(state().copy(sessions = listOf(session(sessionA), session(sessionB))))
        var reads = 0
        var refreshes = 0
        rule.setContent {
            DshTheme { Shell(current, nav, onSession = { reads++ }, onRefreshSessions = { refreshes++ }) }
        }
        rule.onNodeWithTag("directory-open-search").performClick()
        rule.onNodeWithTag("directory-search").performTextInput(sessionB)
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionB"))
        rule.onNodeWithTag("session-$sessionB").assertExists()
        rule.runOnIdle { current = current.copy(runtimes = listOf(restricted)) }
        rule.onNodeWithTag("session-directory").performScrollToNode(hasText("当前目录没有匹配项"))
        rule.onNodeWithText("当前目录没有匹配项").assertIsDisplayed()
        rule.onNodeWithTag("session-$sessionB").assertDoesNotExist()
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("directory-search"))
        rule.onNodeWithTag("directory-search").performTextReplacement(sessionA)
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionA"))
        rule.onNodeWithTag("session-$sessionA").assertExists()
        rule.onNodeWithTag("session-$sessionB").assertDoesNotExist()
        rule.runOnIdle { assertEquals(0, reads); assertEquals(0, refreshes) }

        // An error and a subsequent load cannot turn retained rows into search results.
        rule.runOnIdle { current = current.copy(sessionError = "network.unavailable") }
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
        rule.onNodeWithTag("directory-search").assertDoesNotExist()
        rule.onNodeWithTag("directory-open-search").assertIsNotEnabled()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasText("暂时无法读取会话目录，请检查网络后刷新。"))
        rule.onNodeWithText("当前授权范围内没有会话。").assertDoesNotExist()
        rule.onNodeWithContentDescription("刷新").performClick()
        rule.runOnIdle {
            assertEquals(1, refreshes)
            current = current.copy(sessionError = null, loadingSessions = true)
        }
        rule.onNodeWithTag("directory-search").assertDoesNotExist()
        rule.onNodeWithTag("directory-open-search").assertIsNotEnabled()
        rule.onNodeWithContentDescription("刷新").assertIsNotEnabled()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionA"))
        rule.onNodeWithTag("session-$sessionA").assertIsNotEnabled().assertHasNoClickAction()
        rule.runOnIdle { current = current.copy(loadingSessions = false, sessions = listOf(session(sessionA))) }
        rule.onNodeWithTag("directory-search").assertIsEnabled()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionA"))
        rule.onNodeWithTag("session-$sessionA").assertExists()
    }

    @Test fun switchingRuntimeClearsSearchWithoutReadingAnySession() {
        val nav = navigation()
        val rows = listOf(runtime(runtimeA), runtime(runtimeB))
        var current by mutableStateOf(state(rows))
        var reads = 0
        rule.setContent {
            DshTheme { Shell(current, nav, onRuntime = { id ->
                nav.selectRuntime(id)
                current = current.copy(selectedRuntimeId = id, sessions = listOf(session(sessionB)))
            }, onSession = { reads++ }) }
        }
        rule.onNodeWithTag("directory-open-search").performClick()
        rule.onNodeWithTag("directory-search").performTextInput(sessionA)
        rule.onNodeWithTag("runtime-filter").performScrollTo().assertIsDisplayed().performClick()
        rule.onNode(hasScrollAction() and hasAnyAncestor(isDialog())).performScrollToNode(hasTestTag("runtime-filter-$runtimeB"))
        rule.onNodeWithTag("runtime-filter-$runtimeB").performClick()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionB"))
        rule.onNodeWithTag("session-$sessionB").assertExists()
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
        rule.runOnIdle { assertEquals("", nav.directoryQuery); assertEquals(0, reads) }
    }

    @Test fun recentVisitRequiresAReadyAuthorizedReaderAndRevalidatesCurrentRows() {
        val nav = navigation()
        val original = state().copy(selectedSessionId = sessionA, reader = SessionReadState(SessionReadPhase.CONNECTING))
        nav.recordVisited(original)
        var current by mutableStateOf(original.copy(selectedSessionId = null, reader = null))
        val reads = mutableListOf<String>()
        rule.setContent { DshTheme { Shell(current, nav, onSession = { reads += it }) } }
        rule.onNodeWithTag("directory-recent").assertDoesNotExist()
        rule.runOnIdle { nav.recordVisited(original.copy(reader = SessionReadState(SessionReadPhase.READY))) }
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("directory-recent"))
        rule.onNodeWithTag("directory-recent").assertIsDisplayed().performClick()
        rule.runOnIdle { assertEquals(listOf(sessionA), reads) }

        rule.runOnIdle { current = current.copy(sessions = listOf(session(sessionB))) }
        rule.onNodeWithTag("directory-recent").assertDoesNotExist()
        rule.runOnIdle {
            current = current.copy(sessions = original.sessions,
                runtimes = listOf(runtime(runtimeA, workspaces = emptyList(), sessions = listOf(sessionB))))
        }
        rule.onNodeWithTag("directory-recent").assertDoesNotExist()
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
        rule.runOnIdle { current = current.copy(sessions = original.sessions, loadingSessions = true) }
        rule.onNodeWithTag("directory-recent").assertDoesNotExist()
        rule.runOnIdle { current = current.copy(loadingSessions = false, sessionError = "access.denied") }
        rule.onNodeWithTag("directory-recent").assertDoesNotExist()
        rule.runOnIdle {
            current = current.copy(sessionError = null, runtimes = listOf(runtime(runtimeA, listOf("session.list"))))
        }
        rule.onNodeWithTag("directory-recent").assertDoesNotExist()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionA"))
        rule.onNodeWithTag("session-$sessionA").assertIsNotEnabled().assertHasNoClickAction()
        rule.runOnIdle {
            current = original.copy(selectedSessionId = null, reader = null, subject = "another-account")
        }
        rule.onNodeWithTag("directory-recent").assertDoesNotExist()
        rule.runOnIdle {
            nav.selectRuntime(runtimeB)
            current = original.copy(selectedRuntimeId = runtimeB, selectedSessionId = null, reader = null,
                runtimes = listOf(runtime(runtimeB)))
        }
        rule.onNodeWithTag("directory-recent").assertDoesNotExist()
    }

    @Test fun recentVisitCannotBeRecordedFromAKnownTargetOrDirectoryOnlyGrant() {
        val nav = navigation()
        val original = state().copy(selectedSessionId = sessionA, reader = SessionReadState(SessionReadPhase.READY))
        val known = cn.edu.ustc.dsh.network.SessionTarget.parse(jsonObject(
            "runtime" to jsonObject(
                "id" to runtimeA.json(), "host_id" to workspace.json(), "organization_id" to workspace.json(),
                "protocol_version" to 1L.json(),
                "access" to jsonObject("role" to "viewer".json(), "grant_version" to 1L.json(),
                    "scope" to RelayScope(listOf("session.read"), emptyList(), listOf(sessionA)).json()),
            ),
            "session" to jsonObject("session_id" to sessionA.json(), "workspace_id" to workspace.json(),
                "state" to "available".json(), "last_persisted_seq" to 0L.json(), "updated_at" to "2026-10-25T00:00:00Z".json()),
        ))
        nav.recordVisited(original.copy(knownTarget = known))
        nav.recordVisited(original.copy(runtimes = listOf(runtime(runtimeA, listOf("session.list")))))
        rule.setContent { DshTheme { Shell(original.copy(selectedSessionId = null, reader = null), nav) } }
        rule.onNodeWithTag("directory-recent").assertDoesNotExist()
    }

    @Test fun returningToTheSameDirectoryRetainsItsPositionAndDoesNotOpenAReader() {
        val nav = navigation()
        val entries = (1..24).map { index ->
            session("${index.toString(16).padStart(8, '0')}-7777-4777-8777-777777777777")
        }
        val current = state().copy(sessions = entries)
        val position = nav.directoryPosition
        var index = 0
        var offset = 0
        var reads = 0
        rule.setContent { DshTheme { Shell(current, nav, onSession = { reads++ }) } }
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-${entries.last().id}"))
        rule.runOnIdle {
            index = position.firstVisibleItemIndex
            offset = position.firstVisibleItemScrollOffset
            check(index > 0)
        }
        rule.onNode(hasText("电脑") and hasClickAction()).performClick()
        rule.onNode(hasText("会话") and hasClickAction()).performClick()
        rule.runOnIdle {
            nav.selectRuntime(runtimeA)
            assertEquals(position, nav.directoryPosition)
            assertEquals(index, position.firstVisibleItemIndex)
            assertEquals(offset, position.firstVisibleItemScrollOffset)
            assertEquals(0, reads)
        }
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
    @Test fun wideWindowKeepsDirectoryAndNavigationUsableWithoutExtraReaders() {
        val nav = navigation()
        var opened: String? = null
        rule.setContent {
            CompositionLocalProvider(LocalDensity provides Density(.75f, 1f)) {
                DshTheme { Box(Modifier.width(840.dp).height(600.dp)) { Shell(state(), nav, onSession = { opened = it }) } }
            }
        }
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionA"))
        rule.onNodeWithTag("session-$sessionA").assertIsDisplayed().performClick()
        rule.runOnIdle { assertEquals(sessionA, opened) }
        saveFixture("sessions-wide-window", dark = false)
    }
    @Test fun workspaceCollisionsAreReadableAndDisambiguationUsesOnlyAuthorizedRows() {
        val collision = "55555555-6666-4666-8666-666666665555"
        var current by mutableStateOf(state().copy(sessions = listOf(session(sessionA), session(sessionB, collision))))
        val nav = navigation()
        rule.setContent {
            val density = LocalDensity.current.density
            CompositionLocalProvider(LocalDensity provides Density(density, 2f)) {
                DshTheme(darkTheme = true) { Box(Modifier.width(320.dp).height(480.dp)) { Shell(current, nav) } }
            }
        }
        rule.onNodeWithTag("session-directory").performScrollToNode(hasText("工作区 $workspace"))
        rule.onNodeWithText("工作区 $workspace").assertIsDisplayed()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasText("工作区 $collision"))
        rule.onNodeWithText("工作区 $collision").assertIsDisplayed()
        saveFixture("details-directory-workspace-collision", dark = true)
        rule.runOnIdle {
            current = current.copy(runtimes = listOf(runtime(runtimeA, workspaces = emptyList(), sessions = listOf(sessionA))))
        }
        rule.onNodeWithTag("session-directory").performScrollToNode(hasText("工作区 ${workspace.take(8)}…${workspace.takeLast(4)}"))
        rule.onNodeWithText("工作区 $collision").assertDoesNotExist()
        rule.onNodeWithText("工作区 $workspace").assertDoesNotExist()
        rule.onNodeWithTag("session-$sessionB").assertDoesNotExist()
    }
    @Test fun statusWorkspaceAndIdFiltersIntersectOnlyAcquiredAuthorizedRowsWithoutRequests() {
        val otherWorkspace = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        val excludedWorkspace = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        val excludedSession = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        val nav = navigation()
        val grant = runtime(runtimeA, workspaces = emptyList(), sessions = listOf(sessionA, sessionB, runtimeB))
        val current = state(listOf(grant)).copy(sessions = listOf(
            session(sessionA), session(sessionB, otherWorkspace, "archived"),
            session(runtimeB, null, "unavailable"), session(excludedSession, excludedWorkspace, "archived"),
        ))
        var reads = 0
        var refreshes = 0
        var runtimeRequests = 0
        rule.setContent { DshTheme { Shell(current, nav, onSession = { reads++ },
            onRuntime = { runtimeRequests++ }, onRefreshSessions = { refreshes++ }) } }
        rule.onNodeWithTag("directory-status-ARCHIVED").performClick()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionB"))
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
        rule.onNodeWithTag("session-$runtimeB").assertDoesNotExist()
        rule.onNodeWithTag("session-$excludedSession").assertDoesNotExist()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("directory-workspace-filter"))
        rule.onNodeWithTag("directory-workspace-filter").performClick()
        rule.onNodeWithTag("directory-workspace-$excludedWorkspace").assertDoesNotExist()
        rule.onNodeWithTag("directory-workspace-$workspace").performScrollTo().performClick()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasText("当前目录没有匹配项"))
        rule.onNodeWithText("当前授权范围内没有会话。").assertDoesNotExist()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("directory-reset-filters"))
        rule.onNodeWithTag("directory-reset-filters").performClick()
        rule.runOnIdle {
            assertEquals(DirectorySessionFilter.ALL, nav.directorySessionFilter)
            assertEquals(null, nav.directoryWorkspaceId)
            assertEquals("", nav.directoryQuery)
        }
        rule.onNodeWithTag("directory-status-ACTIVE").performClick()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$runtimeB"))
        rule.onNodeWithTag("session-$runtimeB").assertExists()
        rule.onNodeWithTag("session-$sessionB").assertDoesNotExist()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("directory-reset-filters"))
        rule.onNodeWithTag("directory-reset-filters").performClick()
        rule.onNodeWithTag("directory-open-search").performClick()
        rule.onNodeWithTag("directory-search").performTextInput(otherWorkspace.uppercase())
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionB"))
        rule.onNodeWithTag("session-$sessionA").assertDoesNotExist()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("directory-search"))
        rule.onNodeWithTag("directory-search").performTextReplacement(sessionA)
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("session-$sessionA"))
        rule.onNodeWithTag("session-$sessionB").assertDoesNotExist()
        rule.runOnIdle {
            assertEquals(0, reads)
            assertEquals(0, refreshes)
            assertEquals(0, runtimeRequests)
        }
    }

    @Test fun transientLoadsKeepFiltersButMissingWorkspacesAndOwnerChangesRetireThem() {
        val nav = navigation()
        val owner = CommandOwner(runtimeA, workspace, "a".repeat(64), sessionA, runtimeB)
        val original = state().copy(presentationOwner = owner)
        nav.reconcileDirectory(original)
        nav.directoryWorkspaceId = workspace
        nav.directorySessionFilter = DirectorySessionFilter.ARCHIVED
        nav.directoryQuery = sessionA
        nav.reconcileDirectory(original.copy(loadingSessions = true))
        nav.reconcileDirectory(original.copy(sessionError = "network.unavailable"))
        assertEquals(workspace, nav.directoryWorkspaceId)
        assertEquals(DirectorySessionFilter.ARCHIVED, nav.directorySessionFilter)
        assertEquals(sessionA, nav.directoryQuery)
        // Fresh checkpoint objects with equal identities must preserve local filters.
        nav.reconcileDirectory(original.copy(presentationOwner = CommandOwner(runtimeA, workspace, "a".repeat(64), sessionA, runtimeB)))
        assertEquals(workspace, nav.directoryWorkspaceId)
        nav.reconcileDirectory(original.copy(sessions = emptyList()))
        assertEquals(null, nav.directoryWorkspaceId)
        nav.reconcileDirectory(original)
        assertEquals(null, nav.directoryWorkspaceId)
        nav.directoryWorkspaceId = workspace
        nav.reconcileDirectory(original.copy(presentationOwner = CommandOwner(runtimeA, workspace, "b".repeat(64), sessionA, runtimeB)))
        assertEquals(null, nav.directoryWorkspaceId)
        assertEquals(DirectorySessionFilter.ALL, nav.directorySessionFilter)
        assertEquals("", nav.directoryQuery)
        nav.directoryWorkspaceId = workspace
        nav.directorySessionFilter = DirectorySessionFilter.ARCHIVED
        nav.directoryQuery = sessionA
        nav.selectRuntime(runtimeB)
        assertEquals(null, nav.directoryWorkspaceId)
        assertEquals(DirectorySessionFilter.ALL, nav.directorySessionFilter)
        assertEquals("", nav.directoryQuery)
        nav.directoryQuery = sessionB
        nav.reconcileDirectory(original.copy(phase = HomePhase.SIGNED_OUT))
        assertEquals("", nav.directoryQuery)
    }

    @Test fun scopeNarrowingAndRevocationRetireWorkspaceAndRecentHintsWithoutRestoringThem() {
        val nav = navigation()
        val original = state().copy(selectedSessionId = sessionA, reader = SessionReadState(SessionReadPhase.READY))
        nav.reconcileDirectory(original)
        nav.recordVisited(original)
        nav.directoryWorkspaceId = workspace
        val narrowed = original.copy(runtimes = listOf(runtime(runtimeA, workspaces = emptyList(), sessions = listOf(sessionB))))
        nav.reconcileDirectory(narrowed)
        assertEquals(null, nav.directoryWorkspaceId)
        assertEquals(null, nav.recentSession(narrowed))
        nav.reconcileDirectory(original)
        assertEquals(null, nav.directoryWorkspaceId)
        assertEquals(null, nav.recentSession(original))
        nav.directoryWorkspaceId = workspace
        nav.directoryQuery = sessionA
        nav.directorySessionFilter = DirectorySessionFilter.ARCHIVED
        nav.reconcileDirectory(original.copy(runtimes = listOf(runtime(runtimeA, listOf("session.read")))))
        assertEquals(null, nav.directoryWorkspaceId)
        assertEquals("", nav.directoryQuery)
        assertEquals(DirectorySessionFilter.ALL, nav.directorySessionFilter)
    }

    @Test fun loadingErrorEmptyAndFilteredEmptyAreDistinctWhileFiltersRemainLocal() {
        val nav = navigation()
        var current by mutableStateOf(state().copy(loadingSessions = true))
        var refreshes = 0
        rule.setContent { DshTheme { Shell(current, nav, onRefreshSessions = { refreshes++ }) } }
        rule.onNodeWithText("正在读取会话目录").assertExists()
        rule.onNodeWithText("当前授权范围内没有会话。").assertDoesNotExist()
        rule.onNodeWithTag("directory-status-ARCHIVED").assertIsNotEnabled()
        rule.runOnIdle { current = current.copy(loadingSessions = false, refreshing = true, sessions = emptyList()) }
        rule.onNodeWithText("正在核对电脑授权").assertExists()
        rule.onNodeWithText("当前授权范围内没有会话。").assertDoesNotExist()
        rule.onNodeWithTag("directory-status-ARCHIVED").assertIsNotEnabled()
        rule.runOnIdle { current = current.copy(refreshing = false, loadingSessions = false, sessionError = "network.unavailable") }
        rule.onNodeWithTag("directory-status-ARCHIVED").assertIsNotEnabled()
        rule.onNodeWithText("当前目录没有匹配项").assertDoesNotExist()
        rule.onNodeWithText("当前授权范围内没有会话。").assertDoesNotExist()
        rule.runOnIdle { current = current.copy(sessionError = null, sessions = emptyList()) }
        rule.onNodeWithTag("session-directory").performScrollToNode(hasText("当前授权范围内没有会话。"))
        rule.runOnIdle { current = current.copy(sessions = listOf(session(sessionA))) }
        rule.onNodeWithTag("session-directory").performScrollToNode(hasTestTag("directory-status-ARCHIVED"))
        rule.onNodeWithTag("directory-status-ARCHIVED").performClick()
        rule.onNodeWithTag("session-directory").performScrollToNode(hasText("当前目录没有匹配项"))
        rule.onNodeWithText("当前授权范围内没有会话。").assertDoesNotExist()
        rule.runOnIdle { assertEquals(0, refreshes) }
    }

    @Test fun appearanceRequiresAnOwnerAndHasAWorkingCallbackAfterOneIsAvailable() {
        val nav = navigation(HomeDestination.SETTINGS)
        var current by mutableStateOf(state())
        var opened = 0
        rule.setContent { DshTheme { Shell(current, nav, onAppearance = { opened++ }) } }
        rule.onNodeWithTag("settings-list").performScrollToNode(hasTestTag("settings-appearance"))
        rule.onNodeWithTag("settings-appearance").assertIsNotEnabled().assertHasNoClickAction()
        rule.onNodeWithText("尚未取得当前账号的展示设置归属信息，暂不能打开；请完成登录或刷新账号状态。").assertExists()
        rule.runOnIdle { current = current.copy(presentationOwner = CommandOwner(runtimeA, workspace, "a".repeat(64), sessionA, runtimeB)) }
        rule.onNodeWithTag("settings-appearance").assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(1, opened) }
    }

    @Test fun accountDetailsKeepFullIdentifiersReachable() {
        val owner = CommandOwner(runtimeA, workspace, "d".repeat(64), sessionA, runtimeB)
        val account = state().copy(subject = "full-account-subject-".repeat(6),
            issuer = "https://identity.example.edu/school/complete-issuer", presentationOwner = owner)
        val nav = navigation(HomeDestination.SETTINGS)
        rule.setContent {
            val density = LocalDensity.current.density
            CompositionLocalProvider(LocalDensity provides Density(density, 2f)) {
                DshTheme { Box(Modifier.width(320.dp).height(480.dp)) { Shell(account, nav) } }
            }
        }
        clickSettingsItem("账号与设备详情")
        for (identifier in listOf(account.subject, account.issuer, account.deviceId,
                owner.accountId, owner.organizationId, owner.userId, owner.deploymentHash)) {
            rule.onNodeWithTag("account-detail-list").performScrollToNode(hasText(identifier))
            rule.onNodeWithText(identifier).assertIsDisplayed()
        }
        rule.onNodeWithText("关闭").performClick()
        rule.onNodeWithTag("account-detail-list").assertDoesNotExist()
    }

    @Test fun computerHasOnePrimaryDirectoryActionAndNeverInventsPresence() {
        val opened = mutableListOf<String>()
        var creates = 0
        val row = runtime(runtimeA, listOf("session.list", "session.read", "session.create", "command.status"))
        val nav = navigation(HomeDestination.COMPUTERS)
        rule.setContent { DshTheme { Shell(state(listOf(row)), nav,
            onRuntime = { opened += it }, onCreate = { creates++ }) } }
        rule.onNodeWithText("当前目录未提供连接状态").assertExists()
        rule.onAllNodes(hasTestTag("computer-open-$runtimeA") and hasClickAction()).assertCountEquals(1)
        rule.onNodeWithTag("computer-open-$runtimeA").performScrollTo().performClick()
        rule.onNodeWithTag("computer-create-$runtimeA").performScrollTo().performClick()
        rule.onNodeWithTag("computer-details-$runtimeA").performScrollTo().performClick()
        rule.onNodeWithText(runtimeA).performScrollTo().assertIsDisplayed()
        rule.runOnIdle { assertEquals(listOf(runtimeA), opened); assertEquals(1, creates) }
    }

    @Test fun computerLoadingAndErrorsDoNotMasqueradeAsAnEmptyDirectory() {
        var current by mutableStateOf(state(emptyList()).copy(refreshing = true))
        val nav = navigation(HomeDestination.COMPUTERS)
        rule.setContent { DshTheme { Shell(current, nav) } }
        rule.onNodeWithText("正在核对电脑授权").assertExists()
        rule.onNodeWithText("尚无获授权的电脑").assertDoesNotExist()
        rule.runOnIdle { current = current.copy(refreshing = false, error = "network.unavailable") }
        rule.onNodeWithText("尚无获授权的电脑").assertDoesNotExist()
        rule.runOnIdle { current = current.copy(error = null) }
        rule.onNodeWithText("尚无获授权的电脑").assertExists()
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
        var captureMethod = if (useDisplayCapture) "uiAutomation-display" else "compose-root"
        val bitmap = if (useDisplayCapture) {
            check(rule.activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE == 0) {
                "Only the public synthetic fixture may use display capture"
            }
            val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
            automation.takeScreenshot() ?: run {
                captureMethod = "shell-display"
                val bytes = ParcelFileDescriptor.AutoCloseInputStream(automation.executeShellCommand("screencap -p")).use { it.readBytes() }
                checkNotNull(BitmapFactory.decodeByteArray(bytes, 0, bytes.size)) { "Cannot capture the synthetic dialog display" }
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
            .put("captureMethod", captureMethod)
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
