package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import android.content.res.Configuration
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.ClipboardManager
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.ui.DshTheme
import cn.edu.ustc.dsh.ui.DshTopBar
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import kotlin.math.roundToInt

/** Synthetic public content, in a real Activity. Scene density is recorded separately from its host. */
@RunWith(AndroidJUnit4::class)
class UiDetailLayoutTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private var sceneDensity = Density(1f)

    @Composable
    private fun Scene(width: Int, height: Int, scale: Float, dark: Boolean, content: @Composable () -> Unit) {
        BoxWithConstraints(Modifier.fillMaxSize()) {
            val density = Density(minOf(constraints.maxWidth / width.toFloat(), constraints.maxHeight / height.toFloat()), scale)
            SideEffect { sceneDensity = density }
            CompositionLocalProvider(LocalDensity provides density) {
                DshTheme(darkTheme = dark) {
                    Surface(Modifier.requiredSize(width.dp, height.dp).testTag("ui-detail-scene"), color = MaterialTheme.colorScheme.background) {
                        Box(Modifier.fillMaxSize()) { content() }
                    }
                }
            }
        }
    }

    private fun capture(name: String, dark: Boolean) {
        captureUiFixture(rule, name, darkTheme = dark)
        val directory = File(InstrumentationRegistry.getInstrumentation().targetContext.filesDir, "ui-navigation-fixtures")
        val metadata = File(directory, "$name.json")
        val bounds = rule.onNodeWithTag("ui-detail-scene").fetchSemanticsNode().boundsInRoot
        metadata.writeText(JSONObject(metadata.readText())
            .put("density", sceneDensity.density).put("fontScale", sceneDensity.fontScale)
            .put("sceneWidthPx", bounds.width).put("sceneHeightPx", bounds.height).toString(2))
    }

    private fun titleScene(width: Int, height: Int, scale: Float, dark: Boolean, maxWidth: Int = 800) {
        val title = "会话 11111111"
        val subtitle = "实验室电脑 · 当前已授权的任务会话"
        var backs = 0
        var details = 0
        rule.setContent {
            Scene(width, height, scale, dark) {
                Scaffold(topBar = {
                    DshTopBar(title, subtitle = subtitle, contentMaxWidth = maxWidth.dp,
                        navigationIcon = { IconButton({ backs++ }, Modifier.size(48.dp)) { Icon(painterResource(R.drawable.ic_back), "返回") } },
                        actions = { IconButton({ details++ }, Modifier.size(48.dp)) { Icon(painterResource(R.drawable.ic_info), "会话详情") } })
                }) { padding ->
                    Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState())) {
                        Text("正文起点", Modifier.testTag("body-start"))
                    }
                }
            }
        }
        rule.onNodeWithText(title).assertIsDisplayed()
        rule.onNodeWithText(subtitle).assertIsDisplayed()
        val titleBounds = rule.onNodeWithText(title).fetchSemanticsNode().boundsInRoot
        val subtitleBounds = rule.onNodeWithText(subtitle).fetchSemanticsNode().boundsInRoot
        val bodyBounds = rule.onNodeWithTag("body-start").fetchSemanticsNode().boundsInRoot
        val backBounds = rule.onNodeWithContentDescription("返回").fetchSemanticsNode().boundsInRoot
        val detailBounds = rule.onNodeWithContentDescription("会话详情").fetchSemanticsNode().boundsInRoot
        assertFalse(titleBounds.overlaps(backBounds))
        assertFalse(titleBounds.overlaps(detailBounds))
        assertTrue(subtitleBounds.top >= titleBounds.bottom)
        assertTrue(bodyBounds.top >= subtitleBounds.bottom)
        val minimumTargetPx = (48f * sceneDensity.density).roundToInt()
        assertTrue("back target: $backBounds, minimum=$minimumTargetPx", backBounds.width >= minimumTargetPx)
        assertTrue("detail target: $detailBounds, minimum=$minimumTargetPx", detailBounds.width >= minimumTargetPx)
        rule.onNodeWithContentDescription("返回").performClick()
        rule.onNodeWithContentDescription("会话详情").performClick()
        rule.runOnIdle { assertEquals(1, backs); assertEquals(1, details) }
        capture("details-title-$width-$height-$scale", dark)
    }

    @Test fun phoneTitleAndSubtitleDoNotCompeteWithControls() = titleScene(320, 640, 1f, false)
    @Test fun phoneLargeTextKeepsContentBelowTheGrowingTitle() = titleScene(320, 480, 2f, true)
    @Test fun landscapeTitleAndActionsLeaveAReadableBody() = titleScene(640, 320, 2f, false)
    @Test fun wideTitleControlsStayWithTheBoundedContent() = titleScene(840, 600, 1f, false, 720)
    private fun alignedTableScene(scale: Float, dark: Boolean) {
        val longCell = "长内容需要换行".repeat(3)
        val source = "| 左列 | 右列 |\n| --- | --- |\n| $longCell | 短格 |\n| | 末行 |\n"
        rule.setContent { Scene(320, 640, scale, dark) {
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp)) { RichMessageText(source) }
        } }
        rule.waitUntil(10_000) { rule.onAllNodesWithTag("message-table-cell-1-0").fetchSemanticsNodes().isNotEmpty() }
        val left = rule.onNodeWithTag("message-table-cell-1-0").fetchSemanticsNode().boundsInRoot
        val right = rule.onNodeWithTag("message-table-cell-1-1").fetchSemanticsNode().boundsInRoot
        val next = rule.onNodeWithTag("message-table-cell-2-0").fetchSemanticsNode().boundsInRoot
        val scene = rule.onNodeWithTag("ui-detail-scene").fetchSemanticsNode().boundsInRoot
        assertEquals(left.top, right.top, 1f)
        assertEquals(left.bottom, right.bottom, 1f)
        assertTrue(next.top >= left.bottom - 1f)
        assertTrue(right.right <= scene.right + 1f)
        rule.onNodeWithText(longCell).assertIsDisplayed()
        rule.onNodeWithText("短格").assertIsDisplayed()
        capture("details-table-$scale", dark)
    }

    @Test fun mixedHeightTableCellsShareTheirRowAtPhoneWidth() = alignedTableScene(1f, false)
    @Test fun largeTextTableKeepsEmptyCellsAndTheNextRowAligned() = alignedTableScene(2f, true)

    @Test fun aWideTableScrollsItsHeaderAndBodyTogether() {
        val source = "| 一 | 二 | 三 | 四 |\n| --- | --- | --- | --- |\n| 值一 | 值二 | 值三 | 末列原值 |\n"
        rule.setContent { Scene(320, 640, 1f, false) {
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp)) { RichMessageText(source) }
        } }
        rule.waitUntil(10_000) { rule.onAllNodesWithTag("message-table-cell-0-3").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithTag("message-table-cell-0-3").performScrollTo()
        rule.onNodeWithText("四").assertIsDisplayed()
        rule.onNodeWithText("末列原值").assertIsDisplayed()
        val header = rule.onNodeWithTag("message-table-cell-0-3").fetchSemanticsNode().boundsInRoot
        val body = rule.onNodeWithTag("message-table-cell-1-3").fetchSemanticsNode().boundsInRoot
        assertEquals(header.left, body.left, 1f)
        assertEquals(header.right, body.right, 1f)
        capture("details-table-scroll", false)
    }

    @Test fun copyingCodeUsesTheActualPayloadAndAClipboardRejectionDoesNotClaimSuccess() {
        lateinit var clipboard: ClipboardManager
        val reject = mutableStateOf(false)
        val source = "```shell\necho 中文🙂\n```"
        rule.setContent {
            val system = LocalClipboardManager.current
            SideEffect { clipboard = system }
            val unavailable = remember(system) { object : ClipboardManager by system {
                override fun setText(annotatedString: AnnotatedString) { throw SecurityException("clipboard unavailable") }
            } }
            CompositionLocalProvider(LocalClipboardManager provides if (reject.value) unavailable else system) {
                Scene(360, 640, 1f, false) {
                    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) { RichMessageText(source) }
                }
            }
        }
        rule.waitUntil(10_000) { rule.onAllNodesWithText("复制代码块").fetchSemanticsNodes().isNotEmpty() }
        val previous = clipboard.getText()
        try {
            rule.onNodeWithText("复制代码块").performClick()
            rule.runOnIdle { assertEquals("echo 中文🙂\n", clipboard.getText()?.text); reject.value = true }
            rule.onNode(hasClickAction() and (hasText("复制代码块") or hasText("已复制"))).performClick()
            rule.onNodeWithText("复制未完成，请选择代码后重试。").assertIsDisplayed()
            rule.onNodeWithText("已复制").assertDoesNotExist()
            capture("details-code-copy-failure", false)
        } finally {
            rule.runOnIdle { clipboard.setText(previous ?: AnnotatedString("")) }
        }
    }
    private fun approvalReadingScene(panelWidth: Int, scale: Float) {
        val fixture = ApprovalUiFixture()
        rule.setContent { Scene(840, 600, scale, scale > 1f) {
            val configuration = Configuration(LocalConfiguration.current).apply { screenWidthDp = 840 }
            CompositionLocalProvider(LocalConfiguration provides configuration) {
                Box(Modifier.width(panelWidth.dp).height(480.dp)) {
                    ApprovalReviewScreen(fixture.state(), {}, {}, { _, _ -> fail("Reading navigation cannot authorize a decision") },
                        { _, _ -> }, {}, {}, {}, {})
                }
            }
        } }
        rule.waitUntil(10_000) { rule.onAllNodesWithText("我已核对本页").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithText("下一页").performScrollTo()
        val previous = rule.onNodeWithText("上一页").fetchSemanticsNode().boundsInRoot
        val next = rule.onNodeWithText("下一页").fetchSemanticsNode().boundsInRoot
        if (panelWidth < 432 || scale > 1.3f) assertTrue(next.top >= previous.bottom - 1f)
        else assertEquals(previous.top, next.top, 1f)
        rule.onNodeWithText("字段目录").performScrollTo().assertIsDisplayed().performClick()
        rule.onNodeWithText("完整参数").performClick()
        rule.onNodeWithText("定位未核对页").performScrollTo().assertIsDisplayed().performClick()
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("拒绝并确认身份").performScrollTo().assertIsEnabled()
        capture("details-approval-$panelWidth-$scale", scale > 1f)
    }

    @Test fun anEmbeddedApprovalPanelUsesItsOwnWidthInsteadOfTheWideHost() = approvalReadingScene(320, 1f)
    @Test fun largeTextApprovalNavigationFitsANarrowPanelWithoutAuthorizingIt() = approvalReadingScene(320, 2f)
    @Test fun wideApprovalPagingSharesARowWithoutSkippingReview() = approvalReadingScene(840, 1f)
}
