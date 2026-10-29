package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.ApprovalReviewHandle
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ApprovalReviewScreenTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private val acknowledgement = "我已核对全部动作、参数及资源，仅为本次调用作出决定。"
    private fun content(state: HomeState, decide: (ApprovalReviewHandle, ApprovalChoice) -> Unit = { _, _ -> }, reauthenticate: () -> Unit = {}) {
        rule.setContent { DshTheme { ApprovalReviewScreen(state, {}, {}, decide, { _, _ -> }, {}, {}, {}, reauthenticate) } }
    }
    private fun acknowledge() {
        rule.onNodeWithText("我已核对本页").performScrollTo().performClick()
        rule.onNodeWithText(acknowledgement).performScrollTo().performClick()
    }
    @Test fun narrowLargeTextCanReachReviewRejectAndReturn() {
        val fixture = ApprovalUiFixture()
        rule.setContent {
            val density = LocalDensity.current.density
            CompositionLocalProvider(LocalDensity provides Density(density, 2f)) {
                DshTheme { Box(Modifier.width(320.dp).height(480.dp)) {
                    ApprovalReviewScreen(fixture.state(), {}, {}, { _, _ -> }, { _, _ -> }, {}, {}, {}, {})
                } }
            }
        }
        rule.onNodeWithText("拒绝并确认身份").performScrollTo().assertIsEnabled()
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("我已核对本页").performScrollTo().performClick()
        rule.onNodeWithText(acknowledgement).performScrollTo().performClick()
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsEnabled()
        rule.onNodeWithText("关闭详情").performScrollTo().assertIsDisplayed()
    }
    @Test fun approvalNeedsExplicitReviewAndConsentWhileRejectIsAnIndependentChoice() {
        val fixture = ApprovalUiFixture(); var result: ApprovalChoice? = null; var handle: ApprovalReviewHandle? = null
        content(fixture.state(), { h, c -> handle = h; result = c })
        rule.onNodeWithText("我已核对本页").performScrollTo()
        captureUiFixture(rule, "approval-complete-action")
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("拒绝并确认身份").performScrollTo().assertIsEnabled()
        acknowledge()
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(ApprovalChoice.ALLOW_ONCE, result); assertEquals(fixture.handle, handle); assertEquals(fixture.body.bindingSha256, handle!!.bindingSha256) }
    }
    @Test fun hiddenLaterParametersMustBeDisplayedAndAcknowledgedBeforeAllowCanBeEnabled() {
        val fixture = ApprovalUiFixture("x".repeat(17_000) + "UNREVIEWED_SUFFIX")
        content(fixture.state())
        rule.onNodeWithText("UNREVIEWED_SUFFIX", substring = true).assertDoesNotExist()
        repeat(4) {
            rule.onNodeWithText("我已核对本页").performScrollTo().performClick()
            rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsNotEnabled()
            rule.onNodeWithText("下一页").performScrollTo().performClick()
            rule.waitForIdle()
        }
        rule.onNodeWithText("UNREVIEWED_SUFFIX", substring = true).assertExists()
        acknowledge()
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsEnabled()
    }
    @Test fun consentAndReviewedPagesAreNotRestoredFromSavedInstanceState() {
        val fixture = ApprovalUiFixture(); val tester = StateRestorationTester(rule)
        tester.setContent { DshTheme { ApprovalReviewScreen(fixture.state(), {}, {}, { _, _ -> }, { _, _ -> }, {}, {}, {}, {}) } }
        acknowledge()
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsEnabled()
        tester.emulateSavedInstanceStateRestore()
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("我已核对本页").assertExists()
    }
    @Test fun aHistoricalOriginalWithoutAnOnlineHandleNeverBecomesAnExecutableCallback() {
        val fixture = ApprovalUiFixture(); val row = fixture.original()
        content(fixture.state(live = false, records = listOf(row)))
        rule.onNodeWithText("显示本机原决定，仅供核对。").assertExists()
        rule.onNodeWithText("原决定结果待确认，不会自动重复转交").assertExists()
        rule.onNodeWithText("仅本次允许并确认身份").assertDoesNotExist()
        rule.onNodeWithText("核对并转交同一原决定").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("删除本机未转交决定").assertDoesNotExist()
    }
    @Test fun invisibleDirectionalCharactersAreShownAsEscapesWithoutChangingTheSignedBinding() {
        // Actual format scalars must remain visible for human review.
        val actual = ApprovalUiFixture("echo "+'\u202e'+" then "+'\u200b')
        content(actual.state())
        rule.onNodeWithText("\\u202e", substring = true).assertExists()
        rule.onNodeWithText("\\u200b", substring = true).assertExists()
        rule.onNodeWithText("不可见的方向、格式和控制字符以 Unicode 转义显示。").assertExists()
        assertEquals(actual.body.bindingSha256, actual.handle.bindingSha256)
    }
    @Test fun switchingRepresentationClearsPriorReviewAndCannotAuthorizeUnreviewedContent() {
        val fixture = ApprovalUiFixture()
        content(fixture.state())
        acknowledge()
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsEnabled()
        rule.onNodeWithText("切换到原始完整 JSON").performScrollTo().performClick()
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("我已核对本页").performScrollTo().performClick()
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText(acknowledgement).performScrollTo().performClick()
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsEnabled()
        rule.onNodeWithText("切换到字段化阅读").performScrollTo().performClick()
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsNotEnabled()
    }

    @Test fun structuredProjectionContainsUnknownNestedValuesAndTheirCoverage() {
        val nested = jsonObject("unknown" to JsonArray(listOf(JsonNull, JsonBoolean(false),
            jsonObject("tail" to ("x".repeat(12_000) + "END🙂").json()))))
        val fixture = ApprovalUiFixture(arguments = nested)
        val labels = ApprovalProjectionLabels("对象", "数组", "字符串", "数字", "布尔", "空值", emptyMap())
        val projection = approvalStructuredProjection(fixture.body, labels)
        val all = projection.pages.joinToString("")
        assertTrue(all.contains("\"unknown\""))
        assertTrue(all.contains("[0]: 空值 null"))
        assertTrue(all.contains("[1]: 布尔 false"))
        assertTrue(all.contains("END🙂"))
        assertTrue(projection.coverage.any { it.key == "tail" && it.pages.count() > 1 })
        assertFalse(projection.completelyReviewed(projection.pages.indices.toList().dropLast(1).toSet()))
        assertTrue(projection.completelyReviewed(projection.pages.indices.toSet()))
        assertEquals(fixture.body.document.canonicalText(), approvalRawProjection(fixture.body).pages.joinToString(""))
    }
    @Test fun maximumContextRetainsEveryCharacterAndRequiresItsTailPage() {
        fun argument(value: String) = jsonObject("deep" to JsonArray(listOf(jsonObject("tail" to value.json()))))
        val baseline = ApprovalUiFixture(arguments = argument(""))
        val suffix = "\u202eEND🙂"
        val count = 128 * 1024 - baseline.body.document.canonicalBytes().size - suffix.toByteArray(Charsets.UTF_8).size
        val tail = "x".repeat(count) + suffix
        val raw = baseline.body.document.canonicalText().replace("\"tail\":\"\"", "\"tail\":\"$tail\"")
        val context = ApprovalContext.parse(raw.toByteArray(Charsets.UTF_8))
        val labels = ApprovalProjectionLabels("对象", "数组", "字符串", "数字", "布尔", "空值", emptyMap())
        val projection = approvalStructuredProjection(context, labels)
        assertEquals(128 * 1024, context.document.canonicalBytes().size)
        assertTrue(projection.pages.joinToString("").contains("x".repeat(count) + "\\u202eEND🙂"))
        assertFalse(projection.completelyReviewed(projection.pages.indices.toList().dropLast(1).toSet()))
        assertTrue(projection.completelyReviewed(projection.pages.indices.toSet()))
        assertEquals(context.document.sha256(), context.bindingSha256)
    }
    @Test fun viewerAuthorityHidesTheContextAndSchoolAssuranceFailureOffersExplicitReauthentication() {
        val fixture = ApprovalUiFixture()
        content(fixture.state(role = "viewer", error = "approval.assurance_required"))
        rule.onNodeWithText("printf ui-fixture", substring = true).assertDoesNotExist()
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("拒绝并确认身份").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("重新验证学校登录").assertExists()
    }
}
