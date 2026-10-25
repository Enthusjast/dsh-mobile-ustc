package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
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
    @Test fun approvalNeedsExplicitReviewAndConsentWhileRejectIsAnIndependentChoice() {
        val fixture = ApprovalUiFixture(); var result: ApprovalChoice? = null; var handle: ApprovalReviewHandle? = null
        content(fixture.state(), { h, c -> handle = h; result = c })
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
        repeat(2) {
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
    @Test fun viewerAuthorityHidesTheContextAndSchoolAssuranceFailureOffersExplicitReauthentication() {
        val fixture = ApprovalUiFixture()
        content(fixture.state(role = "viewer", error = "approval.assurance_required"))
        rule.onNodeWithText("printf ui-fixture", substring = true).assertDoesNotExist()
        rule.onNodeWithText("仅本次允许并确认身份").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("拒绝并确认身份").performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText("重新验证学校登录").assertExists()
    }
}
