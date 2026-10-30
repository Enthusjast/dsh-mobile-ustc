package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NotificationsScreenTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()

    @Test fun emptyReferencesNeverClaimAllRequestsAreHandledAndUnconfiguredPushHasAReachableExit() {
        var state by mutableStateOf(NotificationUiState(phase = NotificationPhase.ACTIVE, allowed = true))
        var refreshes = 0
        var backs = 0
        rule.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, 2f)) {
                DshTheme(darkTheme = true) {
                    Box(Modifier.width(320.dp)) {
                        NotificationsScreen(state, { refreshes++ }, {}, {}, {}, {}, {}, { _, _ -> }, { backs++ })
                    }
                }
            }
        }
        val empty = rule.activity.getString(R.string.flow_notifications_no_references)
        rule.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(empty))
        rule.onNodeWithText(empty).assertIsDisplayed()
        rule.onNodeWithText("全部已处理").assertDoesNotExist()
        rule.runOnIdle { state = NotificationUiState(phase = NotificationPhase.UNCONFIGURED, allowed = true) }
        rule.onNodeWithText("启用此账号通知").assertDoesNotExist()
        val foreground = rule.activity.getString(R.string.flow_notifications_foreground)
        rule.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(foreground))
        rule.onNodeWithText(foreground).performScrollTo().assertIsDisplayed()
        rule.onNode(hasScrollToIndexAction()).performScrollToNode(hasText("核对通道状态"))
        rule.onNodeWithText("核对通道状态").performScrollTo().assertHeightIsAtLeast(48.dp).performClick()
        rule.onNodeWithContentDescription("返回设置").assertHeightIsAtLeast(48.dp).performClick()
        rule.runOnIdle { assertEquals(1, refreshes); assertEquals(1, backs) }
    }
}
