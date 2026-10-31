package cn.edu.ustc.dsh.mobile

import android.content.res.Configuration
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.width
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.command.CommandOwner
import cn.edu.ustc.dsh.ui.DshReadingStyle
import cn.edu.ustc.dsh.ui.DshTheme
import cn.edu.ustc.dsh.ui.LocalDshReadingStyle
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class AppearanceSettingsScreenTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val owner = CommandOwner(UUID.randomUUID().toString(), UUID.randomUUID().toString(), "a".repeat(64), UUID.randomUUID().toString(), UUID.randomUUID().toString())

    @After fun removeScalars() { context.deleteSharedPreferences("appearance-v1-${owner.fingerprint}") }

    @Test fun narrowDoubleSystemTextKeepsControlsReachableAndScalesIndependent() {
        val current = mutableStateOf(AppearanceState(persistence = AppearancePersistence.READY))
        rule.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, 2f)) {
                DshTheme {
                    Box(Modifier.width(320.dp).fillMaxHeight()) {
                        AppearanceSettingsContent(current.value, { current.value = AppearanceState(it, AppearancePersistence.SAVED) }, {}, {})
                    }
                }
            }
        }
        val list = rule.onNodeWithTag("appearance-settings-list")
        list.performScrollToNode(hasTestTag("appearance-theme-dark"))
        rule.onNodeWithTag("appearance-theme-dark").performClick().assertIsSelected()
        list.performScrollToNode(hasTestTag("appearance-body-larger"))
        val increaseBody = rule.onNodeWithTag("appearance-body-larger")
        val bounds = increaseBody.fetchSemanticsNode().boundsInRoot
        val minimum = with(rule.density) { 48.dp.toPx() }
        assertTrue(bounds.height >= minimum - 1f && bounds.width >= minimum - 1f)
        increaseBody.performClick()
        rule.runOnIdle {
            assertEquals(1.1f, current.value.preferences.bodyScale)
            assertEquals(1f, current.value.preferences.codeScale)
        }
        list.performScrollToNode(hasTestTag("appearance-code-larger"))
        rule.onNodeWithTag("appearance-code-larger").performClick()
        list.performScrollToNode(hasTestTag("appearance-wrap-code"))
        rule.onNodeWithTag("appearance-wrap-code").performClick().assertIsOn()
        rule.runOnIdle {
            assertEquals(1.1f, current.value.preferences.bodyScale)
            assertEquals(1.1f, current.value.preferences.codeScale)
        }
        list.performScrollToNode(hasTestTag("appearance-code-preview"))
        rule.onNodeWithTag("appearance-code-preview").assertIsDisplayed()
        list.performScrollToNode(hasTestTag("appearance-body-preview"))
        rule.onNodeWithTag("appearance-body-preview").assertIsDisplayed()
    }

    @Test fun failedReadCannotOverwritePreferencesAndFailedSaveHasExplicitRetry() {
        val current = mutableStateOf(AppearanceState(persistence = AppearancePersistence.READ_ERROR))
        var retried = false
        rule.setContent {
            DshTheme { AppearanceSettingsContent(current.value, {}, { retried = true }, {}) }
        }
        rule.onNodeWithText(context.getString(R.string.appearance_read_error)).assertIsDisplayed()
        rule.onNodeWithTag("appearance-settings-list").performScrollToNode(hasTestTag("appearance-theme-light"))
        rule.onNodeWithTag("appearance-theme-light").assertIsNotEnabled()
        rule.runOnIdle { current.value = AppearanceState(AppearancePreferences(theme = AppearanceTheme.DARK), AppearancePersistence.WRITE_ERROR) }
        rule.onNodeWithTag("appearance-settings-list").performScrollToNode(hasTestTag("appearance-persistence"))
        rule.onNodeWithText(context.getString(R.string.appearance_write_error)).assertIsDisplayed()
        rule.onNodeWithText(context.getString(R.string.appearance_retry_save)).performClick()
        rule.runOnIdle { assertTrue(retried) }
    }

    @Test fun scaleLimitsDisableOnlyTheMatchingDirection() {
        val current = mutableStateOf(AppearanceState(AppearancePreferences(bodyScale = MIN_READING_SCALE, codeScale = MAX_READING_SCALE), AppearancePersistence.READY))
        rule.setContent {
            DshTheme { AppearanceSettingsContent(current.value, { current.value = AppearanceState(it, AppearancePersistence.SAVED) }, {}, {}) }
        }
        val list = rule.onNodeWithTag("appearance-settings-list")
        list.performScrollToNode(hasTestTag("appearance-body-smaller"))
        rule.onNodeWithTag("appearance-body-smaller").assertIsNotEnabled()
        list.performScrollToNode(hasTestTag("appearance-code-larger"))
        rule.onNodeWithTag("appearance-code-larger").assertIsNotEnabled()
    }

    @Test fun hostAppliesSystemLightDarkAndReadingScalarsWithoutReplacingSystemFontScale() {
        val states = MutableStateFlow(HomeState(phase = HomePhase.READY, presentationOwner = owner))
        val nightMode = mutableStateOf(true)
        var observedFontScale = 0f
        var observedReading = DshReadingStyle()
        var session: AppearanceSession? = null
        rule.setContent {
            val configuration = Configuration(LocalConfiguration.current).apply {
                uiMode = (uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or
                    if (nightMode.value) Configuration.UI_MODE_NIGHT_YES else Configuration.UI_MODE_NIGHT_NO
            }
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, 2f), LocalConfiguration provides configuration) {
                AppearanceHost(states) {
                    val currentReading = LocalDshReadingStyle.current
                    val currentDensity = LocalDensity.current
                    val currentSession = LocalAppearanceSession.current
                    SideEffect {
                        observedFontScale = currentDensity.fontScale
                        observedReading = currentReading
                        session = currentSession
                    }
                    Text(if (MaterialTheme.colorScheme.background.luminance() < 0.5f) "dark-preview" else "light-preview")
                }
            }
        }
        rule.waitUntil { session?.state?.value?.persistence == AppearancePersistence.READY }
        rule.onNodeWithText("dark-preview").assertIsDisplayed()
        rule.runOnIdle { nightMode.value = false }
        rule.onNodeWithText("light-preview").assertIsDisplayed()
        rule.runOnIdle { runBlocking { session!!.save(AppearancePreferences(AppearanceTheme.DARK, 1.2f, 1.5f, true)) } }
        rule.onNodeWithText("dark-preview").assertIsDisplayed()
        rule.runOnIdle {
            assertEquals(2f, observedFontScale)
            assertEquals(DshReadingStyle(1.2f, 1.5f, true), observedReading)
            runBlocking { session!!.save(AppearancePreferences(theme = AppearanceTheme.LIGHT)) }
            nightMode.value = true
        }
        rule.onNodeWithText("light-preview").assertIsDisplayed()
        rule.runOnIdle { states.value = HomeState(phase = HomePhase.SIGNED_OUT) }
        rule.waitUntil { session == null }
        rule.onNodeWithText("dark-preview").assertIsDisplayed()
        rule.runOnIdle {
            assertEquals(DshReadingStyle(), observedReading)
            assertEquals(2f, observedFontScale)
        }
    }
}
