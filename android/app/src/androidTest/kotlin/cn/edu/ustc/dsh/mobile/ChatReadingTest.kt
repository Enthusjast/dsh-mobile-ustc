package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Column
import androidx.compose.ui.Modifier
import android.os.ParcelFileDescriptor
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.UriHandler
import androidx.compose.ui.semantics.SemanticsActions
import org.junit.Assert.assertEquals
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.*
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ChatReadingTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private val id = "11111111-1111-4111-8111-111111111111"
    private val request = "22222222-2222-4222-8222-222222222222"

    private fun transcript(start: Int, end: Int): SessionTranscript {
        val records = (start..end).map { seq ->
            jsonObject("native_seq" to seq.toLong().json(), "time" to 1000L.json(), "type" to "user/message".json(),
                "surface_op" to "append".json(), "data" to jsonObject("content" to JsonArray(listOf(
                    jsonObject("type" to "text".json(), "text" to "message $seq".json())))))
        }
        return SessionWindow(request).apply {
            accept(SessionContent("session.snapshot", request, id, jsonObject("cursor" to end.toLong().json(), "has_more" to JsonBoolean(start > 0), "assistant" to JsonNull, "records" to JsonArray(records))))
            accept(SessionContent("session.checkpoint", request, id, jsonObject("state" to "persisted".json(), "through_seq" to end.toLong().json())))
        }.snapshot()
    }
    private fun state(transcript: SessionTranscript) = HomeState(HomePhase.READY, selectedRuntimeId = id, selectedSessionId = id,
        reader = SessionReadState(SessionReadPhase.READY, transcript))

    @Test fun incomingMessagesDoNotInterruptHistoryAndLatestButtonReturnsToBottom() {
        val current = mutableStateOf(state(transcript(0, 40)))
        rule.setContent { DshTheme { SessionsScreen(current.value, {}, {}, {}, {}, {}) } }
        val image = rule.onRoot().captureToImage().asAndroidBitmap()
        val directory = File(InstrumentationRegistry.getInstrumentation().targetContext.filesDir, "ui-navigation-fixtures").apply { mkdirs() }
        File(directory, "chat-reading.png").outputStream().use { check(image.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)) }
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        val packageName = InstrumentationRegistry.getInstrumentation().targetContext.packageName
        ParcelFileDescriptor.AutoCloseInputStream(automation.executeShellCommand("dumpsys gfxinfo $packageName reset")).use { it.readBytes() }
        rule.onNodeWithText("message 40").assertIsDisplayed()
        rule.onNodeWithTag("chat-list").performScrollToNode(hasText("message 20"))
        rule.onNodeWithText("message 20").assertIsDisplayed()
        rule.runOnIdle { current.value = state(transcript(0, 41)) }
        rule.onNodeWithText("message 20").assertIsDisplayed()
        rule.onNodeWithText("有新消息 · 回到最新").assertIsDisplayed().performClick()
        rule.onNodeWithText("message 41").assertIsDisplayed()
        repeat(5) {
            rule.onNodeWithTag("chat-list").performScrollToNode(hasText("message 20"))
            rule.onNodeWithTag("chat-list").performScrollToNode(hasText("message 40"))
        }
        ParcelFileDescriptor.AutoCloseInputStream(automation.executeShellCommand("dumpsys gfxinfo $packageName framestats")).use { input ->
            File(directory, "chat-frame-sample.txt").outputStream().use(input::copyTo)
        }
    }

    @Test fun earlierRecordsDoNotMoveTheCurrentMessageAnchor() {
        val current = mutableStateOf(state(transcript(20, 40)))
        rule.setContent { DshTheme { SessionsScreen(current.value, {}, {}, {}, {}, {}) } }
        rule.onNodeWithTag("chat-list").performScrollToNode(hasText("message 25"))
        rule.onNodeWithText("message 25").assertIsDisplayed()
        rule.runOnIdle { current.value = state(transcript(0, 40)) }
        rule.onNodeWithText("message 25").assertIsDisplayed()
        rule.onNodeWithText("有新消息 · 回到最新").assertDoesNotExist()
    }
    @Test fun expandedLongContentStaysVisibleWhenStreamingContinues() {
        val text = mutableStateOf("x".repeat(17_000) + "END")
        rule.setContent { DshTheme { Column(Modifier.verticalScroll(rememberScrollState())) { RichMessageText(text.value) } } }
        rule.onNodeWithText("END", substring = true).assertDoesNotExist()
        rule.onNodeWithText("继续显示").performScrollTo().performClick()
        rule.onNodeWithText("END", substring = true).assertExists()
        rule.runOnIdle { text.value += "-MORE" }
        rule.onNodeWithText("END-MORE", substring = true).assertExists()
    }
    @Test fun externalLinkNeverOpensBeforeExplicitConfirmation() {
        val target = "https://example.invalid/path"
        var opened: String? = null
        rule.setContent {
            CompositionLocalProvider(LocalUriHandler provides object : UriHandler { override fun openUri(uri: String) { opened = uri } }) {
                DshTheme { RichMessageText(target) }
            }
        }
        val directory = File(InstrumentationRegistry.getInstrumentation().targetContext.filesDir, "ui-navigation-fixtures").apply { mkdirs() }
        File(directory, "link-semantics.txt").writeText(rule.onRoot(useUnmergedTree = true).printToString())
        val actions = rule.onNodeWithText(target).fetchSemanticsNode().config[SemanticsActions.CustomActions]
        assertEquals("打开外部链接：$target", actions.single().label)
        rule.runOnIdle { actions.single().action() }
        rule.onNodeWithText("打开外部链接？").assertIsDisplayed()
        rule.onNodeWithText("取消").performClick()
        rule.runOnIdle { assertEquals(null, opened) }
        rule.onNodeWithText(target).performTouchInput { click() }
        rule.onNodeWithText("打开外部链接？").assertIsDisplayed()
        rule.runOnIdle { assertEquals(null, opened) }
        rule.onNodeWithText("取消").performClick()
        rule.runOnIdle { assertEquals(null, opened) }
        rule.onNodeWithText(target).performTouchInput { click() }
        rule.onNodeWithText("打开链接").performClick()
        rule.runOnIdle { assertEquals(target, opened) }
    }
}
