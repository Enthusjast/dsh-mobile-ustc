package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.ClipboardManager
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.assertHeightIsAtLeast
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.longClick
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import cn.edu.ustc.dsh.session.BlockKind
import cn.edu.ustc.dsh.session.ConversationItem
import cn.edu.ustc.dsh.session.ConversationRole
import cn.edu.ustc.dsh.session.DisplayBlock
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ConversationMessageTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()

    @Test fun openStreamingMenuCopiesAndQuotesCurrentExactBlockTextsWithoutMetadata() {
        val item = mutableStateOf(message(listOf(DisplayBlock(BlockKind.TEXT, "old"))))
        val copies = mutableListOf<String>()
        val quotes = mutableListOf<String>()
        rule.setContent {
            val system = LocalClipboardManager.current
            val clipboard = remember(system) { object : ClipboardManager by system {
                override fun setText(annotatedString: AnnotatedString) { copies += annotatedString.text }
            } }
            CompositionLocalProvider(LocalClipboardManager provides clipboard) {
                DshTheme { ConversationMessage(item.value, onQuote = { quotes += it }) }
            }
        }
        rule.onNodeWithTag("conversation-message:message-1").assertExists()
        rule.onNodeWithText("助手").assertIsDisplayed()
        rule.onNodeWithContentDescription("更多消息操作").assertHeightIsAtLeast(48.dp).performClick()
        val blocks = listOf(
            DisplayBlock(BlockKind.TEXT, " \n**最新**🙂  \n"),
            DisplayBlock(BlockKind.REASONING, " hidden \n"),
            DisplayBlock(BlockKind.TOOL, "", name = "metadata-name", callId = "metadata-call-id"),
            DisplayBlock(BlockKind.OTHER, " raw ")
        )
        rule.runOnIdle { item.value = message(blocks) }
        rule.onNodeWithText("复制消息原文").assertHeightIsAtLeast(48.dp).performClick()
        rule.runOnIdle {
            assertEquals(listOf(" \n**最新**🙂  \n\n\n hidden \n\n\n\n\n raw "), copies)
            assertEquals(emptyList<String>(), quotes)
        }
        rule.onNodeWithContentDescription("更多消息操作").performClick()
        val newest = listOf(DisplayBlock(BlockKind.TEXT, "\n newest  "), DisplayBlock(BlockKind.REASONING, "\n"))
        rule.runOnIdle { item.value = message(newest) }
        rule.onNodeWithText("引用到本地草稿").assertHeightIsAtLeast(48.dp).performClick()
        rule.runOnIdle {
            assertEquals(listOf("\n newest  \n\n\n"), quotes)
            assertEquals(1, copies.size)
        }
    }

    @Test fun longPressOpensTheSameMenuAndClipboardFailureIsVisibleWithoutQuotePermission() {
        rule.setContent {
            val system = LocalClipboardManager.current
            val unavailable = remember(system) { object : ClipboardManager by system {
                override fun setText(annotatedString: AnnotatedString) { throw SecurityException("clipboard unavailable") }
            } }
            CompositionLocalProvider(LocalClipboardManager provides unavailable) {
                DshTheme { ConversationMessage(message(listOf(DisplayBlock(BlockKind.TEXT, "消息正文"))), onQuote = null) }
            }
        }
        rule.onNodeWithText("消息正文").performTouchInput { longClick() }
        rule.onNodeWithText("引用到本地草稿").assertDoesNotExist()
        rule.onNodeWithText("复制消息原文").assertIsDisplayed().performClick()
        rule.onNodeWithText("复制失败，请通过“更多”重试。").assertIsDisplayed()
        rule.onNodeWithContentDescription("更多消息操作").performClick()
        rule.onNodeWithText("复制消息原文").assertIsDisplayed()
    }

    @Test fun disclosuresExposeExpandedStateAndRetainCurrentRealDetailsAcrossDeltas() {
        val item = mutableStateOf(message(listOf(
            DisplayBlock(BlockKind.REASONING, "reasoning detail"),
            DisplayBlock(BlockKind.TOOL, "tool detail", name = "shell", callId = "call-1")
        )))
        rule.setContent { DshTheme { ConversationMessage(item.value, onQuote = null) } }
        rule.onNodeWithText("reasoning detail").assertDoesNotExist()
        rule.onNodeWithText("tool detail").assertDoesNotExist()
        rule.onNodeWithText("思考过程").assertHeightIsAtLeast(48.dp).performClick()
        assertEquals("已展开", rule.onNodeWithText("思考过程").fetchSemanticsNode().config[SemanticsProperties.StateDescription])
        rule.onNodeWithText("shell").assertHeightIsAtLeast(48.dp).performClick()
        assertEquals("已展开", rule.onNodeWithText("shell").fetchSemanticsNode().config[SemanticsProperties.StateDescription])
        rule.onNodeWithText("调用标识：call-1").assertIsDisplayed()
        rule.onNodeWithText("tool detail").assertIsDisplayed()
        rule.runOnIdle { item.value = message(listOf(
            DisplayBlock(BlockKind.REASONING, "reasoning detail latest"),
            DisplayBlock(BlockKind.TOOL, "tool detail latest", name = "shell", callId = "call-1")
        )) }
        rule.onNodeWithText("reasoning detail latest").assertIsDisplayed()
        rule.onNodeWithText("tool detail latest").assertIsDisplayed()
        rule.onNodeWithText("shell").performClick()
        assertEquals("已收起", rule.onNodeWithText("shell").fetchSemanticsNode().config[SemanticsProperties.StateDescription])
        rule.onNodeWithText("tool detail latest").assertDoesNotExist()
    }

    private fun message(blocks: List<DisplayBlock>) = ConversationItem(
        id = "message-1", role = ConversationRole.ASSISTANT, blocks = blocks, live = true, persisted = false
    )
}
