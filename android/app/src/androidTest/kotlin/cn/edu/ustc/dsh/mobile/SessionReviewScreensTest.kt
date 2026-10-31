package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.ui.DshTheme
import java.util.Base64
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SessionReviewScreensTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private val id = "11111111-1111-4111-8111-111111111111"
    private val other = "22222222-2222-4222-8222-222222222222"
    private fun text(resource: Int) = rule.activity.getString(resource)
    private fun reveal(label: String) { rule.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(label)) }
    private fun preview(message: String?) = SessionMessagePreview.parse(jsonObject("v" to 1L.json(),
        "anchor" to SessionForkAnchor(id, other, 8, "a".repeat(64), "b".repeat(64)).json(),
        "text" to (message?.json() ?: JsonNull), "shareable" to JsonBoolean(message != null), "complete" to JsonBoolean(true)))

    @Test fun partialPatchCannotBeCopiedAsCompleteAndRetryAndBackStayReachable() {
        val body = "diff --git a/a b/a\n--- a/a\n"
        val path = jsonObject("bytes_base64" to "YQ==".json(), "display" to "a".json())
        val file = SessionChangeFile.parse(jsonObject("file_id" to id.json(), "status" to "modified".json(),
            "old_path" to path, "new_path" to path, "old_mode" to "100644".json(), "new_mode" to "100644".json(),
            "kind" to "text".json(), "patch_bytes" to 100L.json(), "complete" to JsonBoolean(true), "copyable" to JsonBoolean(false)))
        val patch = SessionChangesPatch(other, other, id, "a".repeat(64), "text", false, false, true,
            Base64.getEncoder().encodeToString(body.toByteArray()), body, emptyList(), other)
        val state = SessionChangesState(SessionChangesPhase.READY, listOf(file),
            SessionChangesManifest("a".repeat(40), "a".repeat(64), "b".repeat(64), System.currentTimeMillis() + 30_000, other),
            patch, patchHasMore = true)
        rule.setContent { DshTheme { SessionChangesScreen(state, {}, {}, {}, {}, {},
            { fail("A fragment must never be copied as a complete patch") }, {}) } }
        val copy = text(R.string.changes_fork_copy_complete)
        reveal(copy)
        rule.onNodeWithText(copy).assertIsNotEnabled()
        rule.onNodeWithContentDescription(text(R.string.changes_fork_back)).assertIsDisplayed()
        captureUiFixture(rule, "review-partial-patch", darkTheme = false)
    }

    @Test fun attachmentOnlyPreviewCannotShareAndForkStillRequiresSeparateConfirmation() {
        val selected = preview(null)
        val state = SessionMessageActionState(SessionMessageActionPhase.READY, selected, canFork = true, canPreview = true)
        var forks = 0
        rule.setContent { DshTheme { SessionMessageActionPreview(state, null, { forks++ },
            { fail("An attachment-only message has no shareable text") }, {}, {}, {}) } }
        reveal(text(R.string.changes_fork_share_action))
        rule.onNodeWithText(text(R.string.changes_fork_share_action)).assertIsNotEnabled()
        reveal(text(R.string.changes_fork_new_child))
        rule.onNodeWithText(text(R.string.changes_fork_new_child)).assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(0, forks) }
        rule.onNodeWithText(text(R.string.changes_fork_cancel)).performClick()
        rule.runOnIdle { assertEquals(0, forks) }
        reveal(text(R.string.changes_fork_new_child))
        rule.onNodeWithText(text(R.string.changes_fork_new_child)).performClick()
        rule.onNodeWithText(text(R.string.changes_fork_confirm_action)).performClick()
        rule.runOnIdle { assertEquals(1, forks) }
    }

    @Test fun anUnresolvedOriginalCannotExposeASecondForkAction() {
        val selected = preview("actual visible text only")
        val state = SessionMessageActionState(SessionMessageActionPhase.READY, selected, canFork = true,
            originalRequestId = id, canPreview = true)
        rule.setContent { DshTheme { SessionMessageActionPreview(state, null,
            { fail("Unknown original must be queried, not forked again") }, {}, {}, {}, {}) } }
        reveal(text(R.string.changes_fork_query_original))
        rule.onNodeWithText(text(R.string.changes_fork_query_original)).assertIsEnabled()
        rule.onNodeWithText(text(R.string.changes_fork_new_child)).assertDoesNotExist()
        captureUiFixture(rule, "review-original-unknown", dialog = true, darkTheme = false)
    }
}
