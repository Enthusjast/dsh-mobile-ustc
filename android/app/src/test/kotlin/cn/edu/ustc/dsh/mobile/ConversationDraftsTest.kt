package cn.edu.ustc.dsh.mobile

import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.TextFieldValue
import cn.edu.ustc.dsh.command.CommandOwner
import org.junit.Assert.*
import org.junit.Test

class ConversationDraftsTest {
    private val id = "11111111-1111-4111-8111-111111111111"
    private val other = "22222222-2222-4222-8222-222222222222"
    private fun owner(account: String = id, deployment: String = "a".repeat(64)) = CommandOwner(account, id, deployment, id, id)
    private fun resource(account: String = id, host: String = id, runtime: String = id, session: String = id) = ConversationResource(owner(account), host, runtime, session)

    @Test fun compactAndExpandedEditorsShareValueSelectionCompositionModeAndRevision() {
        val drafts = ConversationDrafts()
        val original = drafts.open(resource())
        val editing = TextFieldValue("中文候选🙂", TextRange(2), TextRange(0, 2))
        val next = drafts.edit(original.copy(value = editing, mode = "steer"))!!
        assertEquals(editing, drafts.open(resource()).value)
        assertEquals("steer", next.mode)
        assertTrue(next.revision > original.revision)
        assertNull(drafts.edit(original.copy(value = TextFieldValue("old callback"))))
    }

    @Test fun aSavedOriginalCannotClearANewerRevisionOrAnotherResource() {
        val drafts = ConversationDrafts()
        val original = drafts.edit(drafts.open(resource()).copy(value = TextFieldValue("original")))!!
        val submitted = MessageSubmission(original, true)
        val newer = drafts.edit(original.copy(value = TextFieldValue("new draft")))!!
        val another = drafts.edit(drafts.open(resource(session = other)).copy(value = TextFieldValue("other resource")))!!
        assertNull(drafts.saved(submitted.draft))
        assertEquals(newer, drafts.current(newer.resource))
        assertEquals(another, drafts.current(another.resource))
        val cleared = drafts.saved(newer)!!
        assertEquals("", cleared.value.text)
        assertEquals("queue", cleared.mode)
        assertNull(drafts.saved(newer))
    }

    @Test fun equalAcceptedOwnersShareOnlyTheSameExactHostRuntimeAndSession() {
        val drafts = ConversationDrafts()
        val original = drafts.edit(drafts.open(resource()).copy(value = TextFieldValue("private")))!!
        assertSame(original, drafts.open(resource()))
        listOf(resource(account = other), resource(host = other), resource(runtime = other), resource(session = other),
            ConversationResource(owner(deployment = "b".repeat(64)), id, id, id)).forEach { assertEquals("", drafts.open(it).value.text) }
    }

    @Test fun backgroundClearsEveryOrdinaryDraftAndOnlyTheCurrentPickerExceptionSurvives() {
        val drafts = ConversationDrafts()
        val first = drafts.edit(drafts.open(resource()).copy(value = TextFieldValue("first")))!!
        val picker = drafts.edit(drafts.open(resource(session = other)).copy(value = TextFieldValue("picker"), mode = "steer"))!!
        drafts.clear(picker)
        assertNull(drafts.current(first.resource))
        assertEquals(picker, drafts.open(picker.resource))
        drafts.clear()
        assertNull(drafts.current(picker.resource))
        assertNull(drafts.saved(first))
        assertNull(drafts.edit(picker))
        assertEquals("", drafts.open(picker.resource).value.text)
    }

    @Test fun foregroundCacheIsBoundedAndAuthorityRetirementRemovesEveryRuntimeDraft() {
        val drafts = ConversationDrafts(maxEntries = 2, maxCharacters = 8)
        val first = drafts.edit(drafts.open(resource()).copy(value = TextFieldValue("1234")))!!
        drafts.edit(drafts.open(resource(session = other)).copy(value = TextFieldValue("5678")))
        val keep = drafts.edit(drafts.open(resource(host = other)).copy(value = TextFieldValue("abcd")))!!
        assertNull(drafts.current(first.resource))
        assertEquals("abcd", drafts.current(keep.resource)!!.value.text)
        drafts.revokeRuntime(id)
        assertNull(drafts.current(keep.resource))
    }

    @Test fun localQuoteIsEditableTextOnlyAndPreservesItsSourceExactly() {
        val draft = MessageComposerState(resource(), TextFieldValue("before"), "steer", 9)
        val quote = draft.withLocalQuote("  code\n\n尾行\n")
        assertEquals("before\n\n>   code\n> \n> 尾行\n> \n\n", quote.value.text)
        assertEquals(TextRange(quote.value.text.length), quote.value.selection)
        assertEquals(draft.revision, quote.revision)
        assertEquals(draft.mode, quote.mode)
    }
    @Test fun failedSaveKeepsNewTextUntilTheUserChoosesToRestoreTheOriginal() {
        val drafts = ConversationDrafts()
        val original = drafts.edit(drafts.open(resource()).copy(value = TextFieldValue("原来的候选", TextRange(2), TextRange(0, 2)), mode = "steer"))!!
        val newer = drafts.edit(original.copy(value = TextFieldValue("保存期间继续输入"), mode = "queue"))!!
        val failed = drafts.retainFailed(original)!!
        assertSame(newer, drafts.current(newer.resource))
        assertNull(failed.value.composition)
        assertSame(newer, drafts.resolveFailure(failed, restore = false))
        assertNull(drafts.recoverable(newer.resource))
        val retry = drafts.retainFailed(original)!!
        val restored = drafts.resolveFailure(retry, restore = true)!!
        assertEquals(original.value.text, restored.value.text)
        assertEquals(original.value.selection, restored.value.selection)
        assertEquals("steer", restored.mode)
        assertTrue(restored.revision > newer.revision)
        assertNull(drafts.resolveFailure(retry, restore = true))
    }

    @Test fun recoveryNeverSurvivesBackgroundOrRuntimeRevocationOrLeaksToAnotherOwner() {
        for (revoke in listOf(false, true)) {
            val drafts = ConversationDrafts()
            val original = drafts.edit(drafts.open(resource()).copy(value = TextFieldValue("sensitive original")))!!
            drafts.edit(original.copy(value = TextFieldValue("current")))
            val failed = drafts.retainFailed(original)!!
            assertNull(drafts.recoverable(resource(account = other)))
            if (revoke) drafts.revokeRuntime(id) else drafts.clear()
            assertNull(drafts.recoverable(original.resource))
            assertNull(drafts.resolveFailure(failed, restore = true))
            assertEquals("", drafts.open(original.resource).value.text)
        }
    }

    @Test fun recoverySharesTheForegroundBudgetAndCannotEvictTheCurrentInput() {
        val drafts = ConversationDrafts(maxEntries = 2, maxCharacters = 8)
        val older = drafts.edit(drafts.open(resource(session = other)).copy(value = TextFieldValue("old!")))!!
        val original = drafts.edit(drafts.open(resource()).copy(value = TextFieldValue("1234")))!!
        val current = drafts.edit(original.copy(value = TextFieldValue("5678")))!!
        assertNotNull(drafts.retainFailed(original))
        assertNull(drafts.current(older.resource))
        assertSame(current, drafts.current(current.resource))
        drafts.dismissFailure()
        val larger = drafts.edit(current.copy(value = TextFieldValue("56789")))!!
        assertNull(drafts.retainFailed(original))
        assertSame(larger, drafts.current(larger.resource))
    }
}
