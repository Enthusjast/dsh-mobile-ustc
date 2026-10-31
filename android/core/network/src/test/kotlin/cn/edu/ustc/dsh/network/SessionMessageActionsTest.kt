package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.command.CommandDataException
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.util.UUID

class SessionMessageActionsTest {
    private fun id() = UUID.randomUUID().toString()
    private val binding = SessionActionBinding(id(), id(), id(), id(), id())
    private val capabilities = setOf("session.read.v1", SESSION_MESSAGE_ACTIONS_CAPABILITY)
    private val anchor = SessionForkAnchor(binding.subscriptionId, binding.syncId, 0, "a".repeat(64), "b".repeat(64))
    private fun record(seq: Long, text: String, replacement: Boolean = false): JsonObject {
        val raw = jsonObject("native_seq" to seq.json(), "time" to 0L.json(), "type" to "user/message".json(),
            "data" to jsonObject("content" to JsonArray(listOf(jsonObject("type" to "text".json(), "text" to text.json())))))
        return if (!replacement) raw else raw.with("surface_op" to jsonObject("op" to "replace".json(), "startSeq" to 0L.json(), "endSeq" to 0L.json()))
    }
    private fun transcript(text: String = "正文", append: Boolean = false, replacement: Boolean = false, persisted: Boolean = true): SessionTranscript {
        val request = id(); val window = SessionWindow(request)
        val records = listOf(record(0, text)) + if (append || replacement) listOf(record(1, "另一条", replacement)) else emptyList()
        window.accept(SessionContent("session.snapshot", request, binding.syncId, jsonObject("cursor" to (records.size - 1).toLong().json(),
            "has_more" to JsonBoolean(false), "records" to JsonArray(records), "assistant" to JsonNull)))
        if (persisted) window.accept(SessionContent("session.checkpoint", request, binding.syncId, jsonObject("state" to "persisted".json(), "through_seq" to (records.size - 1).toLong().json())))
        return window.snapshot()
    }
    private fun result(query: JsonObject, text: String? = "正文", selected: SessionForkAnchor = anchor): JsonObject = query.with(
        "type" to "session.message.preview.result".json(), "sync_id" to binding.syncId.json(), "payload" to jsonObject(
            "v" to 1L.json(), "anchor" to selected.json(), "text" to (text?.json() ?: JsonNull), "shareable" to JsonBoolean(!text.isNullOrEmpty()), "complete" to JsonBoolean(true)))
    private fun ready(actions: SessionMessageActions, sends: MutableList<JsonObject>, snapshot: SessionTranscript = transcript()) {
        actions.connected(capabilities, true); actions.ready(binding, snapshot, false, { true }) { sends += it }
    }
    @Test fun onlyExactPersistedVisibleMessageCanNominateNativeSequence(): Unit = runBlocking {
        val sends = arrayListOf<JsonObject>()
        SessionMessageActions(null, null).use { actions ->
            ready(actions, sends, transcript(persisted = false)); assertTrue(sends.isEmpty())
            assertThrows(CommandDataException::class.java) { runBlocking { actions.previewMessage("event:0") } }
            actions.ready(binding, transcript(), false, { true }) { sends += it }
            for (bad in listOf("0", "copied:event:0", "live:0", "event:99")) assertThrows(CommandDataException::class.java) { runBlocking { actions.previewMessage(bad) } }
            assertTrue(actions.previewMessage("event:0")); assertEquals(0L, sends.single().obj("payload").integer("native_seq", 0))
            assertFalse(actions.preview(0)); actions.accept(result(sends.single())); assertEquals(anchor, actions.state.value.preview!!.anchor)
        }
    }
    @Test fun chooserAuthorityRequiresActualExactConfirmationAndTracksCurrentMessageVersion(): Unit = runBlocking {
        val sends = arrayListOf<JsonObject>()
        SessionMessageActions(null, null).use { actions ->
            ready(actions, sends); actions.previewMessage("event:0"); actions.accept(result(sends.last()))
            val awaiting = async(start = CoroutineStart.UNDISPATCHED) { actions.confirmShare(anchor) }
            assertEquals("session.message.preview.confirm", sends.last().string("type")); assertFalse(awaiting.isCompleted)
            assertTrue(actions.accept(result(sends.last())))
            val share = awaiting.await(); assertEquals("正文", share.text); assertTrue(share.current())
            actions.ready(binding, transcript(append = true), false, { true }) { sends += it }; assertTrue(share.current())
            actions.ready(binding, transcript(text = "正文改版"), false, { true }) { sends += it }; assertFalse(share.current())
            assertEquals(SessionMessageActionPhase.STALE, actions.state.value.phase); assertNull(actions.state.value.preview)
        }
    }
    @Test fun cancellationDismissReplacementAndRevocationRetireConfirmedAuthority(): Unit = runBlocking {
        val sends = arrayListOf<JsonObject>()
        SessionMessageActions(null, null).use { actions ->
            ready(actions, sends); actions.preview(0); actions.accept(result(sends.last()))
            val cancelled = async(start = CoroutineStart.UNDISPATCHED) { actions.confirmShare(anchor) }
            val late = result(sends.last()); cancelled.cancelAndJoin(); assertFalse(actions.accept(late)); assertFalse(actions.state.value.busy)
            val awaiting = async(start = CoroutineStart.UNDISPATCHED) { actions.confirmShare(anchor) }
            actions.accept(result(sends.last())); val share = awaiting.await(); assertTrue(share.current())
            actions.dismiss(); assertFalse(share.current()); assertNull(actions.state.value.preview); assertTrue(actions.canPreview)
            actions.preview(0); actions.accept(result(sends.last()))
            val second = async(start = CoroutineStart.UNDISPATCHED) { actions.confirmShare(anchor) }
            actions.accept(result(sends.last())); val replaced = second.await()
            actions.ready(binding, transcript(replacement = true), false, { true }) { sends += it }; assertFalse(replaced.current())
            actions.disconnected("access.revoked"); assertFalse(actions.canPreview); assertEquals(SessionMessageActionPhase.DENIED, actions.state.value.phase)
        }
    }
    @Test fun textlessPreviewIsForkAnchorOnlyAndWrongConfirmationNeverMintsShare(): Unit = runBlocking {
        val sends = arrayListOf<JsonObject>()
        SessionMessageActions(null, null).use { actions ->
            ready(actions, sends); actions.preview(0); actions.accept(result(sends.last(), null))
            assertEquals(anchor, actions.state.value.preview!!.anchor); assertFalse(actions.state.value.preview!!.shareable)
            assertThrows(CommandDataException::class.java) { runBlocking { actions.confirmShare(anchor) } }; assertEquals(1, sends.size)
            actions.dismiss(); actions.preview(0); actions.accept(result(sends.last()))
            val awaiting = async(start = CoroutineStart.UNDISPATCHED) { runCatching { actions.confirmShare(anchor) } }
            val wrong = anchor.copy(messageVersionSha256 = "c".repeat(64))
            assertTrue(actions.accept(result(sends.last(), selected = wrong))); assertTrue(awaiting.await().isFailure)
            assertEquals(SessionMessageActionPhase.STALE, actions.state.value.phase)
        }
    }
    @Test fun deadlineAndOuterErrorsNeverRetryOrAcceptOtherReaderReplies(): Unit = runBlocking {
        var nano = 1L; val sends = arrayListOf<JsonObject>()
        SessionMessageActions(null, null, { nano }, 1).use { actions ->
            ready(actions, sends); actions.preview(0); val response = result(sends.last())
            for (key in listOf("request_id", "runtime_id", "runtime_epoch", "session_id", "subscription_id", "sync_id")) assertFalse(actions.accept(response.with(key to id().json())))
            nano += 1_000_000; actions.tick(); assertEquals("network.message_timeout", actions.state.value.error); assertFalse(actions.accept(response)); assertEquals(1, sends.size)
            actions.preview(0)
            assertTrue(actions.error(sends.last(), "access.denied")); assertEquals(SessionMessageActionPhase.DENIED, actions.state.value.phase); assertFalse(actions.canPreview)
        }
    }
}
