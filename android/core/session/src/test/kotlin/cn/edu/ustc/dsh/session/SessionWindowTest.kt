package cn.edu.ustc.dsh.session

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class SessionWindowTest {
    private val request = "66666666-6666-4666-8666-666666666666"
    private val sync = "77777777-7777-4777-8777-777777777777"
    private val page = "88888888-8888-4888-8888-888888888888"
    private fun record(seq: Long, type: String = "cursor", data: JsonObject = jsonObject(), surface: JsonValue? = null): JsonObject {
        var root = jsonObject("native_seq" to seq.json(), "time" to 1000L.json(), "type" to type.json(), "data" to data)
        if (surface != null) root = root.with("surface_op" to surface)
        return root
    }
    private fun user(seq: Long, text: String = "hello") = record(seq, "user/message", jsonObject("id" to "message-$seq".json(), "content" to JsonArray(listOf(jsonObject("type" to "text".json(), "text" to text.json())))), "append".json())
    private fun assistant(seq: Long, text: String = "complete") = record(seq, "assistant/message", jsonObject("turn" to 1L.json(), "step" to 1L.json(), "message" to jsonObject("content" to JsonArray(listOf(jsonObject("type" to "text".json(), "text" to text.json()))))), "append".json())
    private fun content(type: String, payload: JsonObject, requestId: String = request, syncId: String = sync) = SessionContent(type, requestId, syncId, payload)
    private fun snapshot(records: List<JsonValue> = listOf(record(0), user(1)), cursor: Long = 1, baseline: JsonValue = jsonObject("revision" to 0L.json()), more: Boolean = false) = content("session.snapshot", jsonObject("cursor" to cursor.json(), "has_more" to JsonBoolean(more), "records" to JsonArray(records), "assistant" to baseline))
    private fun started(revision: Long = 1) = content("assistant.start", jsonObject("type" to "start".json(), "attemptId" to "attempt".json(), "revision" to revision.json(), "startedAfterSeq" to 1L.json(), "turn" to 1L.json(), "step" to 1L.json()))
    private fun chunk(revision: Long, index: Long, text: String) = content("assistant.chunk", jsonObject("type" to "chunk".json(), "attemptId" to "attempt".json(), "revision" to revision.json(), "index" to index.json(), "time" to 1000L.json(), "chunk" to jsonObject("type" to "text-delta".json(), "index" to 0L.json(), "text" to text.json())))
    private fun ended(revision: Long, index: Long, outcome: JsonObject) = content("assistant.end", jsonObject("type" to "end".json(), "attemptId" to "attempt".json(), "revision" to revision.json(), "index" to index.json(), "outcome" to outcome))

    @Test fun sharedGoldenAndLargeDisplayPayloadsKeepSigningBudgetsIndependent() {
        val frame = JsonDocument.parse(File(System.getProperty("contracts.root"), "ws/v1/golden/session-snapshot.json").readBytes()).root
        val route = SessionRoute(frame.string("runtime_id"), frame.string("runtime_epoch"), frame.string("session_id"), frame.string("subscription_id"))
        val window = SessionWindow(frame.string("request_id")); window.accept(SessionFragments(route).accept(frame)!!)
        assertEquals("中文🙂", window.snapshot().items.single().blocks.single().text)
        val large = "{\"text\":\"" + "中🙂".repeat(40_000) + "\"}"
        assertTrue(large.toByteArray().size > JsonDocument.MAX_BYTES)
        assertEquals("中🙂".repeat(40_000), SessionJson.parse(large.toByteArray()).string("text"))
        assertThrows(ProtocolException::class.java) { JsonDocument.parse(large) }
        for (bad in listOf("{\"x\":null,\"x\":1}", "{\"x\":01}", "{\"x\":\"\\ud800\"}")) assertThrows(SessionDataException::class.java) { SessionJson.parse(bad.toByteArray()) }
        assertThrows(SessionDataException::class.java) { SessionJson.parse(ByteArray(SESSION_PAYLOAD_BYTES + 1)) }
    }
    @Test fun nativePositionsDeduplicateButChangedFactsAndGapsRequireReplacement() {
        val window = SessionWindow(request); window.accept(snapshot())
        assertFalse(window.accept(content("session.event", user(1))))
        assertThrows(SessionDataException::class.java) { window.accept(content("session.event", user(1, "changed"))) }
        assertThrows(SessionDataException::class.java) { window.accept(content("session.event", record(3))) }
        assertEquals(1L, window.snapshot().cursor)
        window.accept(content("session.event", record(2)))
        assertThrows(SessionDataException::class.java) { window.accept(snapshot(listOf(record(3), user(5)), 5)) }
        assertEquals(2L, window.snapshot().cursor)
    }
    @Test fun aDurableSettlementReplacesItsLiveAttemptOnlyAfterTheMatchingEnd() {
        val window = SessionWindow(request); window.accept(snapshot()); window.accept(started()); window.accept(chunk(2, 0, "partial"))
        window.accept(content("assistant.chunk", jsonObject("type" to "chunk".json(), "attemptId" to "attempt".json(), "revision" to 3L.json(), "index" to 1L.json(), "time" to 1000L.json(),
            "chunk" to jsonObject("type" to "block-end".json(), "index" to 0L.json(), "block" to jsonObject("type" to "text".json(), "text" to "complete".json())))))
        window.accept(content("session.event", assistant(2)))
        assertEquals(1, window.snapshot().items.count { it.role == ConversationRole.ASSISTANT })
        assertTrue(window.snapshot().items.last().live); assertEquals("complete", window.snapshot().items.last().blocks.single().text)
        assertNotNull(window.settlementMillis())
        window.accept(content("session.checkpoint", jsonObject("state" to "persisted".json(), "through_seq" to 2L.json())))
        assertEquals(1, window.snapshot(durableOnly = true).items.size)
        val cached = CachedTranscript(sync, 1000, window.snapshot(durableOnly = true).records)
        assertEquals(1L, cached.transcript.cursor)
        assertEquals(1, cached.transcript.items.size)
        assertFalse(cached.transcript.taskRunning)
        assertFalse(cached.transcript.items.any { it.live })
        assertTrue(window.settlementMillis(System.nanoTime() + 11_000_000_000) == 0L)
        window.accept(ended(4, 2, jsonObject("kind" to "committed".json(), "eventType" to "assistant/message".json(), "seq" to 2L.json())))
        assertEquals(1, window.snapshot().items.count { it.role == ConversationRole.ASSISTANT })
        assertEquals("event:2", window.snapshot().items.last().id); assertFalse(window.snapshot().items.last().live)
        assertEquals(2, window.snapshot(durableOnly = true).items.size)
    }
    @Test fun revisionIndexAndSettlementGapsCannotSilentlyAppend() {
        val window = SessionWindow(request); window.accept(snapshot()); window.accept(started())
        val first = chunk(2, 0, "one"); window.accept(first); window.accept(first)
        assertEquals("one", window.snapshot().items.last().blocks.single().text)
        assertThrows(SessionDataException::class.java) { window.accept(chunk(4, 1, "gap")) }
        val next = SessionWindow(request); next.accept(snapshot()); next.accept(started())
        assertThrows(SessionDataException::class.java) { next.accept(chunk(2, 1, "missing")) }
        val missing = SessionWindow(request); missing.accept(snapshot()); missing.accept(started())
        assertThrows(SessionDataException::class.java) { missing.accept(ended(2, 0, jsonObject("kind" to "committed".json(), "eventType" to "assistant/message".json(), "seq" to 2L.json()))) }
    }
    @Test fun compactOpeningRestoresTheExactDenseIndexBeforeContinuing() {
        val baseline = jsonObject("revision" to 7L.json(), "activeAttempt" to jsonObject("attemptId" to "attempt".json(), "startedAfterSeq" to 1L.json(), "turn" to 1L.json(), "step" to 1L.json(), "nextIndex" to 3L.json(),
            "stream" to JsonArray(listOf(jsonObject("type" to "chunk".json(), "time" to 1000L.json(), "chunk" to jsonObject("type" to "block-start".json(), "index" to 0L.json(), "blockType" to "text".json())),
                jsonObject("type" to "text-chunks".json(), "time0" to 1000L.json(), "index" to 0L.json(), "dt" to JsonArray(listOf(1L.json())), "texts" to JsonArray(listOf("中".json(), "文".json())))))))
        val window = SessionWindow(request); window.accept(snapshot(baseline = baseline)); window.accept(chunk(8, 3, "🙂"))
        assertEquals("中文🙂", window.snapshot().items.last().blocks.single().text)
        val bad = baseline.with("activeAttempt" to baseline.obj("activeAttempt").with("nextIndex" to 4L.json()))
        assertThrows(SessionDataException::class.java) { SessionWindow(request).accept(snapshot(baseline = bad)) }
    }
    @Test fun abandonmentRetiresTransientRowsAndUnknownAttemptSettlementsStayVisible() {
        val window = SessionWindow(request); window.accept(snapshot()); window.accept(started()); window.accept(chunk(2, 0, "transient")); window.accept(ended(3, 1, jsonObject("kind" to "abandoned".json())))
        assertEquals(1, window.snapshot().items.size)
        val unknown = SessionWindow(request); unknown.accept(snapshot()); unknown.accept(chunk(1, 5, "missed start")); unknown.accept(content("session.event", assistant(2)))
        unknown.accept(ended(2, 6, jsonObject("kind" to "committed".json(), "eventType" to "assistant/message".json(), "seq" to 2L.json())))
        assertEquals("complete", unknown.snapshot().items.last().blocks.single().text)
    }
    @Test fun persistenceMayLeadObservationButCannotRegress() {
        val window = SessionWindow(request); window.accept(snapshot()); assertFalse(window.snapshot().items.single().persisted)
        window.accept(content("session.checkpoint", jsonObject("state" to "persisted".json(), "through_seq" to 4L.json()))); window.accept(content("session.event", user(2)))
        assertTrue(window.snapshot().items.all { it.persisted })
        assertThrows(SessionDataException::class.java) { window.accept(content("session.checkpoint", jsonObject("state" to "persisted".json(), "through_seq" to 3L.json()))) }
        window.accept(content("session.checkpoint", jsonObject("state" to "failed".json())))
        assertEquals(4L, window.snapshot().persistedThrough); assertEquals("failed", window.snapshot().checkpoint)
    }
    @Test fun pagesKeepTheOpeningCursorWhileLiveEventsAdvance() {
        val window = SessionWindow(request); window.accept(snapshot(listOf(user(4), record(5)), 5, more = true))
        val older = window.page(page)!!; assertEquals(5L, older.payload.integer("through_seq", -1)); assertEquals(4L, older.payload.integer("before_seq", 0))
        window.accept(content("session.event", user(6)))
        window.accept(content("session.page.result", jsonObject("records" to JsonArray(listOf(record(0), user(1), record(2), record(3))), "has_more" to JsonBoolean(false), "through_seq" to 5L.json()), page))
        assertEquals(6L, window.snapshot().cursor); assertEquals(7, window.snapshot().records.size); assertFalse(window.snapshot().hasMore)
        assertFalse(window.accept(content("session.page.result", jsonObject(), page)))
    }
    @Test fun modelReplacementCopiesDoNotEraseOrDuplicateHumanHistory() {
        val replacement = assistant(3, "model-only").with("surface_op" to jsonObject("op" to "replace".json(), "startSeq" to 0L.json(), "endSeq" to 1L.json()))
        val window = SessionWindow(request); window.accept(snapshot(listOf(user(0), assistant(1), record(2), replacement), 3))
        assertEquals(listOf("hello", "complete"), window.snapshot().items.map { it.blocks.single().text })
        window.accept(content("session.snapshot", snapshot().payload, syncId = "99999999-9999-4999-8999-999999999999"))
        assertEquals(1L, window.snapshot().cursor); assertFalse(window.accept(content("session.event", user(4), syncId = sync)))
    }
}
