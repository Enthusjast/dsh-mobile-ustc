package cn.edu.ustc.dsh.session

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test

class MediaCacheTest {
    private val request = "11111111-1111-4111-8111-111111111111"
    private val sync = "22222222-2222-4222-8222-222222222222"
    private val digest = "a".repeat(64)
    private fun text(value: String) = jsonObject("type" to "text".json(), "text" to value.json())
    private fun event(seq: Long, type: String, parts: List<JsonValue>): JsonObject {
        val message = jsonObject("id" to "message-$seq".json(), "content" to JsonArray(parts))
        val data = if (type == "user/message") message else jsonObject("turn" to 1L.json(), "step" to 0L.json(), "message" to message)
        return jsonObject("native_seq" to seq.json(), "time" to 1000L.json(), "type" to type.json(), "data" to data, "surface_op" to "append".json())
    }
    private fun ordinary(seq: Long = 0, type: String = "user/message", count: Int = 1) =
        event(seq, type, listOf(text("before")) + List(count) { text(LEGACY_IMAGE_NOTICE) } + text("after"))
    private fun media(seq: Long = 0, type: String = "user/message", count: Int = 1): JsonObject {
        // Bind to the ordinary display projection, not a native full-event/fork anchor hash.
        val version = mediaEventSha256(SessionJson.encode(ordinary(seq, type, count)))
        val images = List(count) { index -> jsonObject("type" to "image".json(), "reference" to jsonObject(
            "v" to 1L.json(), "origin" to "session_attachment".json(), "native_seq" to seq.json(),
            "part_index" to (index + 1L).json(), "event_version_sha256" to version.json(),
            "manifest" to ExportManifest("photo-$index.png", 123, digest).json(),
            "media_type" to "image/png".json(), "width" to 640L.json(), "height" to 480L.json())) }
        return event(seq, type, listOf(text("before")) + images + text("after"))
    }
    private fun mapReferences(root: JsonObject, change: (JsonObject) -> JsonObject): JsonObject {
        val data = root.obj("data")
        val user = root.string("type") == "user/message"
        val message = if (user) data else data.obj("message")
        val content = JsonArray(message.array("content").map { value ->
            val block = value as JsonObject
            if (block.string("type") == "image") block.with("reference" to change(block.obj("reference"))) else block
        })
        return root.with("data" to if (user) data.with("content" to content) else data.with("message" to message.with("content" to content)))
    }
    private fun content(type: String, payload: JsonObject, requestId: String = request) = SessionContent(type, requestId, sync, payload)
    private fun snapshot(records: List<JsonValue>, cursor: Long = 0, more: Boolean = false) = content("session.snapshot",
        jsonObject("cursor" to cursor.json(), "has_more" to JsonBoolean(more), "records" to JsonArray(records), "assistant" to JsonNull))

    @Test fun recordsRequireNegotiationAndVerifyTheOrdinaryDisplayProjectionForEveryMessageRole() {
        for (type in listOf("user/message", "assistant/message", "tool/result")) {
            val root = media(type = type)
            assertThrows(SessionDataException::class.java) { SessionRecord.parse(root) }
            val parsed = SessionRecord.parse(root, mediaRefs = true)
            val expected = mediaEventSha256(SessionJson.encode(ordinary(type = type)))
            assertEquals(expected, parsed.messageVersionSha256)
            assertEquals(expected, SessionRecord.parse(ordinary(type = type)).messageVersionSha256)
            assertNotEquals(mediaEventSha256(SessionJson.encode(root)), parsed.messageVersionSha256)
            val block = parsed.blocks[1]
            assertEquals(BlockKind.IMAGE, block.kind); assertEquals("", block.text)
            assertEquals("photo-0.png", block.media!!.manifest.name)
            assertEquals(expected, block.media!!.eventVersionSha256)
            assertThrows(SessionDataException::class.java) { SessionRecord.parse(root.with("time" to 1001L.json()), mediaRefs = true) }
            assertThrows(SessionDataException::class.java) {
                SessionRecord.parse(mapReferences(root) { it.with("event_version_sha256" to digest.json()) }, mediaRefs = true)
            }
        }
    }

    @Test fun referencesMustMatchTheRecordSequenceAndStrictlyIncreaseNativePartIndices() {
        val root = media(count = 2)
        assertEquals(2, SessionRecord.parse(root, true).blocks.count { it.media != null })
        for (bad in listOf(mapReferences(root) { it.with("native_seq" to 1L.json()) },
            mapReferences(root) { it.with("part_index" to 1L.json()) },
            mapReferences(root) { it.with("part_index" to (3L - it.integer("part_index", 0)).json()) })) {
            assertThrows(SessionDataException::class.java) { SessionRecord.parse(bad, true) }
        }
        assertThrows(ProtocolException::class.java) {
            SessionRecord.parse(mapReferences(root) { it.with("url" to "https://example.invalid".json()) }, true)
        }
    }

    @Test fun windowNegotiationAppliesToSnapshotsEventsAndHistoricalPages() {
        val root = media()
        assertThrows(SessionDataException::class.java) { SessionWindow(request).accept(snapshot(listOf(root))) }
        val legacy = SessionWindow(request)
        legacy.accept(snapshot(emptyList(), -1))
        assertThrows(SessionDataException::class.java) { legacy.accept(content("session.event", root)) }
        val current = SessionWindow(request, mediaRefs = true)
        current.accept(snapshot(emptyList(), -1))
        current.accept(content("session.event", root))
        assertEquals(BlockKind.IMAGE, current.snapshot().items.single().blocks[1].kind)
        val pageRequest = "33333333-3333-4333-8333-333333333333"
        for (negotiated in listOf(false, true)) {
            val window = SessionWindow(request, mediaRefs = negotiated)
            window.accept(snapshot(listOf(event(1, "user/message", listOf(text("newer")))) , 1, true))
            assertNotNull(window.page(pageRequest))
            val page = content("session.page.result", jsonObject("records" to JsonArray(listOf(root)),
                "has_more" to JsonBoolean(false), "through_seq" to 1L.json()), pageRequest)
            if (negotiated) {
                window.accept(page)
                assertEquals(BlockKind.IMAGE, window.snapshot().items.first().blocks[1].kind)
            } else assertThrows(SessionDataException::class.java) { window.accept(page) }
        }
    }

    @Test fun durableCacheV2RetainsTypedReferencesWithoutClaimingLiveOrDownloadAuthority() {
        val window = SessionWindow(request, mediaRefs = true)
        window.accept(snapshot(listOf(media())))
        assertTrue(window.snapshot(durableOnly = true).records.isEmpty())
        window.accept(content("session.checkpoint", jsonObject("state" to "persisted".json(), "through_seq" to 0L.json())))
        val durable = window.snapshot(durableOnly = true)
        val original = durable.records.single()
        val bytes = original.cacheBytes()
        val wrapper = SessionJson.parse(bytes)
        assertEquals(setOf("cache_v", "media_v", "record"), wrapper.fields.keys)
        assertEquals(2L, wrapper.integer("cache_v", 2, 2)); assertEquals(1L, wrapper.integer("media_v", 1, 1))
        val restored = parseCachedSessionRecord(bytes)
        assertTrue(SessionJson.same(original.raw, restored.raw))
        assertEquals(original.messageVersionSha256, restored.messageVersionSha256)
        assertTrue(original.blocks[1].media!!.same(restored.blocks[1].media!!))
        assertArrayEquals(bytes, restored.cacheBytes())
        val cached = CachedTranscript(sync, 1000, listOf(restored)).transcript
        assertTrue(cached.durableOnly); assertFalse(cached.taskRunning)
        assertTrue(cached.items.single().persisted); assertFalse(cached.items.single().live)
        assertEquals(BlockKind.IMAGE, cached.items.single().blocks[1].kind)
        assertEquals(digest, cached.items.single().blocks[1].media!!.manifest.sha256)
    }

    @Test fun oldUnversionedRowsMigrateOnlyThroughStrictNonMediaGrammar() {
        val old = ordinary()
        val restored = parseCachedSessionRecord(SessionJson.encode(old))
        assertTrue(restored.blocks.all { it.media == null })
        assertEquals(LEGACY_IMAGE_NOTICE, restored.blocks[1].text)
        val migrated = SessionJson.parse(restored.cacheBytes())
        assertEquals(2L, migrated.integer("cache_v", 2, 2)); assertEquals(0L, migrated.integer("media_v", 0, 0))
        assertTrue(SessionJson.same(old, parseCachedSessionRecord(restored.cacheBytes()).raw))
        assertThrows(SessionDataException::class.java) { parseCachedSessionRecord(SessionJson.encode(media())) }
        assertThrows(SessionDataException::class.java) { parseCachedSessionRecord(SessionJson.encode(old.with("unknown" to JsonNull))) }
    }

    @Test fun cacheRejectsUnknownVersionsDowngradedMediaAndCorruptDigests() {
        val wrapper = SessionJson.parse(SessionRecord.parse(media(), true).cacheBytes())
        for (bad in listOf(wrapper.with("cache_v" to 1L.json()), wrapper.with("cache_v" to 3L.json()),
            wrapper.with("media_v" to (-1L).json()), wrapper.with("media_v" to 2L.json()),
            wrapper.with("media_v" to "1".json()), wrapper.with("unknown" to JsonNull),
            JsonObject(wrapper.fields.filterKeys { it != "media_v" }))) {
            assertThrows(ProtocolException::class.java) { parseCachedSessionRecord(SessionJson.encode(bad)) }
        }
        assertThrows(SessionDataException::class.java) { parseCachedSessionRecord(SessionJson.encode(wrapper.with("media_v" to 0L.json()))) }
        val wrongEvent = mapReferences(media()) { it.with("event_version_sha256" to digest.json()) }
        assertThrows(SessionDataException::class.java) { parseCachedSessionRecord(SessionJson.encode(wrapper.with("record" to wrongEvent))) }
        for (badRecord in listOf(mapReferences(media()) { it.with("event_version_sha256" to "corrupt".json()) },
            mapReferences(media()) { it.with("manifest" to it.obj("manifest").with("sha256" to "corrupt".json())) })) {
            assertThrows(ProtocolException::class.java) { parseCachedSessionRecord(SessionJson.encode(wrapper.with("record" to badRecord))) }
        }
    }
}
