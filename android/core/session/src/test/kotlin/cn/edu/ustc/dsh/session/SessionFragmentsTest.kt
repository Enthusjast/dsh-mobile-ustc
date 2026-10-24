package cn.edu.ustc.dsh.session

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class SessionFragmentsTest {
    private val ids = (1..7).map { "${it.toString().repeat(8)}-${it.toString().repeat(4)}-4${it.toString().repeat(3)}-8${it.toString().repeat(3)}-${it.toString().repeat(12)}" }
    private val route = SessionRoute(ids[0], ids[1], ids[2], ids[3])
    private fun frame(index: Int, count: Int, bytes: ByteArray, change: Pair<String, JsonValue>? = null): JsonObject {
        var payload = jsonObject("type" to "session.snapshot".json(), "fragment_id" to ids[6].json(), "index" to index.toLong().json(), "count" to count.toLong().json(), "data" to Base64.getEncoder().encodeToString(bytes).json())
        if (change != null) payload = payload.with(change)
        return jsonObject("v" to 1L.json(), "type" to "session.fragment".json(), "request_id" to ids[4].json(), "runtime_id" to route.runtimeId.json(), "runtime_epoch" to route.epoch.json(),
            "session_id" to route.sessionId.json(), "subscription_id" to route.subscriptionId.json(), "sync_id" to ids[5].json(), "payload" to payload)
    }
    @Test fun largeUtf8ContentPublishesOnlyAfterTheFinalPieceEvenAcrossAScalarBoundary() {
        val text = "中🙂".repeat(40_000)
        val bytes = ("{\"text\":\"" + text + "\"}").toByteArray()
        val pieces = bytes.asList().chunked(40_959).map { it.toByteArray() }
        val fragments = SessionFragments(route)
        for (index in 0 until pieces.lastIndex) assertNull(fragments.accept(frame(index, pieces.size, pieces[index]), 0))
        assertNotNull(fragments.pendingMillis(1))
        val result = fragments.accept(frame(pieces.lastIndex, pieces.size, pieces.last()), 2)!!
        assertEquals("session.snapshot", result.type); assertEquals(ids[4], result.requestId); assertEquals(ids[5], result.syncId)
        assertEquals(text, result.payload.string("text")); assertNull(fragments.pendingMillis())
    }
    @Test fun missingRepeatedReorderedAndChangedIdentityPiecesCannotPublish() {
        val head = frame(0, 2, "{\"text\":".toByteArray())
        val tail = frame(1, 2, "\"ok\"}".toByteArray())
        for (bad in listOf(head, tail.with("sync_id" to ids[0].json()), tail.with("request_id" to ids[0].json()),
            tail.with("runtime_epoch" to ids[0].json()), tail.with("subscription_id" to ids[0].json()),
            frame(1, 3, "\"ok\"}".toByteArray()), frame(1, 2, "\"ok\"}".toByteArray(), "fragment_id" to ids[0].json()),
            frame(1, 2, "\"ok\"}".toByteArray(), "type" to "session.event".json()))) {
            val fragments = SessionFragments(route); assertNull(fragments.accept(head, 0))
            assertThrows(IllegalArgumentException::class.java) { fragments.accept(bad, 1) }
        }
        assertThrows(IllegalArgumentException::class.java) { SessionFragments(route).accept(tail) }
        val fragments = SessionFragments(route); fragments.accept(head, 0)
        val unfragmented = head.with("type" to "session.snapshot".json(), "payload" to jsonObject())
        assertThrows(IllegalArgumentException::class.java) { fragments.accept(unfragmented, 1) }
        fragments.clear(); assertNotNull(fragments.accept(unfragmented, 2))
    }
    @Test fun canonicalBase64PieceBudgetAndLogicalDeadlineAreEnforced() {
        for (bad in listOf("AB==", "eA", "eA==\n", "eA--", "====", "")) {
            assertThrows(IllegalArgumentException::class.java) { SessionFragments(route).accept(frame(0, 2, byteArrayOf(1), "data" to bad.json())) }
        }
        assertThrows(IllegalArgumentException::class.java) { SessionFragments(route).accept(frame(0, 2, ByteArray(40 * 1024 + 1))) }
        val fragments = SessionFragments(route); fragments.accept(frame(0, 2, "{".toByteArray()), 1)
        assertEquals(0L, fragments.pendingMillis(10_000_000_002))
        assertThrows(IllegalArgumentException::class.java) { fragments.accept(frame(1, 2, "}".toByteArray()), 10_000_000_002) }
        val oversized = ByteArray(SESSION_PAYLOAD_BYTES + 1) { 32 }.asList().chunked(40 * 1024).map { it.toByteArray() }
        val large = SessionFragments(route)
        for (index in 0 until oversized.lastIndex) assertNull(large.accept(frame(index, oversized.size, oversized[index]), 0))
        val error = assertThrows(SessionDataException::class.java) { large.accept(frame(oversized.lastIndex, oversized.size, oversized.last()), 1) }
        assertEquals("protocol.snapshot_too_large", error.code)
    }
    @Test fun displayParserRejectsDuplicateKeysTrailingJsonInvalidUnicodeDepthAndNodeFloods() {
        val invalid = listOf("{\"x\":1,\"x\":2}", "{} {}", "{\"x\":\"\\udc00\"}", "{\"x\":\"\\ud800x\"}", "{\"x\":1e9999}",
            "{\"x\":" + "[".repeat(33) + "0" + "]".repeat(33) + "}", "{\"x\":[" + List(SESSION_MAX_NODES) { "0" }.joinToString(",") + "]}")
        for (bad in invalid) assertThrows(SessionDataException::class.java) { SessionJson.parse(bad.toByteArray()) }
        assertThrows(SessionDataException::class.java) { SessionJson.parse(byteArrayOf(123, 34, -64, -81, 34, 58, 48, 125)) }
    }
}
