package cn.edu.ustc.dsh.protocol

import org.junit.Assert.*
import org.junit.Test
import java.util.Base64
import java.util.UUID

class SessionChangesActionsTest {
    private val id = UUID.randomUUID().toString()
    private val anchor = SessionForkAnchor(id, id, 0, "a".repeat(64), "b".repeat(64))
    private fun preview(text: JsonValue, shareable: Boolean) = jsonObject("v" to 1L.json(), "anchor" to anchor.json(), "text" to text,
        "shareable" to JsonBoolean(shareable), "complete" to JsonBoolean(true))
    private fun patch(bytes: ByteArray = "diff --git a/a b/a\n".toByteArray()) = jsonObject("v" to 1L.json(), "sync_id" to id.json(), "snapshot_id" to id.json(), "file_id" to id.json(),
        "version" to "a".repeat(64).json(), "kind" to "text".json(), "complete" to JsonBoolean(true), "copyable" to JsonBoolean(true), "partial" to JsonBoolean(false),
        "patch_base64" to Base64.getEncoder().encodeToString(bytes).json(), "patch_utf8" to (sessionChangeUtf8(bytes)?.json() ?: JsonNull), "hunks" to JsonArray(emptyList()), "next_cursor" to JsonNull)
    @Test fun anchorsAndOutcomesRequireExactVersionKeysAndSafeNativeSequence() {
        assertEquals(anchor, SessionForkAnchor.parse(anchor.json()))
        assertEquals(SessionForkOutcome("failed", "unknown"), SessionForkOutcome.parse(SessionForkOutcome("failed", "unknown").json()))
        for (root in listOf(anchor.json().with("v" to 2L.json()), anchor.json().with("native_seq" to JsonNumber(MAX_SAFE_INTEGER.toDouble() + 1)),
            anchor.json().with("native_seq" to JsonNumber(0.5)), anchor.json().with("hidden" to "x".json()), anchor.json().with("anchor_sha256" to "A".repeat(64).json()))) {
            assertThrows(ProtocolException::class.java) { SessionForkAnchor.parse(root) }
        }
        assertThrows(ProtocolException::class.java) { SessionForkOutcome.parse(SessionForkOutcome("attached", "persisted").json().with("checkpoint" to "pending".json())) }
    }
    @Test fun textlessMessageRemainsAnchoredButCannotPretendToBeShareable() {
        val empty = SessionMessagePreview.parse(preview(JsonNull, false))
        assertEquals(anchor, empty.anchor); assertNull(empty.text); assertFalse(empty.shareable); assertTrue(empty.complete)
        assertEquals("正文", SessionMessagePreview.parse(preview("正文".json(), true)).text)
        for (root in listOf(preview(JsonNull, true), preview("".json(), true), preview("正文".json(), false), preview("x".repeat(32769).json(), true),
            preview("bad\u0000".json(), true), preview("x".json(), true).with("complete" to JsonBoolean(false)))) {
            assertThrows(ProtocolException::class.java) { SessionMessagePreview.parse(root) }
        }
        assertThrows(ProtocolException::class.java) { SessionMessagePreview.parse(JsonObject(preview("x".json(), true).fields - "text")) }
    }
    @Test fun payloadBudgetIncludesGoHtmlEscapesAndActualUtf8Bytes() {
        assertThrows(ProtocolException::class.java) { SessionMessagePreview.parse(preview("中".repeat(10923).json(), true)) }
        val escaped = preview("<".repeat(9000).json(), true)
        assertTrue(JsonDocument.of(escaped).canonicalBytes().size < 48 * 1024)
        assertTrue(sessionActionPayloadBytes(escaped) > 48 * 1024)
        assertThrows(ProtocolException::class.java) { SessionMessagePreview.parse(escaped) }
        val separator = jsonObject("x" to "\u2028<&>".json())
        assertEquals(JsonDocument.of(separator).canonicalBytes().size + 18, sessionActionPayloadBytes(separator))
    }
    @Test fun patchBytesRequiredNullsAndStructuredCoordinatesAreStrict() {
        assertTrue(SessionChangesPatch.parse(patch()).copyable)
        for (root in listOf(patch().with("patch_base64" to "Zh==".json()), patch().with("patch_utf8" to "different".json()),
            patch().with("kind" to "binary".json()), patch().with("next_cursor" to id.json()), patch().with("partial" to JsonBoolean(true)))) {
            assertThrows(ProtocolException::class.java) { SessionChangesPatch.parse(root) }
        }
        assertThrows(ProtocolException::class.java) { SessionChangesPatch.parse(JsonObject(patch().fields - "patch_utf8")) }
        assertThrows(ProtocolException::class.java) { SessionChangesPatch.parse(patch(byteArrayOf(0xc3.toByte(), 0x28))) }
        val line = jsonObject("kind" to "add".json(), "bytes_base64" to "YQ==".json(), "text" to "a".json(), "old_line" to JsonNull, "new_line" to JsonNumber(MAX_SAFE_INTEGER.toDouble() + 1))
        assertThrows(ProtocolException::class.java) { SessionChangeLine.parse(line) }
        assertThrows(ProtocolException::class.java) { SessionChangePath.parse(jsonObject("bytes_base64" to "AA==".json(), "display" to "\\0".json())) }
        assertThrows(ProtocolException::class.java) { SessionChangePath.parse(jsonObject("bytes_base64" to "YQ==".json(), "display" to "a\n".json())) }
    }
}
