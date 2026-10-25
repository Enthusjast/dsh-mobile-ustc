package cn.edu.ustc.dsh.session

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test

class TranscriptCacheTest {
    private val epoch = "11111111-1111-4111-8111-111111111111"
    private fun record(seq: Long, text: String) = SessionRecord.parse(jsonObject("native_seq" to seq.json(), "time" to 1000L.json(), "type" to "user/message".json(),
        "data" to jsonObject("content" to JsonArray(listOf(jsonObject("type" to "text".json(), "text" to text.json()))))))
    @Test fun largeUnicodeRecordsRoundTripWithoutWeakeningSigningJsonLimits() {
        val original = record(40, "中文🙂".repeat(20_000))
        val encoded = SessionJson.encode(original.raw)
        assertTrue(encoded.size > JsonDocument.MAX_BYTES)
        assertThrows(ProtocolException::class.java) { JsonDocument.parse(encoded) }
        val restored = SessionRecord.parse(SessionJson.parse(encoded))
        assertEquals(original.blocks.single().text, restored.blocks.single().text)
        assertEquals(40L, restored.seq)
    }
    @Test fun restoredHistoryHasNoLiveTaskClaimAndPreservesItsRecentWindowCut() {
        val cache = CachedTranscript(epoch, 1000, listOf(record(40, "one"), record(41, "two")))
        assertEquals(41L, cache.transcript.cursor); assertTrue(cache.transcript.hasMore)
        assertTrue(cache.transcript.durableOnly); assertFalse(cache.transcript.taskRunning)
        assertTrue(cache.transcript.items.all { it.persisted && !it.live })
        assertFalse(cache.toString().contains("one"))
        assertThrows(SessionDataException::class.java) { CachedTranscript(epoch, 1000, listOf(record(40, "one"), record(42, "gap"))) }
    }
    @Test fun localRecordEncoderRejectsMalformedScalarsAndBoundedOutputOverflow() {
        assertThrows(SessionDataException::class.java) { SessionJson.encode(jsonObject("text" to "\ud800".json())) }
        assertThrows(SessionDataException::class.java) { SessionJson.encode(jsonObject("text" to "\n".repeat(SESSION_PAYLOAD_BYTES).json())) }
        val empty = CachedTranscript(epoch, 1000, emptyList()).transcript
        assertEquals(-1L, empty.cursor); assertFalse(empty.hasMore); assertTrue(empty.items.isEmpty())
    }
}
