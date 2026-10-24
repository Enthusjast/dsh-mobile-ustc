package cn.edu.ustc.dsh.session

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test

class StreamBlocksTest {
    private fun delta(type: String = "text-delta", text: String = "partial") = jsonObject("type" to type.json(), "index" to 0L.json(), "text" to text.json())
    private fun end(text: String) = jsonObject("type" to "block-end".json(), "index" to 0L.json(), "block" to jsonObject("type" to "text".json(), "text" to text.json()))
    @Test fun firstCloseReplacesPartialTextAndIgnoresLaterUpdates() {
        val blocks = StreamBlocks(); blocks.accept(delta()); blocks.accept(end("final")); blocks.accept(delta(text = "late")); blocks.accept(end("changed"))
        assertEquals("final", blocks.snapshot().single().text); assertTrue(blocks.snapshot().single().complete)
        assertFalse(blocks.snapshot().single().toString().contains("final"))
    }
    @Test fun mismatchedLiveBlockKindsOversizedToolIdsAndTextBudgetsAreRejected() {
        val blocks = StreamBlocks(); blocks.accept(delta())
        assertThrows(SessionDataException::class.java) { blocks.accept(delta("reasoning-delta")) }
        assertThrows(IllegalArgumentException::class.java) { StreamBlocks().accept(jsonObject("type" to "block-end".json(), "index" to 0L.json(), "block" to jsonObject("type" to "tool-call".json(), "id" to "x".repeat(2049).json()))) }
        assertThrows(SessionDataException::class.java) { StreamBlocks().accept(delta(text = "x".repeat(SESSION_PAYLOAD_BYTES + 1))) }
    }
    @Test fun compactToolAndReasoningChunksKeepDenseCountsAndValidateDeltaTimes() {
        val stream = listOf(jsonObject("type" to "reasoning-chunks".json(), "time0" to 1000L.json(), "index" to 0L.json(), "dt" to JsonArray(listOf(1L.json())), "texts" to JsonArray(listOf("思".json(), "考".json()))),
            jsonObject("type" to "tool-call-chunks".json(), "time0" to 1001L.json(), "index" to 1L.json(), "dt" to JsonArray(emptyList()), "id" to "call".json(), "name" to "bash".json(), "args" to JsonArray(listOf("{}".json()))))
        val blocks = StreamBlocks(); blocks.compact(stream, 3)
        assertEquals(listOf(BlockKind.REASONING, BlockKind.TOOL), blocks.snapshot().map { it.kind }); assertEquals("思考", blocks.snapshot().first().text)
        assertThrows(SessionDataException::class.java) { StreamBlocks().compact(stream, 4) }
        val invalid = stream.first().with("dt" to JsonArray(listOf(JsonNumber(0.5))))
        assertThrows(SessionDataException::class.java) { StreamBlocks().compact(listOf(invalid)) }
    }
}
