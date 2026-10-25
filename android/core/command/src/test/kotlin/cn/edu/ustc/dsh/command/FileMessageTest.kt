package cn.edu.ustc.dsh.command

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class FileMessageTest {
    private fun golden(name: String) = JsonDocument.parse(File(System.getProperty("contracts.root"), "ws/v1/golden/$name.json").readBytes()).root
    @Test fun fileMessageMatchesSharedGoNodeDigestAndSurvivesTheEncryptedJournalShape() {
        val root = golden("message-file-submit")
        val forwarded = golden("message-file-submit.forwarded")
        val intent = CommandIntent.parse(root)
        assertEquals(forwarded.string("payload_sha256"), intent.digest)
        assertEquals(listOf("cccccccc-cccc-4ccc-8ccc-cccccccccccc"), intent.fileIds())
        assertEquals("请检查附件。", intent.text())
        assertEquals(intent.digest, CommandIntent.stored(intent.storageBytes()).digest)
        val made = CommandIntent.message(intent.requestId, intent.runtimeId, intent.sessionId!!, "queue", intent.text()!!, intent.fileIds())
        assertEquals(intent.digest, made.digest)
        val only = CommandIntent.message(intent.requestId, intent.runtimeId, intent.sessionId, "steer", "", intent.fileIds())
        assertEquals("", only.text()); assertEquals(1, only.payload.array("content").size)
    }
    @Test fun duplicateIdsAndReceiptOrPathFieldsCannotEnterAMobileIntent() {
        val root = golden("message-file-submit")
        val id = root.string("request_id")
        for (content in listOf(
            listOf(jsonObject("type" to "file".json(), "file_id" to id.json()), jsonObject("type" to "file".json(), "file_id" to id.json())),
            listOf(jsonObject("type" to "file".json(), "receiptId" to id.json())),
            listOf(jsonObject("type" to "file".json(), "file_id" to id.json(), "path" to "/private".json())),
            listOf(jsonObject("type" to "file".json(), "file_id" to id.json(), "text" to "".json())))) {
            assertThrows(ProtocolException::class.java) { CommandIntent.parse(root.with("payload" to jsonObject("mode" to "queue".json(), "content" to JsonArray(content)))) }
        }
    }
    @Test fun unboundFileRecoveryKeepsTheOriginalWithoutInventingAReceivedReceipt() {
        val intent = CommandIntent.parse(golden("message-file-submit"))
        val attempted = CommandEvolution.begin(CommandEvolution.created(intent, 1000), 1001)
        val ready = CommandEvolution.rearmUnboundFiles(attempted, 2000)
        assertNull(ready.remote); assertFalse(ready.everHostSaved); assertFalse(ready.everAgentQueued)
        assertEquals(intent.digest, ready.intent.digest); assertEquals(intent.requestId, ready.intent.requestId)
        assertEquals(2, CommandEvolution.begin(ready, 2001).attempts)
        assertThrows(CommandDataException::class.java) { CommandEvolution.begin(ready, 7001) }
        val text = CommandIntent.message(intent.requestId, intent.runtimeId, intent.sessionId!!, "queue", "text only")
        assertThrows(CommandDataException::class.java) { CommandEvolution.rearmUnboundFiles(CommandEvolution.begin(CommandEvolution.created(text, 1000), 1001), 2000) }
    }
}
