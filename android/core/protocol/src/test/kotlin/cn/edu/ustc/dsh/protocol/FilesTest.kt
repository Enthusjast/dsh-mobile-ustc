package cn.edu.ustc.dsh.protocol

import org.junit.Assert.*
import org.junit.Test
import java.io.File

class FilesTest {
    private fun golden(name: String) = JsonDocument.parse(File(System.getProperty("contracts.root"), "files/v1/golden/$name.json").readBytes()).root
    @Test fun sharedFileMetadataMatchesStrictKotlinShapes() {
        val registration = golden("registration")
        val manifest = FileManifest.parse(JsonObject(registration.fields.filterKeys { it != "request_id" }))
        for (name in listOf("prepared", "clean")) {
            val status = RemoteFileStatus.parse(golden(name).obj("data").obj("file"))
            assertTrue(status.manifest.same(manifest)); assertEquals("to_host", golden(name).obj("data").obj("file").string("direction"))
            assertEquals(if (name == "prepared") FileTransferState.UPLOADING else FileTransferState.CLEAN, status.state)
            assertFalse(status.toString().contains(manifest.name))
        }
    }
    @Test fun metadataRejectsPathsInvalidSizesAndUntrustedAuthorityFields() {
        val base = golden("clean").obj("data").obj("file")
        for (bad in listOf(base.with("receipt_id" to "private".json()), base.with("object_key" to "private".json()), base.with("size_bytes" to JsonNull),
            base.with("size_bytes" to (MAX_FILE_BYTES + 1).json()), base.with("state" to "staged".json()), base.with("error_code" to "private error body".json()),
            base.with("state" to "clean".json(), "error_code" to "access_revoked".json()), base.with("direction" to "from_host".json()), base.with("name" to "../private".json()))) {
            assertThrows(ProtocolException::class.java) { RemoteFileStatus.parse(bad) }
        }
        val digest = "a".repeat(64)
        for (name in listOf("", " ", ".", "..", "a/b", "a\\b", "bad\u0000", "bad\u0085", "\ud800", "中".repeat(200))) {
            assertThrows(ProtocolException::class.java) { FileManifest(name, 1, digest) }
        }
        assertEquals(0, FileManifest("empty.txt", 0, digest).sizeBytes)
    }
    @Test fun cleanAndReadyAreDistinctAndBoundReferencesCannotBeReusedAsNewAttachments() {
        val base = golden("clean").obj("data").obj("file")
        assertFalse(RemoteFileStatus.parse(base).readyForMessage())
        assertEquals(FileDeliveryState.WAITING, RemoteFileStatus.parse(base.with("delivery" to jsonObject("state" to "waiting".json()))).delivery!!.state)
        val bound = RemoteFileStatus.parse(base.with("delivery" to jsonObject("state" to "bound".json(), "request_id" to base["file_id"], "command_state" to "received".json())))
        assertFalse(bound.readyForMessage()); assertEquals(base.string("file_id"), bound.delivery!!.requestId)
        val deferred = RemoteFileStatus.parse(base.with("state" to "scanning".json(), "error_code" to "scan_unavailable".json()))
        assertEquals(FileTransferState.SCANNING, deferred.state); assertEquals("scan_unavailable", deferred.error); assertFalse(deferred.readyForMessage())
        for (delivery in listOf(jsonObject("state" to "ready".json()), jsonObject("state" to "waiting".json(), "receipt_id" to "private".json()),
            jsonObject("state" to "bound".json(), "request_id" to base["file_id"], "command_state" to "invented".json()))) {
            assertThrows(ProtocolException::class.java) { RemoteFileStatus.parse(base.with("delivery" to delivery)) }
        }
    }
}
