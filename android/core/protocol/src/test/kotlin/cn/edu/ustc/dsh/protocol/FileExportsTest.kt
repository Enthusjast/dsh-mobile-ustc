package cn.edu.ustc.dsh.protocol

import org.junit.Assert.*
import org.junit.Test
import java.io.File

class FileExportsTest {
    private fun golden(name: String) = JsonDocument.parse(File(System.getProperty("contracts.root"), "ws/v1/golden/$name.json").readBytes()).root
    @Test fun sharedExportMetadataStaysSeparateFromUploadAndNativeReferences() {
        val root = golden("file.export.accepted").obj("payload").obj("file")
        val file = RemoteExportStatus.parse(root)
        assertEquals(FileTransferState.SCANNING, file.state)
        assertFalse(file.downloadable()); assertFalse(file.toString().contains("资料"))
        assertEquals(MAX_EXPORT_BYTES, RemoteExportStatus.parse(root.with("size_bytes" to MAX_EXPORT_BYTES.json())).manifest.sizeBytes)
        assertThrows(ProtocolException::class.java) { RemoteFileStatus.parse(root) }
        for (bad in listOf(root.with("direction" to "to_host".json()), root.with("size_bytes" to (MAX_EXPORT_BYTES + 1).json()),
            root.with("delivery" to jsonObject("state" to "ready".json())), root.with("object_key" to "private".json()), root.with("name" to "../private".json()),
            root.with("state" to "clean".json(), "error_code" to "integrity_mismatch".json()))) {
            assertThrows(ProtocolException::class.java) { RemoteExportStatus.parse(bad) }
        }
        assertThrows(ProtocolException::class.java) { FileManifest("upload", MAX_EXPORT_BYTES, "a".repeat(64)) }
    }
    @Test fun sourceCatalogRejectsPathsAuthorityFieldsAndUnboundedPages() {
        val root = golden("file.exports.result").obj("payload")
        val page = ExportPage.parse(root)
        assertEquals(3L, page.items.single().sizeBytes); assertNull(page.cursor)
        val source = root.array("items").single() as JsonObject
        for (bad in listOf(source.with("path" to "/private".json()), source.with("origin" to "arbitrary".json()), source.with("name" to "bad\\name".json()),
            source.with("size_bytes" to (MAX_EXPORT_BYTES + 1).json()), source.with("kind" to "directory".json()), source.with("unavailable" to "private error".json()))) {
            assertThrows(ProtocolException::class.java) { ExportSource.parse(bad) }
        }
        val large = ExportSource.parse(source.with("size_bytes" to (MAX_EXPORT_BYTES + 1).json(), "unavailable" to "file.too_large".json()))
        assertTrue(large.unavailable)
        assertTrue(ExportSource.parse(source.with("unavailable" to "file.too_large".json())).unavailable)
        assertThrows(ProtocolException::class.java) { ExportPage.parse(root.with("items" to JsonArray(List(17) { source }))) }
        assertThrows(ProtocolException::class.java) { ExportPage.parse(root.with("items" to JsonArray(List(2) { source }))) }
    }
}
