package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.ExportManifest
import org.junit.Assert.*
import org.junit.Test
import java.io.*
import java.security.MessageDigest
import java.nio.file.Files

class EncryptedExportStageTest {
    private fun manifest(bytes: ByteArray) = ExportManifest("PRIVATE_stage.txt", bytes.size.toLong(), MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) })
    @Test fun boundedAuthenticatedChunksRoundTripWithoutAPlaintextSpool() {
        val root = Files.createTempDirectory("export-stage-test").toFile()
        try {
            val bytes = "PRIVATE_PLAINTEXT_MARKER|".repeat(14000).toByteArray()
            EncryptedExportStage(root, manifest(bytes)).use { stage ->
                stage.output().use { output -> bytes.toList().chunked(137).forEach { chunk -> output.write(chunk.toByteArray()) } }
                assertFalse(stage.file.readBytes().toString(Charsets.ISO_8859_1).contains("PRIVATE_PLAINTEXT_MARKER"))
                val restored = ByteArrayOutputStream(); stage.copyVerified(restored); assertArrayEquals(bytes, restored.toByteArray())
                assertFalse(stage.toString().contains("PRIVATE"))
            }
            assertTrue(root.listFiles()!!.isEmpty())
        } finally { root.deleteRecursively() }
    }
    @Test fun alteredReorderedTruncatedAndAppendedRecordsCannotProduceSuccess() {
        val root = Files.createTempDirectory("export-stage-test").toFile()
        try {
            val bytes = ByteArray(150_000) { (it % 251).toByte() }
            for (mutation in 0..3) EncryptedExportStage(root, manifest(bytes)).use { stage ->
                stage.output().use { it.write(bytes) }
                val raw = stage.file.readBytes()
                when (mutation) {
                    0 -> { raw[8] = (raw[8].toInt() xor 1).toByte(); stage.file.writeBytes(raw) }
                    1 -> { val length = 4 + 65536 + 16; stage.file.writeBytes(raw.copyOfRange(length, length * 2) + raw.copyOfRange(0, length) + raw.copyOfRange(length * 2, raw.size)) }
                    2 -> stage.file.writeBytes(raw.copyOf(raw.size - 1))
                    3 -> stage.file.appendBytes(byteArrayOf(1))
                }
                assertThrows(RemoteRequestException::class.java) { stage.copyVerified(ByteArrayOutputStream()) }
            }
            assertTrue(root.listFiles()!!.isEmpty())
        } finally { root.deleteRecursively() }
    }
    @Test fun emptyContentVerifiesAndFailedOrClosedStagesCannotBePublished() {
        val root = Files.createTempDirectory("export-stage-test").toFile()
        try {
            EncryptedExportStage(root, manifest(byteArrayOf())).use { stage -> stage.output().close(); stage.copyVerified(ByteArrayOutputStream()) }
            val stage = EncryptedExportStage(root, manifest("abc".toByteArray()))
            stage.output().use { it.write("ab".toByteArray()) }
            assertThrows(RemoteRequestException::class.java) { stage.copyVerified(ByteArrayOutputStream()) }
            stage.close()
            assertThrows(RemoteRequestException::class.java) { stage.copyVerified(ByteArrayOutputStream()) }
            assertTrue(root.listFiles()!!.isEmpty())
        } finally { root.deleteRecursively() }
    }
}
