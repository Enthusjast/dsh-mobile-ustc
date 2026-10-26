package cn.edu.ustc.dsh.mobile

import android.provider.DocumentsContract
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.network.RemoteRequestException
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.After
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class ExportDocumentTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val resolver = context.contentResolver
    private val bytes = "Public Android export fixture\n".repeat(6000).toByteArray()
    private fun file(content: ByteArray = bytes): RemoteExportStatus {
        val id = UUID.randomUUID().toString()
        val digest = MessageDigest.getInstance("SHA-256").digest(content).joinToString("") { "%02x".format(it.toInt() and 255) }
        return RemoteExportStatus.parse(jsonObject("file_id" to id.json(), "runtime_id" to id.json(), "session_id" to id.json(), "direction" to "from_host".json(), "name" to "fixture.txt".json(),
            "size_bytes" to content.size.toLong().json(), "sha256" to digest.json(), "state" to "clean".json(), "created_at" to Instant.now().minusSeconds(1).toString().json(),
            "upload_expires_at" to Instant.now().plusSeconds(60).toString().json(), "expires_at" to Instant.now().plusSeconds(3600).toString().json()))
    }
    private fun destination(name: String) = resolver.call(FixtureDocumentProvider.URI, "createExport", name, null)!!.getParcelable<android.net.Uri>("uri")!!
    private fun exists(uri: android.net.Uri) = runCatching { resolver.query(uri, arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID), null, null, null)?.use { it.moveToFirst() } == true }.getOrDefault(false)
    private fun name(uri: android.net.Uri) = resolver.query(uri, arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME), null, null, null)!!.use { it.moveToFirst(); it.getString(0) }
    private fun noStaging() { assertTrue(File(context.cacheDir, "file-exports").listFiles()?.isEmpty() != false) }
    @After fun cleanup() { resolver.call(FixtureDocumentProvider.URI, "resetExports", null, null) }
    @Test fun providerDocumentIsReadBackAndVerifiedForNonemptyAndEmptyContent(): Unit = runBlocking {
        for (destinationName in listOf("normal", "moving")) for (content in listOf(bytes, byteArrayOf())) {
            val uri = destination(destinationName)
            var published = uri
            try {
                saveStagedExportDocument(context, uri, file(content)) { stage -> stage.output().use { it.write(content) } }
                published = resolver.call(FixtureDocumentProvider.URI, "findExport", destinationName, null)!!.getParcelable<android.net.Uri>("uri")!!
                assertArrayEquals(content, resolver.openInputStream(published)!!.use { it.readBytes() }); assertEquals(destinationName, name(published)); noStaging()
                if (destinationName == "moving") assertFalse(exists(uri))
            } finally { DocumentsContract.deleteDocument(resolver, published) }
        }
    }
    @Test fun corruptedStageOrProviderReadbackDeletesTheIncompleteDocument(): Unit = runBlocking {
        for (name in listOf("normal", "corrupt")) {
            val uri = destination(name)
            assertThrows(RemoteRequestException::class.java) { runBlocking {
                saveStagedExportDocument(context, uri, file()) { stage -> stage.output().use { it.write(if (name == "normal") "changed bytes".toByteArray() else bytes) } }
            } }
            assertFalse(exists(uri)); noStaging()
        }
    }
    @Test fun cancellationDeletesTheCreatedDocumentAndEncryptedStaging(): Unit = runBlocking {
        val uri = destination("normal"); val entered = CompletableDeferred<Unit>()
        val task = launch { saveStagedExportDocument(context, uri, file()) { stage -> stage.output().write(bytes, 0, 10); entered.complete(Unit); awaitCancellation() } }
        withTimeout(3000) { entered.await() }; assertTrue(name(uri).startsWith("DSH-incomplete-")); task.cancelAndJoin()
        assertFalse(exists(uri)); noStaging()
    }
    @Test fun unsupportedDestinationNeverStartsTransferAndFailedCleanupIsExplicit(): Unit = runBlocking {
        var downloaded = false
        val unsupported = destination("unsupported")
        assertThrows(RemoteRequestException::class.java) { runBlocking { saveStagedExportDocument(context, unsupported, file()) { downloaded = true } } }
        assertFalse(downloaded); assertFalse(exists(unsupported)); noStaging()
        val stuck = destination("cleanup-failure")
        val error = assertThrows(RemoteRequestException::class.java) { runBlocking { saveStagedExportDocument(context, stuck, file()) { throw RemoteRequestException("file.download_failed") } } }
        assertEquals("file.save_cleanup_required", error.code); assertTrue(exists(stuck)); noStaging()
    }
}
