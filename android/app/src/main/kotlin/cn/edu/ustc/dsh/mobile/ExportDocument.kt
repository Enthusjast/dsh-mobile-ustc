package cn.edu.ustc.dsh.mobile

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.RemoteExportStatus
import kotlinx.coroutines.*
import java.io.Closeable
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicReference

/** The new document URI and all stream handles remain private and ephemeral. */
internal suspend fun saveExportDocument(context: Context, uri: Uri, api: RemoteApi, file: RemoteExportStatus, current: () -> Unit, progress: (Long) -> Unit) =
    saveStagedExportDocument(context, uri, file, current) { stage -> api.downloadExport(file, stage::output, current, progress) }

internal suspend fun saveStagedExportDocument(context: Context, uri: Uri, file: RemoteExportStatus, current: () -> Unit = {}, download: suspend (EncryptedExportStage) -> Unit) = coroutineScope {
    val resolver = context.contentResolver
    val handle = AtomicReference<Closeable?>()
    val stage = EncryptedExportStage(File(context.cacheDir, "file-exports"), file.manifest)
    val cancellation = launch(Dispatchers.Default, start = CoroutineStart.UNDISPATCHED) {
        try { awaitCancellation() } finally { runCatching { handle.getAndSet(null)?.close() }; stage.close() }
    }
    var saved = false
    var document = uri
    var finalName = file.manifest.name
    try {
        withContext(Dispatchers.IO) {
            currentCoroutineContext().ensureActive(); current()
            if (uri.scheme != "content" || !DocumentsContract.isDocumentUri(context, uri)) throw RemoteRequestException("file.destination_unsupported")
            val metadata = resolver.query(document, arrayOf(DocumentsContract.Document.COLUMN_FLAGS, DocumentsContract.Document.COLUMN_DISPLAY_NAME), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) cursor.getLong(0) to cursor.getString(1) else null
            } ?: throw RemoteRequestException("file.destination_unsupported")
            val required = DocumentsContract.Document.FLAG_SUPPORTS_WRITE or DocumentsContract.Document.FLAG_SUPPORTS_DELETE or DocumentsContract.Document.FLAG_SUPPORTS_RENAME
            if (metadata.first and required.toLong() != required.toLong()) throw RemoteRequestException("file.destination_unsupported")
            finalName = if (metadata.second == exportSuggestedName(file.manifest.name)) file.manifest.name else metadata.second.removeSuffix(".dsh-partial")
            cn.edu.ustc.dsh.protocol.FileManifest(finalName, 0, file.manifest.sha256)
            // A process death during copying leaves an explicitly incomplete name.
            document = DocumentsContract.renameDocument(resolver, document, "DSH-incomplete-${java.util.UUID.randomUUID()}.dsh-partial") ?: throw RemoteRequestException("file.destination_unsupported")
        }
        download(stage)
        withContext(Dispatchers.IO) {
            val lifetime = currentCoroutineContext()
            fun check() { lifetime.ensureActive(); current() }
            check()
            val output = resolver.openOutputStream(document, "wt") ?: throw RemoteRequestException("file.save_failed")
            handle.set(output)
            output.use { stage.copyVerified(it, ::check); check() }
            handle.compareAndSet(output, null)
            check()
            // Closing a provider stream is insufficient evidence of a saved document.
            val input = resolver.openInputStream(document) ?: throw RemoteRequestException("file.save_failed")
            handle.set(input)
            input.use {
                val hash = MessageDigest.getInstance("SHA-256"); val buffer = ByteArray(64 * 1024); var bytes = 0L
                while (true) {
                    check(); val count = it.read(buffer); if (count < 0) break
                    if (count == 0 || bytes + count > file.manifest.sizeBytes) throw RemoteRequestException("file.integrity_mismatch")
                    bytes += count; hash.update(buffer, 0, count)
                }
                check()
                val digest = hash.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
                if (bytes != file.manifest.sizeBytes || digest != file.manifest.sha256) throw RemoteRequestException("file.integrity_mismatch")
            }
            handle.compareAndSet(input, null); check()
            document = DocumentsContract.renameDocument(resolver, document, finalName) ?: throw RemoteRequestException("file.save_failed")
            check(); saved = true
        }
    } finally {
        withContext(NonCancellable + Dispatchers.IO) {
            runCatching { handle.getAndSet(null)?.close() }; stage.close()
            cancellation.cancelAndJoin()
            if (!saved && !discardExportDocument(context, document)) throw RemoteRequestException("file.save_cleanup_required")
        }
    }
}

/** On failure prefer removal, then truncate. Never leave a completed-looking partial file silently. */
internal fun discardExportDocument(context: Context, uri: Uri): Boolean {
    if (uri.scheme != "content" || !DocumentsContract.isDocumentUri(context, uri)) return false
    if (runCatching { DocumentsContract.deleteDocument(context.contentResolver, uri) }.getOrDefault(false)) return true
    return runCatching {
        val descriptor = context.contentResolver.openFileDescriptor(uri, "rwt") ?: return@runCatching false
        descriptor.use { android.system.Os.ftruncate(it.fileDescriptor, 0); android.system.Os.fsync(it.fileDescriptor) }
        true
    }.getOrDefault(false)
}

internal fun exportSuggestedName(name: String) = name.take(64).trimEnd { it.isHighSurrogate() } + ".dsh-partial"
