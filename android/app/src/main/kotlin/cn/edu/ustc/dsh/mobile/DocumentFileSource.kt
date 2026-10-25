package cn.edu.ustc.dsh.mobile

import android.content.Context
import android.net.Uri
import android.os.CancellationSignal
import android.provider.OpenableColumns
import cn.edu.ustc.dsh.network.FileInputSource
import cn.edu.ustc.dsh.network.RemoteRequestException
import java.io.FilterInputStream
import java.io.InputStream
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Selected content-provider permission stays in memory; no URI is saved or logged. */
internal class DocumentFileSource(context: Context, private val uri: Uri) : FileInputSource {
    private val resolver = context.applicationContext.contentResolver
    private val closed = AtomicBoolean()
    private val operation = AtomicReference<CancellationSignal?>()
    private val stream = AtomicReference<InputStream?>()
    init { if (uri.scheme != "content" || uri.authority.isNullOrEmpty()) throw RemoteRequestException("file.source_unavailable") }
    override val name: String by lazy {
        checked {
            val signal = begin()
            val raw = resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null, signal)?.use { cursor ->
                if (cursor.moveToFirst()) cursor.getString(0) else null
            } ?: "attachment.bin"
            val name = StringBuilder(); var bytes = 0; var at = 0
            while (at < raw.length) {
                val point = raw.codePointAt(at); at += Character.charCount(point)
                val part = if (point in 0xD800..0xDFFF || Character.isISOControl(point) || point == '/'.code || point == '\\'.code) "_" else String(Character.toChars(point))
                val size = part.toByteArray(Charsets.UTF_8).size
                if (bytes + size > 512) break
                name.append(part); bytes += size
            }
            name.toString().trim().takeUnless { it.isBlank() || it == "." || it == ".." } ?: "attachment.bin"
        }
    }
    private fun begin(): CancellationSignal {
        if (closed.get()) throw RemoteRequestException("file.source_unavailable")
        val next = CancellationSignal(); operation.set(next)
        if (closed.get()) { next.cancel(); throw RemoteRequestException("file.source_unavailable") }
        return next
    }
    override fun open(): InputStream = checked {
        val descriptor = resolver.openAssetFileDescriptor(uri, "r", begin()) ?: throw RemoteRequestException("file.source_unavailable")
        val raw = try { descriptor.createInputStream() } catch (error: Exception) { descriptor.close(); throw error }
        val wrapped = object : FilterInputStream(raw) {
            override fun close() { try { super.close() } finally { stream.compareAndSet(this, null) } }
        }
        stream.getAndSet(wrapped)?.close()
        if (closed.get()) { wrapped.close(); throw RemoteRequestException("file.source_unavailable") }
        wrapped
    }
    private fun <T> checked(action: () -> T): T = try { action() } catch (_: Exception) { throw RemoteRequestException("file.source_unavailable") }
    override fun close() { closed.set(true); operation.getAndSet(null)?.cancel(); runCatching { stream.getAndSet(null)?.close() } }
    override fun toString() = "DocumentFileSource"
}
