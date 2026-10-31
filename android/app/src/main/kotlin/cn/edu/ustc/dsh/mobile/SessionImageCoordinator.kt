package cn.edu.ustc.dsh.mobile

import android.content.Context
import android.net.Uri
import android.os.CancellationSignal
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** No second picker authority or reader: parent supplies its original token/resource/revision check. */
class SessionImageCoordinator(context: Context, owner: CoroutineScope) : AutoCloseable {
    private val resolver = context.applicationContext.contentResolver
    private val scope = CoroutineScope(SupervisorJob(owner.coroutineContext[Job]) + Dispatchers.Main.immediate)
    private val mutable = MutableStateFlow(SessionImageState())
    val state: StateFlow<SessionImageState> = mutable.asStateFlow()
    private val generation = AtomicLong()
    private val closed = AtomicBoolean()
    private val cancellation = AtomicReference<CancellationSignal?>()
    private val input = AtomicReference<InputStream?>()
    private val source = AtomicReference<MemoryImageSource?>()
    private var preparation: Job? = null
    private var previewWork: Job? = null
    private var previewReader: SessionReader? = null
    private var preview: DecodedStaticImage? = null
    private var imageUploads: SessionUploads? = null
    @Volatile private var foreground = true

    private fun check(operation: Long, current: () -> Boolean) {
        if (closed.get() || !foreground || generation.get() != operation || !current()) throw CancellationException("image.stale")
    }
    fun select(uri: Uri, uploads: SessionUploads, resumeId: String? = null, current: () -> Boolean, finished: () -> Unit = {}) {
        cancel()
        if (closed.get() || !foreground || !current()) {
            scope.launch(NonCancellable + Dispatchers.IO) { finished() }
            return
        }
        val operation = generation.get()
        mutable.value = SessionImageState(preparing = true)
        preparation = scope.launch(start = CoroutineStart.UNDISPATCHED) {
            var bytes: ByteArray? = null
            var decoded: DecodedStaticImage? = null
            var handedOff: MemoryImageSource? = null
            try {
                withContext(Dispatchers.IO) { bytes = read(uri, operation, current) }
                check(operation, current)
                val original = bytes!!
                withContext(Dispatchers.Default) { decoded = StaticImageDecoder.decode(original) }
                check(operation, current)
                val extension = when (decoded!!.metadata.mediaType) { "image/png" -> "png"; "image/jpeg" -> "jpg"; "image/webp" -> "webp"; "image/gif" -> "gif"; else -> throw ProtocolException() }
                val memory = MemoryImageSource(original, "image-${UUID.randomUUID()}.$extension") { completed -> source.compareAndSet(completed, null) }
                handedOff = memory
                source.set(memory); imageUploads = uploads
                uploads.selectImage(memory, decoded!!.metadata, resumeId)
                bytes = null
                preview = decoded
                mutable.value = SessionImageState(preview = ImagePreviewState(decoded!!.bitmap, memory.name, false), previewRequested = true)
                decoded = null
            } catch (error: CancellationException) { throw error }
            catch (error: OutOfMemoryError) { if (generation.get() == operation && !closed.get()) mutable.value = SessionImageState(error = "image.memory_limited") }
            catch (error: Exception) { if (generation.get() == operation && !closed.get()) mutable.value = SessionImageState(error = code(error)) }
            finally {
                bytes?.fill(0); decoded?.close()
                if (bytes != null) handedOff?.close()
                withContext(NonCancellable + Dispatchers.IO) { finished() }
                if (generation.get() == operation) mutable.update { it.copy(preparing = false) }
            }
        }
    }
    private suspend fun read(uri: Uri, operation: Long, current: () -> Boolean): ByteArray {
        if (uri.scheme != "content" || uri.authority.isNullOrEmpty()) throw RemoteRequestException("image.source_unavailable")
        check(operation, current)
        val signal = CancellationSignal()
        cancellation.set(signal)
        try {
            return resolver.openAssetFileDescriptor(uri, "r", signal)?.use { descriptor ->
                check(operation, current)
                if (descriptor.declaredLength > MAX_IMAGE_BYTES) throw RemoteRequestException("image.too_large")
                descriptor.createInputStream().use { stream ->
                    input.set(stream)
                    val capacity = descriptor.declaredLength.takeIf { it in 1..MAX_IMAGE_BYTES.toLong() }?.toInt() ?: 64 * 1024
                    val output = WipingImageOutput(capacity)
                    val chunk = ByteArray(64 * 1024)
                    try {
                        while (true) {
                            currentCoroutineContext().ensureActive(); check(operation, current)
                            val count = stream.read(chunk)
                            if (count < 0) break
                            if (count == 0 || count > MAX_IMAGE_BYTES - output.size()) throw RemoteRequestException("image.too_large")
                            output.write(chunk, 0, count)
                        }
                        check(operation, current)
                        if (output.size() < 10) throw RemoteRequestException("image.invalid")
                        output.toByteArray()
                    } finally { chunk.fill(0); output.wipe(); input.compareAndSet(stream, null) }
                }
            } ?: throw RemoteRequestException("image.source_unavailable")
        } finally { cancellation.compareAndSet(signal, null); signal.cancel() }
    }
    fun open(reference: VisibleMediaReference, reader: SessionReader, current: () -> Boolean) {
        dismissPreview()
        if (closed.get() || !foreground || !current()) return
        val operation = generation.get()
        previewReader = reader
        mutable.value = SessionImageState(previewRequested = true, previewLoading = true)
        reader.media.open(reference)
        previewWork = scope.launch {
            var observed: VerifiedMediaBytes? = null
            try {
            reader.media.state.collectLatest { value ->
                check(operation, current)
                if (value.reference !== reference || !value.canPreview) {
                    clearBitmap()
                    mutable.value = SessionImageState(previewRequested = true, error = value.error ?: "image.stale")
                    return@collectLatest
                }
                if (value.loading) {
                    mutable.update { it.copy(previewLoading = true, error = null) }
                    return@collectLatest
                }
                val encoded = value.bytes
                if (encoded == null) {
                    clearBitmap()
                    mutable.value = SessionImageState(previewRequested = true, error = value.error ?: "image.unavailable")
                    return@collectLatest
                }
                if (encoded === observed) return@collectLatest
                observed = encoded
                var decoded: DecodedStaticImage? = null
                try {
                    withContext(Dispatchers.Default) { decoded = encoded.read { StaticImageDecoder.decode(it, reference.image) } }
                    check(operation, current)
                    if (!reader.media.isCurrent(reference)) throw CancellationException("image.stale")
                    clearBitmap(); preview = decoded
                    mutable.value = SessionImageState(preview = ImagePreviewState(decoded!!.bitmap, reference.manifest.name, true), previewRequested = true)
                    decoded = null
                } catch (error: CancellationException) { throw error }
                catch (error: OutOfMemoryError) { mutable.value = SessionImageState(previewRequested = true, error = "image.memory_limited") }
                catch (error: Exception) { mutable.value = SessionImageState(previewRequested = true, error = code(error)) }
                finally { decoded?.close(); encoded.close() }
            }
            } finally {
                if (generation.get() == operation) {
                    reader.media.dismiss(); clearBitmap()
                    mutable.value = SessionImageState()
                }
            }
        }
    }
    private fun clearBitmap() { val previous = preview; preview = null; previous?.close() }
    fun dismissPreview() {
        if (mutable.value.preparing) {
            preparation?.cancel(); preparation = null
            cancellation.getAndSet(null)?.cancel(); input.getAndSet(null)?.let { runCatching { it.close() } }
        }
        generation.incrementAndGet(); previewWork?.cancel(); previewWork = null
        previewReader?.media?.dismiss(); previewReader = null
        mutable.value = SessionImageState()
        clearBitmap()
    }
    fun cancel() {
        generation.incrementAndGet(); preparation?.cancel(); preparation = null
        cancellation.getAndSet(null)?.cancel(); input.getAndSet(null)?.let { runCatching { it.close() } }
        source.getAndSet(null)?.let { it.close(); imageUploads?.cancelTransfer() }; imageUploads = null
        dismissPreview()
    }
    fun foreground(active: Boolean) { foreground = active; if (!active) cancel() }
    override fun close() { if (closed.compareAndSet(false, true)) { foreground = false; cancel(); scope.cancel() } }
    private fun code(error: Exception) = when (error) {
        is RemoteRequestException -> error.code
        is IllegalArgumentException -> error.message?.takeIf { it in setOf("image.invalid", "image.too_large", "image.invalid_exif", "image.metadata_mismatch") } ?: "image.invalid"
        else -> "image.source_unavailable"
    }
    private class WipingImageOutput(capacity: Int) : ByteArrayOutputStream(capacity) {
        private fun reserve(required: Int) {
            if (required < 0 || required > MAX_IMAGE_BYTES) throw RemoteRequestException("image.too_large")
            if (required <= buf.size) return
            val previous = buf
            buf = previous.copyOf(minOf(MAX_IMAGE_BYTES, maxOf(required, previous.size * 2)))
            previous.fill(0)
        }
        @Synchronized override fun write(value: Int) { reserve(count + 1); buf[count++] = value.toByte() }
        @Synchronized override fun write(bytes: ByteArray, offset: Int, length: Int) {
            if (offset < 0 || length < 0 || offset > bytes.size - length) throw IndexOutOfBoundsException()
            reserve(count + length); bytes.copyInto(buf, count, offset, offset + length); count += length
        }
        fun wipe() { buf.fill(0); reset() }
    }
    private class MemoryImageSource(private val bytes: ByteArray, override val name: String, private val finished: (MemoryImageSource) -> Unit) : FileInputSource {
        private val lock = Any()
        private var closed = false
        override fun open(): InputStream = synchronized(lock) {
            if (closed) throw IOException("image source closed")
            object : InputStream() {
                private var position = 0
                private var streamClosed = false
                override fun read(): Int = synchronized(lock) {
                    if (closed || streamClosed) throw IOException("image source closed")
                    if (position == bytes.size) -1 else bytes[position++].toInt() and 255
                }
                override fun read(target: ByteArray, offset: Int, length: Int): Int = synchronized(lock) {
                    if (closed || streamClosed) throw IOException("image source closed")
                    if (offset < 0 || length < 0 || offset > target.size - length) throw IndexOutOfBoundsException()
                    if (length == 0) return@synchronized 0
                    if (position == bytes.size) return@synchronized -1
                    val count = minOf(length, bytes.size - position)
                    bytes.copyInto(target, offset, position, position + count); position += count; count
                }
                override fun close() { synchronized(lock) { streamClosed = true } }
            }
        }
        override fun close() {
            val notify = synchronized(lock) { if (closed) false else { closed = true; bytes.fill(0); true } }
            if (notify) finished(this)
        }
        override fun toString() = "ImageInputSource"
    }
}
