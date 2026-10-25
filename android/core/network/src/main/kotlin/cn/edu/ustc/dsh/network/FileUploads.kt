package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import okhttp3.*
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okio.BufferedSink
import java.io.IOException
import java.io.InputStream
import java.net.URI
import java.security.MessageDigest
import java.util.Base64
import java.util.Collections
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Ephemeral capability; its address and signed headers never enter presentation or storage. */
class PreparedFileUpload internal constructor(val file: RemoteFileStatus, internal val capability: FileUploadCapability?, internal val owner: Any) {
    val canUpload: Boolean get() = capability?.current() == true && file.state == FileTransferState.UPLOADING
    override fun toString() = "PreparedFileUpload"
}

internal class FileUploadCapability private constructor(val url: HttpUrl, val headers: Map<String, String>, private val expiry: Long) {
    private val issued = System.currentTimeMillis()
    private val started = System.nanoTime()
    fun current(): Boolean = System.currentTimeMillis() in issued until expiry && (System.nanoTime() - started) / 1_000_000 < expiry - issued
    fun remaining(): Long = minOf(expiry - System.currentTimeMillis(), expiry - issued - (System.nanoTime() - started) / 1_000_000)
    override fun toString() = "FileUploadCapability"
    companion object {
        private val allowed = setOf("content-type", "content-length", "cache-control", "x-amz-checksum-sha256", "x-amz-sdk-checksum-algorithm", "x-amz-security-token",
            "x-amz-server-side-encryption", "x-amz-server-side-encryption-aws-kms-key-id")
        fun parse(root: JsonObject, file: RemoteFileStatus): FileUploadCapability {
            root.exactKeys("url", "method", "headers", "expires_at")
            val raw = root.string("url")
            if (raw.toByteArray(Charsets.UTF_8).size > 16_384 || raw.any { it <= ' ' || it == '\u007f' } || root.string("method") != "PUT" || file.state != FileTransferState.UPLOADING) throw ProtocolException()
            val uri = try { URI(raw) } catch (_: Exception) { throw ProtocolException() }
            if (uri.scheme != "https" || uri.host.isNullOrBlank() || uri.rawUserInfo != null || uri.rawFragment != null) throw ProtocolException()
            val url = try { raw.toHttpUrl() } catch (_: Exception) { throw ProtocolException() }
            val headers = linkedMapOf<String, String>()
            for ((name, item) in root.obj("headers").fields) {
                val key = name.lowercase(java.util.Locale.ROOT)
                val value = (item as? JsonString)?.value ?: throw ProtocolException()
                if (key !in allowed || headers.containsKey(key) || value.length > 4096 || value.any { it !in ' '..'~' }) throw ProtocolException()
                headers[key] = value
            }
            if (headers["content-type"] != "application/octet-stream") throw ProtocolException()
            if (headers["content-length"]?.let { it != file.manifest.sizeBytes.toString() } == true || headers["cache-control"]?.let { it != "no-store" } == true ||
                headers["x-amz-server-side-encryption"]?.let { it != "aws:kms" } == true || headers["x-amz-sdk-checksum-algorithm"]?.let { it != "SHA256" } == true) throw ProtocolException()
            val checksum = Base64.getEncoder().encodeToString(file.manifest.sha256.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
            if (headers["x-amz-checksum-sha256"]?.let { it != checksum } == true) throw ProtocolException()
            val expiry = relayTime(root.string("expires_at")); val now = System.currentTimeMillis()
            if (expiry > file.uploadExpiresAt || expiry > file.expiresAt || expiry - now > 930_000) throw ProtocolException()
            return FileUploadCapability(url, Collections.unmodifiableMap(headers), expiry)
        }
    }
}

/** Uses the transport's TLS policy, but sends only a signed anonymous PUT. */
internal suspend fun uploadFileBytes(client: OkHttpClient, prepared: PreparedFileUpload, source: () -> InputStream, current: () -> Unit, progress: (Long) -> Unit) {
    val capability = prepared.capability ?: throw RemoteRequestException("file.state_changed")
    if (!capability.current()) throw RemoteRequestException("file.upload_expired")
    currentCoroutineContext().ensureActive(); current()
    val lifetime = currentCoroutineContext()
    val input = AtomicReference<InputStream?>()
    val failure = AtomicReference("file.upload_failed")
    val manifest = prepared.file.manifest
    val body = object : RequestBody() {
        override fun contentType() = "application/octet-stream".toMediaType()
        override fun contentLength() = manifest.sizeBytes
        override fun isOneShot() = true
        override fun writeTo(sink: BufferedSink) {
            try {
                lifetime.ensureActive(); current()
                if (!capability.current()) { failure.set("file.upload_expired"); throw IOException() }
                val stream = try { source() } catch (_: Exception) { failure.set("file.source_unavailable"); throw IOException() }
                input.set(stream)
                stream.use {
                    val buffer = ByteArray(64 * 1024)
                    val hash = MessageDigest.getInstance("SHA-256")
                    var bytes = 0L
                    while (true) {
                        lifetime.ensureActive(); current()
                        if (!capability.current()) { failure.set("file.upload_expired"); throw IOException() }
                        val count = try { it.read(buffer) } catch (_: IOException) { failure.set("file.source_unavailable"); throw IOException() }
                        if (count < 0) break
                        if (count == 0 || bytes + count > manifest.sizeBytes) { failure.set("file.integrity_mismatch"); throw IOException() }
                        bytes += count; hash.update(buffer, 0, count); sink.write(buffer, 0, count); progress(bytes)
                    }
                    val actual = hash.digest().joinToString("") { byte -> "%02x".format(byte.toInt() and 255) }
                    if (bytes != manifest.sizeBytes || actual != manifest.sha256) { failure.set("file.integrity_mismatch"); throw IOException() }
                }
            } catch (_: Exception) { throw IOException("file upload interrupted") }
            finally { input.set(null) }
        }
    }
    val request = Request.Builder().url(capability.url).put(body).apply {
        capability.headers.forEach { (key, value) -> header(key, value) }
        header("Cache-Control", "no-store"); header("Accept-Encoding", "identity")
    }.build()
    val uploaded = withTimeoutOrNull(capability.remaining().coerceAtLeast(1)) {
        suspendCancellableCoroutine<Unit> { continuation ->
            val call = client.newCall(request)
            call.timeout().timeout(capability.remaining().coerceAtLeast(1), TimeUnit.MILLISECONDS)
            continuation.invokeOnCancellation { call.cancel(); runCatching { input.getAndSet(null)?.close() } }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    if (continuation.isActive) continuation.resumeWithException(RemoteRequestException(if (!capability.current()) "file.upload_expired" else failure.get()))
                }
                override fun onResponse(call: Call, response: Response) {
                    val accepted = response.use { it.code in 200..299 }
                    if (continuation.isActive) {
                        if (accepted) continuation.resume(Unit) else continuation.resumeWithException(RemoteRequestException("file.upload_rejected"))
                    }
                }
            })
        }
        true
    }
    if (uploaded != true) throw RemoteRequestException("file.upload_expired")
}
