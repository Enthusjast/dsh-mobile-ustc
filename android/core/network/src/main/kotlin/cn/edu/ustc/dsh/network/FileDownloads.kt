package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import okhttp3.*
import java.io.IOException
import java.io.OutputStream
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Streams only into a private staging sink. Callers publish after successful verification. */
internal suspend fun downloadFileBytes(client: OkHttpClient, request: Request, file: RemoteExportStatus,
    destination: () -> OutputStream, current: () -> Unit, progress: (Long) -> Unit): HttpReply? {
    if (request.url.scheme != "https" || request.url.username.isNotEmpty() || request.url.password.isNotEmpty()) throw RemoteRequestException("network.insecure_endpoint")
    if (!file.downloadable()) throw RemoteRequestException("file.state_changed")
    val lifetime = currentCoroutineContext()
    val output = AtomicReference<OutputStream?>()
    val activeResponse = AtomicReference<Response?>()
    return suspendCancellableCoroutine { continuation ->
        val call = client.newCall(request)
        call.timeout().timeout(minOf(300_000, file.expiresAt - System.currentTimeMillis()).coerceAtLeast(1), TimeUnit.MILLISECONDS)
        continuation.invokeOnCancellation {
            call.cancel(); runCatching { activeResponse.getAndSet(null)?.close() }; runCatching { output.getAndSet(null)?.close() }
        }
        call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                if (continuation.isActive) continuation.resumeWithException(RemoteRequestException("file.download_failed"))
            }
            override fun onResponse(call: Call, response: Response) {
                activeResponse.set(response)
                try {
                    val reply = response.use { reply ->
                        lifetime.ensureActive(); current()
                        val body = reply.body ?: throw RemoteRequestException("network.invalid_response")
                        if (reply.code != 200) {
                            val type = body.contentType()
                            if (type?.type != "application" || type.subtype != "json" || type.charset(Charsets.UTF_8) != Charsets.UTF_8 || body.contentLength() > JsonDocument.MAX_BYTES) throw RemoteRequestException("network.invalid_response")
                            val source = body.source(); source.request(JsonDocument.MAX_BYTES.toLong() + 1)
                            if (source.buffer.size > JsonDocument.MAX_BYTES) throw RemoteRequestException("network.response_too_large")
                            return@use HttpReply(reply.code, reply.headers, source.buffer.readByteArray())
                        }
                        val manifest = file.manifest
                        if (reply.headers.values("Content-Length") != listOf(manifest.sizeBytes.toString()) || body.contentLength() != manifest.sizeBytes ||
                            reply.headers.values("Content-Type") != listOf("application/octet-stream") || reply.header("Content-Range") != null ||
                            reply.headers.values("Content-Encoding").let { it.isNotEmpty() && it != listOf("identity") } ||
                            reply.headers.values("X-DSH-Content-SHA256") != listOf(manifest.sha256)) throw RemoteRequestException("file.integrity_mismatch")
                        val sink = destination()
                        output.set(sink)
                        sink.use {
                            val hash = MessageDigest.getInstance("SHA-256")
                            val buffer = ByteArray(64 * 1024)
                            var count = 0L
                            val source = body.byteStream()
                            while (true) {
                                lifetime.ensureActive(); current()
                                if (!file.downloadable()) throw RemoteRequestException("file.expired")
                                val size = source.read(buffer)
                                if (size < 0) break
                                if (size == 0 || count + size > manifest.sizeBytes) throw RemoteRequestException("file.integrity_mismatch")
                                hash.update(buffer, 0, size); it.write(buffer, 0, size); count += size; progress(count)
                            }
                            val actual = hash.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
                            lifetime.ensureActive(); current()
                            if (count != manifest.sizeBytes || actual != manifest.sha256) throw RemoteRequestException("file.integrity_mismatch")
                        }
                        null
                    }
                    if (continuation.isActive) continuation.resume(reply)
                } catch (error: Exception) {
                    if (continuation.isActive) continuation.resumeWithException(if (error is RemoteRequestException) error else RemoteRequestException("file.download_failed"))
                } finally { output.set(null); activeResponse.set(null) }
            }
        })
    }
}
