package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import okhttp3.*
import java.io.IOException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** A distinct anonymous GET, with no credential-bearing request supplied by a caller. */
internal suspend fun downloadAppBytes(client: OkHttpClient, candidate: PrivateApkCandidate, origins: Set<String>, current: () -> Unit, progress: (Long) -> Unit) {
    val release = candidate.release
    if (origins.size !in 1..8 || origins.any { appUpdateOrigin(it, originOnly = true) != it } || release.downloadOrigin !in origins) throw RemoteRequestException("network.insecure_endpoint")
    val request = Request.Builder().url(release.downloadUrl).get().header("Accept", "application/vnd.android.package-archive, application/octet-stream")
        .header("Accept-Encoding", "identity").header("Cache-Control", "no-store").build()
    // Preserve the configured TLS trust/proxy path, while separating HTTP state
    // from resource requests even when the APK and API share an origin.
    val anonymous = client.newBuilder().followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
        .authenticator(Authenticator.NONE).proxyAuthenticator(Authenticator.NONE).cookieJar(CookieJar.NO_COOKIES).cache(null)
        .connectionPool(ConnectionPool(0, 1, TimeUnit.SECONDS)).apply { interceptors().clear(); networkInterceptors().clear() }.build()
    val lifetime = currentCoroutineContext()
    val active = AtomicReference<Response?>()
    suspendCancellableCoroutine { continuation ->
        val call = anonymous.newCall(request)
        call.timeout().timeout(300_000, TimeUnit.MILLISECONDS)
        continuation.invokeOnCancellation { call.cancel(); runCatching { active.getAndSet(null)?.close() }; candidate.close() }
        call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                if (continuation.isActive) continuation.resumeWithException(RemoteRequestException("update.download_failed").also { it.initCause(e) })
            }
            override fun onResponse(call: Call, response: Response) {
                active.set(response)
                try {
                    response.use { reply ->
                        lifetime.ensureActive(); current()
                        val body = reply.body ?: throw RemoteRequestException("update.download_failed")
                        if (reply.code != 200) throw RemoteRequestException("update.download_failed")
                        val lengths = reply.headers.values("Content-Length")
                        val transfers = reply.headers.values("Transfer-Encoding")
                        val type = body.contentType()
                        if (lengths.isNotEmpty() && lengths != listOf(release.sizeBytes.toString()) || body.contentLength().let { it >= 0 && it != release.sizeBytes } ||
                            transfers.isNotEmpty() && (lengths.isNotEmpty() || transfers.size != 1 || !transfers.single().equals("chunked", ignoreCase = true)) ||
                            reply.headers.values("Content-Type").size != 1 || type?.type != "application" || type.subtype !in setOf("vnd.android.package-archive", "octet-stream") ||
                            reply.header("Content-Range") != null || reply.headers.values("Content-Encoding").let { it.isNotEmpty() && it != listOf("identity") }) throw RemoteRequestException("update.integrity_mismatch")
                        candidate.output().use { sink ->
                            val buffer = ByteArray(64 * 1024)
                            var count = 0L
                            val source = body.byteStream()
                            while (true) {
                                lifetime.ensureActive(); current()
                                val size = source.read(buffer)
                                if (size < 0) break
                                if (size == 0 || count + size > release.sizeBytes) throw RemoteRequestException("update.integrity_mismatch")
                                sink.write(buffer, 0, size); count += size; progress(count)
                            }
                            lifetime.ensureActive(); current()
                            if (count != release.sizeBytes) throw RemoteRequestException("update.integrity_mismatch")
                        }
                    }
                    if (continuation.isActive) continuation.resume(Unit)
                } catch (error: Exception) {
                    if (continuation.isActive) continuation.resumeWithException(when (error) {
                        is CancellationException, is RemoteRequestException -> error
                        else -> RemoteRequestException("update.download_failed").also { it.initCause(error) }
                    })
                } finally { active.set(null) }
            }
        })
    }
}
