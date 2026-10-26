package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import okhttp3.*
import okhttp3.mockwebserver.*
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.Buffer
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

class AppReleaseDownloadsTest {
    private val server = MockWebServer()
    private val elsewhere = MockWebServer()
    private val certificate = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
    private val tls = HandshakeCertificates.Builder().heldCertificate(certificate).build()
    private val trusted = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
    private val http: LoginHttp
    private val directory = Files.createTempDirectory("dsh-apk-download-").toFile()
    private val origin get() = server.url("/").toString().trimEnd('/')
    init {
        server.protocols = listOf(Protocol.HTTP_1_1)
        server.useHttps(tls.sslSocketFactory(), false); elsewhere.useHttps(tls.sslSocketFactory(), false)
        server.start(); elsewhere.start()
        http = LoginHttp.forTests(OkHttpClient.Builder().sslSocketFactory(trusted.sslSocketFactory(), trusted.trustManager).build())
    }
    @After fun cleanup() { server.shutdown(); elsewhere.shutdown(); directory.deleteRecursively() }
    private fun release(bytes: ByteArray, vararg changes: Pair<String, JsonValue>): AppRelease = AppRelease.parse(jsonObject(
        "release_id" to "99999999-9999-4999-8999-999999999999".json(), "version_code" to 2L.json(), "version_name" to "fixture".json(),
        "package_name" to "cn.edu.ustc.dsh.mobile".json(), "sha256" to MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }.json(),
        "size_bytes" to bytes.size.toLong().json(), "signing_cert_sha256" to "b".repeat(64).json(), "download_url" to server.url("/release.apk").toString().json(),
        "minimum_protocol_version" to 1L.json(), "maximum_protocol_version" to 1L.json(), "minimum_android_api" to 26L.json(), "rollout_basis_points" to 10000L.json(),
        "release_notes" to "fixture".json()).with(*changes))
    private fun response(bytes: ByteArray) = MockResponse().setHeader("Content-Type", "application/vnd.android.package-archive").setBody(Buffer().write(bytes))
    private fun empty() = assertTrue("failed transfer retained APK bytes", directory.listFiles()!!.isEmpty())

    @Test fun aDownloadSealsTheActualPrivateBytesAndCopiesOnlyAfterRecheckingThem(): Unit = runBlocking {
        val bytes = "APK fixture bytes 资料".toByteArray()
        server.enqueue(response(bytes).setHeader("Set-Cookie", "private=ignored"))
        val progress = ArrayList<Long>()
        val candidate = http.downloadAppRelease(release(bytes), setOf(origin), directory, progress = { progress += it })
        candidate.use {
            assertArrayEquals(bytes, it.inspectVerified { path -> path.readBytes() })
            val sink = ByteArrayOutputStream(); it.copyVerifiedTo(sink); assertArrayEquals(bytes, sink.toByteArray())
            try { it.output(); fail("sealed candidate reopened for writing") } catch (_: RemoteRequestException) {}
            assertEquals(bytes.size.toLong(), progress.last()); assertFalse(it.toString().contains(directory.path))
        }
        empty()
        val request = server.takeRequest()
        assertEquals("GET", request.method); assertEquals("/release.apk", request.path)
        assertEquals("identity", request.getHeader("Accept-Encoding")); assertEquals("no-store", request.getHeader("Cache-Control"))
        for (header in listOf("Authorization", "DPoP", "Cookie", "Range")) assertNull(request.getHeader(header))
    }
    @Test fun unapprovedOriginsAreRejectedWithoutAnyNetworkRequest(): Unit = runBlocking {
        try { http.downloadAppRelease(release("abc".toByteArray()), setOf(elsewhere.url("/").toString().trimEnd('/')), directory); fail("unapproved download origin used") }
        catch (error: RemoteRequestException) { assertEquals("network.insecure_endpoint", error.code) }
        assertEquals(0, server.requestCount); assertEquals(0, elsewhere.requestCount); empty()
    }
    @Test fun aSharedResourceInterceptorCannotAddCredentialsToAnApkDownload(): Unit = runBlocking {
        val transport = OkHttpClient.Builder().sslSocketFactory(trusted.sslSocketFactory(), trusted.trustManager).addInterceptor { chain ->
            chain.proceed(chain.request().newBuilder().header("Authorization", "Bearer PRIVATE_RESOURCE_TOKEN").header("DPoP", "PRIVATE_PROOF").header("Cookie", "school=PRIVATE").build())
        }.build()
        val isolated = LoginHttp.forTests(transport)
        val bytes = "abc".toByteArray(); server.enqueue(response(bytes))
        isolated.downloadAppRelease(release(bytes), setOf(origin), directory).close()
        val request = server.takeRequest()
        for (name in listOf("Authorization", "DPoP", "Cookie")) assertNull(request.getHeader(name))
        empty()
    }
    @Test fun redirectsAndAmbiguousTransferHeadersNeverProduceACandidate(): Unit = runBlocking {
        val bytes = "abc".toByteArray()
        for (reply in listOf(
            response(bytes).setResponseCode(307).setHeader("Location", elsewhere.url("/secret.apk")),
            response(bytes).setResponseCode(206), response(bytes).setHeader("Content-Type", "text/html"),
            response(bytes).setHeader("Content-Encoding", "gzip"), response(bytes).setHeader("Content-Range", "bytes 0-2/3"),
            response(bytes).addHeader("Content-Length", "3"), MockResponse().setHeader("Content-Type", "application/octet-stream").setChunkedBody("abc", 1).setHeader("Content-Length", "3"))) {
            server.enqueue(reply)
            try { http.downloadAppRelease(release(bytes), setOf(origin), directory); fail("invalid transfer accepted") } catch (_: RemoteRequestException) {}
            empty()
        }
        assertEquals(0, elsewhere.requestCount)
    }
    @Test fun chunkedBodiesStillRequireTheExactBoundedLengthAndSavedDigest(): Unit = runBlocking {
        val bytes = "abc".toByteArray()
        server.enqueue(MockResponse().setHeader("Content-Type", "application/octet-stream; fixture=1").setChunkedBody("abc", 1))
        http.downloadAppRelease(release(bytes), setOf(origin), directory).use { assertArrayEquals(bytes, it.inspectVerified { file -> file.readBytes() }) }
        empty()
        for (body in listOf("ab", "abd", "abcdef")) {
            server.enqueue(MockResponse().setHeader("Content-Type", "application/vnd.android.package-archive").setChunkedBody(body, 1))
            try { http.downloadAppRelease(release(bytes), setOf(origin), directory); fail("invalid chunked bytes accepted") }
            catch (error: RemoteRequestException) { assertEquals("update.integrity_mismatch", error.code) }
            empty()
        }
    }
    @Test fun http2WithoutAContentLengthStillVerifiesTheCompleteBoundedFile(): Unit = runBlocking {
        val modern = MockWebServer()
        modern.protocols = listOf(Protocol.HTTP_2, Protocol.HTTP_1_1)
        modern.useHttps(tls.sslSocketFactory(), false); modern.start()
        val observed = AtomicReference<Protocol>()
        val client = OkHttpClient.Builder().sslSocketFactory(trusted.sslSocketFactory(), trusted.trustManager).eventListener(object : EventListener() {
            override fun connectionAcquired(call: Call, connection: Connection) { observed.set(connection.protocol()) }
        }).build()
        try {
            modern.enqueue(MockResponse().setHeader("Content-Type", "application/vnd.android.package-archive").setBody("abc").removeHeader("Content-Length"))
            val bytes = "abc".toByteArray()
            LoginHttp.forTests(client).downloadAppRelease(release(bytes, "download_url" to modern.url("/release.apk").toString().json()), setOf(modern.url("/").toString().trimEnd('/')), directory).use {
                assertArrayEquals(bytes, it.inspectVerified { file -> file.readBytes() })
            }
            assertEquals(Protocol.HTTP_2, observed.get()); empty()
        } finally { modern.shutdown() }
    }
    @Test fun exactLengthAndTheHashOfTheSavedFileAreBothRequired(): Unit = runBlocking {
        val bytes = "abc".toByteArray()
        server.enqueue(response(bytes))
        try { http.downloadAppRelease(release(bytes, "size_bytes" to 4L.json()), setOf(origin), directory); fail("wrong declared length accepted") }
        catch (error: RemoteRequestException) { assertEquals("update.integrity_mismatch", error.code) }
        empty()
        server.enqueue(response("abd".toByteArray()))
        try { http.downloadAppRelease(release(bytes), setOf(origin), directory); fail("wrong saved digest accepted") }
        catch (error: RemoteRequestException) { assertEquals("update.integrity_mismatch", error.code) }
        empty()
        val larger = ByteArray(16 * 1024) { 7 }
        server.enqueue(response(larger).setSocketPolicy(SocketPolicy.DISCONNECT_DURING_RESPONSE_BODY))
        try { http.downloadAppRelease(release(larger), setOf(origin), directory); fail("interrupted download accepted") } catch (_: RemoteRequestException) {}
        empty()
    }
    @Test fun cancellationClosesTheNetworkAndDeletesThePartiallyWrittenFile(): Unit = runBlocking {
        val bytes = ByteArray(128 * 1024) { 7 }; val progress = AtomicLong()
        server.enqueue(response(bytes).throttleBody(1024, 1, TimeUnit.SECONDS))
        val task = launch(Dispatchers.Default) { http.downloadAppRelease(release(bytes), setOf(origin), directory, progress = progress::set).close() }
        withTimeout(5000) { while (progress.get() == 0L) delay(10) }
        withTimeout(3000) { task.cancelAndJoin() }; empty()
    }
    @Test fun losingTheCurrentOwnerDuringStreamingCannotReturnASealedCandidate(): Unit = runBlocking {
        val bytes = ByteArray(128 * 1024) { 9 }; val current = AtomicBoolean(true)
        server.enqueue(response(bytes))
        try {
            http.downloadAppRelease(release(bytes), setOf(origin), directory, current = { if (!current.get()) throw CancellationException() }, progress = { current.set(false) })
            fail("retired owner retained downloaded bytes")
        } catch (_: CancellationException) {}
        empty()
    }
    @Test fun aChangedCandidateIsDeletedBeforeThePlatformInspectorCanReadIt(): Unit = runBlocking {
        val bytes = "abc".toByteArray(); server.enqueue(response(bytes))
        val candidate = http.downloadAppRelease(release(bytes), setOf(origin), directory)
        assertTrue(candidate.file.setWritable(true, true)); candidate.file.writeText("abd")
        var inspected = false
        try { candidate.inspectVerified { inspected = true }; fail("replacement bytes inspected") }
        catch (error: RemoteRequestException) { assertEquals("update.integrity_mismatch", error.code) }
        assertFalse(inspected); empty()
    }
    @Test fun symlinkReplacementCannotReadOrDeleteAnUnrelatedFile(): Unit = runBlocking {
        val bytes = "abc".toByteArray(); server.enqueue(response(bytes))
        val candidate = http.downloadAppRelease(release(bytes), setOf(origin), directory)
        val outside = File.createTempFile("dsh-unrelated-", ".data")
        try {
            outside.writeBytes(bytes); assertTrue(candidate.file.delete()); Files.createSymbolicLink(candidate.file.toPath(), outside.toPath())
            try { candidate.inspectVerified { fail("symlink reached platform inspection") }; fail("symlink accepted") } catch (_: RemoteRequestException) {}
            assertArrayEquals(bytes, outside.readBytes()); empty()
        } finally { outside.delete() }
    }
    @Test fun modificationDuringInspectionCannotReturnAnEarlierVerdict(): Unit = runBlocking {
        val bytes = "abc".toByteArray(); server.enqueue(response(bytes))
        val candidate = http.downloadAppRelease(release(bytes), setOf(origin), directory)
        try {
            candidate.inspectVerified { path -> path.setWritable(true, true); path.writeText("abd"); "old verdict" }
            fail("stale inspection verdict returned")
        } catch (error: RemoteRequestException) { assertEquals("update.integrity_mismatch", error.code) }
        empty()
    }
    @Test fun closeRetiresAnInFlightInspectorWithoutBlockingItsCaller(): Unit = runBlocking {
        val bytes = "abc".toByteArray(); server.enqueue(response(bytes))
        val candidate = http.downloadAppRelease(release(bytes), setOf(origin), directory)
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val inspecting = async(Dispatchers.IO) {
            runCatching { candidate.inspectVerified { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); "old verdict" } }.exceptionOrNull()
        }
        try {
            withTimeout(3000) { while (entered.count > 0) delay(10) }
            withTimeout(1000) { withContext(Dispatchers.Default) { candidate.close() } }
            empty(); release.countDown()
            val error = withTimeout(3000) { inspecting.await() }
            assertTrue(error is RemoteRequestException); assertEquals("update.state_changed", (error as RemoteRequestException).code)
        } finally { release.countDown(); inspecting.cancelAndJoin(); candidate.close() }
    }
}
