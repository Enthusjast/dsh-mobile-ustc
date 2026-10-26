package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.auth.*
import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.command.*
import kotlinx.coroutines.flow.first
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.*
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class FileUploadsTest {
    private val service = MockWebServer()
    private val objects = MockWebServer()
    private val certificate = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
    private val tls = HandshakeCertificates.Builder().heldCertificate(certificate).build()
    private val trusted = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
    private val http: LoginHttp
    private val issuer = ECKeyGenerator(Curve.P_256).keyID("fixture-issuer").generate()
    private val key = ECKeyGenerator(Curve.P_256).generate()
    private val signer = object : DeviceProofSigner {
        override val publicKey = PublicProofKey(JsonDocument.parse(key.toPublicJWK().toJSONString()).root)
        override fun signJose(signingInput: ByteArray): ByteArray = ECDSASigner(key).sign(JWSHeader(JWSAlgorithm.ES256), signingInput).decode()
    }
    private val runtime = "66666666-6666-4666-8666-666666666666"
    private val session = "22222222-2222-4222-8222-222222222222"
    private val request = "11111111-1111-4111-8111-111111111111"
    private val file = "33333333-3333-4333-8333-333333333333"
    private val bytes = "abc".toByteArray()
    private val manifest = FileManifest("PRIVATE_资料.txt", bytes.size.toLong(), digest(bytes))
    private val origin get() = service.url("/").toString().trimEnd('/')
    init {
        service.useHttps(tls.sslSocketFactory(), false); objects.useHttps(tls.sslSocketFactory(), false)
        service.start(); objects.start()
        http = LoginHttp.forTests(OkHttpClient.Builder().sslSocketFactory(trusted.sslSocketFactory(), trusted.trustManager).build())
    }
    @After fun cleanup() { service.shutdown(); objects.shutdown() }
    private fun digest(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value).joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun api(onConfig: (LoginConfiguration) -> Unit = {}): RemoteApi {
        val config = LoginConfiguration.parse(JsonDocument.of(jsonObject("issuer" to "$origin/issuer".json(), "client_id" to "mobile".json(), "redirect_uri" to LoginConfiguration.REDIRECT_URI.json(),
            "resource" to "urn:dsh-remote".json(), "audience" to "urn:dsh-remote".json(), "remote_origin" to origin.json(), "organization_id" to request.json(),
            "scopes" to JsonArray(listOf("openid".json(), "remote.access".json())), "endpoint_origins" to JsonArray(listOf(origin.json())), "signing_algorithms" to JsonArray(listOf("ES256".json())))).canonicalBytes())
        onConfig(config)
        val discovery = OidcDiscovery.parse(JsonDocument.of(jsonObject("issuer" to config.issuer.json(), "authorization_endpoint" to "$origin/authorize".json(), "token_endpoint" to "$origin/token".json(),
            "jwks_uri" to "$origin/jwks".json(), "response_types_supported" to JsonArray(listOf("code".json())), "id_token_signing_alg_values_supported" to JsonArray(listOf("ES256".json())))).canonicalBytes(), config)
        val now = System.currentTimeMillis()
        val login = PendingLogin(discovery, signer.publicKey.thumbprint, now)
        val exchange = login.acceptCallback(LoginConfiguration.REDIRECT_URI + "?state=${login.state}&code=fixture", now)
        val base = jsonObject("iss" to config.issuer.json(), "sub" to "fixture-user".json(), "iat" to (now / 1000).json(), "exp" to (now / 1000 + 300).json())
        fun jwt(claims: JsonObject, type: String) = JWSObject(JWSHeader.Builder(JWSAlgorithm.ES256).keyID(issuer.keyID).type(JOSEObjectType(type)).build(), Payload(JsonDocument.of(claims).canonicalText())).apply { sign(ECDSASigner(issuer)) }.serialize()
        val token = jsonObject("access_token" to jwt(base.with("aud" to config.audience.json(), "client_id" to config.clientId.json(), "jti" to "fixture-access".json(), "scope" to "remote.access".json(), "cnf" to jsonObject("jkt" to signer.publicKey.thumbprint.json())), "at+jwt").json(),
            "id_token" to jwt(base.with("aud" to config.clientId.json(), "nonce" to login.nonce.json()), "JWT").json(), "token_type" to "DPoP".json(), "expires_in" to 300L.json())
        val keys = IssuerKeys.parse(JsonDocument.of(jsonObject("keys" to JsonArray(listOf(JsonDocument.parse(issuer.toPublicJWK().toJSONString()).root)))).canonicalBytes())
        return http.resource(config, TokenVerifier.authorizationCodeResponse(JsonDocument.of(token).canonicalBytes(), exchange, keys, now), signer)
    }
    private fun time(offset: Long) = Instant.ofEpochMilli(System.currentTimeMillis() + offset).toString().json()
    private fun status(state: String = "uploading", expected: FileManifest = manifest) = jsonObject("file_id" to file.json(), "runtime_id" to runtime.json(), "session_id" to session.json(), "direction" to "to_host".json(),
        "name" to expected.name.json(), "size_bytes" to expected.sizeBytes.json(), "sha256" to expected.sha256.json(), "state" to state.json(), "created_at" to time(-1000), "upload_expires_at" to time(120_000), "expires_at" to time(3_600_000))
    private fun headers() = jsonObject("Content-Type" to "application/octet-stream".json(), "Content-Length" to manifest.sizeBytes.toString().json(), "Cache-Control" to "no-store".json(),
        "X-Amz-Checksum-Sha256" to Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(bytes)).json(), "X-Amz-Server-Side-Encryption" to "aws:kms".json(), "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id" to "fixture-kms".json())
    private fun capability() = jsonObject("url" to objects.url("/quarantine?X-Amz-Signature=PRIVATE_CAPABILITY").toString().json(), "method" to "PUT".json(), "headers" to headers(), "expires_at" to time(60_000))
    private fun prepared(capability: JsonObject = capability(), value: JsonObject = status()) = jsonObject("file" to value, "upload" to capability)
    private fun reply(data: JsonObject, code: Int = 200) = MockResponse().setResponseCode(code).setHeader("Content-Type", "application/json").setBody(JsonDocument.of(jsonObject("ok" to JsonBoolean(true), "data" to data)).canonicalText())
    private fun proof(request: RecordedRequest): JsonObject {
        val signed = JWSObject.parse(request.getHeader("DPoP")); assertTrue(signed.verify(ECDSAVerifier(key)))
        return JsonDocument.parse(signed.payload.toBytes()).root
    }
    @Test fun authenticatedRegistrationStreamsAnAnonymousVerifiedPutThenCommitsAndQueries(): Unit = runBlocking {
        val api = api()
        service.enqueue(MockResponse().setResponseCode(401).setHeader("Content-Type", "application/json").setHeader("DPoP-Nonce", "registration-nonce")
            .setHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"").setBody("{\"ok\":false,\"error\":{\"code\":\"auth.proof_invalid\"}}"))
        service.enqueue(reply(prepared(), 201).setHeader("DPoP-Nonce", "service-next-nonce"))
        val handle = api.registerFile(runtime, session, request, manifest)
        val first = service.takeRequest(); val retried = service.takeRequest()
        assertEquals("POST", retried.method); assertEquals("/v1/runtimes/$runtime/sessions/$session/files", retried.path)
        assertEquals("registration-nonce", proof(retried).string("nonce")); assertNotEquals(proof(first).string("jti"), proof(retried).string("jti"))
        assertTrue(retried.getHeader("Authorization")!!.startsWith("DPoP "))
        val body = JsonDocument.parse(retried.body.readByteArray()).root
        assertEquals(request, body.string("request_id")); assertTrue(FileManifest.parse(JsonObject(body.fields.filterKeys { it != "request_id" })).same(manifest))
        assertTrue(handle.canUpload); assertFalse(handle.toString().contains("PRIVATE")); assertFalse(handle.file.toString().contains("PRIVATE"))
        objects.enqueue(MockResponse().setResponseCode(200).setHeader("DPoP-Nonce", "evil-object-nonce").setHeader("Set-Cookie", "private=secret"))
        val progress = arrayListOf<Long>()
        api.uploadFile(handle, { ByteArrayInputStream(bytes) }, progress::add)
        val put = objects.takeRequest()
        assertEquals("PUT", put.method); assertNull(put.getHeader("Authorization")); assertNull(put.getHeader("DPoP")); assertNull(put.getHeader("Cookie"))
        assertEquals(bytes.size.toString(), put.getHeader("Content-Length")); assertEquals("no-store", put.getHeader("Cache-Control"))
        assertEquals("aws:kms", put.getHeader("X-Amz-Server-Side-Encryption")); assertArrayEquals(bytes, put.body.readByteArray()); assertEquals(manifest.sizeBytes, progress.last())
        service.enqueue(reply(jsonObject("file" to status("scanning")), 202))
        assertEquals(FileTransferState.SCANNING, api.commitFile(file).state)
        val commit = service.takeRequest(); assertEquals("/v1/files/$file/commit", commit.path); assertEquals("service-next-nonce", proof(commit).string("nonce"))
        service.enqueue(reply(jsonObject("file" to status("clean"))))
        assertEquals(FileTransferState.CLEAN, api.fileStatus(file).state); assertEquals("/v1/files/$file", service.takeRequest().path)
    }
    @Test fun malformedCapabilitiesAndCrossSessionManifestsFailBeforeSendingBytes(): Unit = runBlocking {
        val api = api()
        val base = capability()
        val invalid = listOf(base.with("url" to "http://localhost/private".json()), base.with("url" to "https://user:secret@localhost/private".json()),
            base.with("url" to objects.url("/private#fragment").toString().json()), base.with("method" to "GET".json()), base.with("expires_at" to time(2_000_000)),
            base.with("headers" to headers().with("Authorization" to "secret".json())), base.with("headers" to headers().with("Cookie" to "secret".json())),
            base.with("headers" to headers().with("DPoP" to "secret".json())), base.with("headers" to headers().with("content-type" to "application/octet-stream".json())),
            base.with("headers" to headers().with("Content-Length" to "7".json())), base.with("headers" to headers().with("X-Amz-Checksum-Sha256" to "invalid".json())))
        for (bad in invalid) {
            service.enqueue(reply(prepared(bad), 201))
            try { api.registerFile(runtime, session, request, manifest); fail("unsafe capability accepted") } catch (_: ProtocolException) { }
            service.takeRequest()
        }
        service.enqueue(reply(prepared(value = status().with("session_id" to runtime.json())), 201))
        try { api.registerFile(runtime, session, request, manifest); fail("cross-session response accepted") } catch (_: ProtocolException) { }
        service.takeRequest(); assertEquals(0, objects.requestCount)
    }
    @Test fun redirectsDoNotCarryTheBodyOrAnyCredentialsToAnotherRequest(): Unit = runBlocking {
        val api = api(); service.enqueue(reply(prepared(), 201)); val handle = api.registerFile(runtime, session, request, manifest); service.takeRequest()
        objects.enqueue(MockResponse().setResponseCode(307).setHeader("Location", objects.url("/redirect-target")))
        try { api.uploadFile(handle, { ByteArrayInputStream(bytes) }); fail("redirect accepted") } catch (error: RemoteRequestException) { assertEquals("file.upload_rejected", error.code) }
        objects.takeRequest(); assertEquals(1, objects.requestCount)
    }
    @Test fun changedSourcesAndForeignApiHandlesCannotCompleteAnUpload(): Unit = runBlocking {
        val api = api(); service.enqueue(reply(prepared(), 201)); val handle = api.registerFile(runtime, session, request, manifest); service.takeRequest()
        var opened = false
        try { api().uploadFile(handle, { opened = true; ByteArrayInputStream(bytes) }); fail("foreign handle accepted") } catch (error: RemoteRequestException) { assertEquals("auth.identity_mismatch", error.code) }
        assertFalse(opened); assertEquals(0, objects.requestCount)
        objects.enqueue(MockResponse().setResponseCode(200))
        try { api.uploadFile(handle, { ByteArrayInputStream("xyz".toByteArray()) }); fail("changed source accepted") } catch (error: RemoteRequestException) { assertEquals("file.integrity_mismatch", error.code) }
        assertEquals(1, service.requestCount)
    }
    @Test fun cancellationClosesTheOpenedContentSource(): Unit = runBlocking {
        val api = api(); service.enqueue(reply(prepared(), 201)); val handle = api.registerFile(runtime, session, request, manifest); service.takeRequest()
        val entered = CountDownLatch(1); val released = CountDownLatch(1); val closed = AtomicBoolean()
        val source = object : InputStream() {
            override fun read(): Int = error("bulk reads required")
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int { entered.countDown(); released.await(5, TimeUnit.SECONDS); return -1 }
            override fun close() { closed.set(true); released.countDown() }
        }
        objects.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
        val transfer = launch { api.uploadFile(handle, { source }) }
        assertTrue(withContext(Dispatchers.IO) { entered.await(3, TimeUnit.SECONDS) })
        transfer.cancelAndJoin(); assertTrue(closed.get())
    }
    @Test fun emptyFilesHaveAnExactZeroLengthBodyAndExpiredCapabilitiesNeverOpenTheSource(): Unit = runBlocking {
        val api = api()
        val empty = FileManifest("empty.txt", 0, digest(byteArrayOf()))
        val cap = capability().with("headers" to jsonObject("Content-Type" to "application/octet-stream".json(), "Content-Length" to "0".json()))
        service.enqueue(reply(prepared(cap, status(expected = empty)), 201))
        val handle = api.registerFile(runtime, session, request, empty); service.takeRequest()
        objects.enqueue(MockResponse().setResponseCode(200))
        api.uploadFile(handle, { ByteArrayInputStream(byteArrayOf()) })
        assertEquals(0, objects.takeRequest().bodySize)
        service.enqueue(reply(prepared(capability().with("expires_at" to time(-1))), 201))
        val expired = api.registerFile(runtime, session, request, manifest); service.takeRequest()
        var opened = false
        try { api.uploadFile(expired, { opened = true; ByteArrayInputStream(bytes) }); fail("expired upload accepted") } catch (error: RemoteRequestException) { assertEquals("file.upload_expired", error.code) }
        assertFalse(opened); assertEquals(1, objects.requestCount)
    }
    @Test fun objectTlsIdentityIsVerifiedBeforeReadingContent(): Unit = runBlocking {
        val api = api()
        val bad = capability().with("url" to objects.url("/quarantine").newBuilder().host("127.0.0.1").build().toString().json())
        service.enqueue(reply(prepared(bad), 201))
        val handle = api.registerFile(runtime, session, request, manifest); service.takeRequest()
        var opened = false
        try { api.uploadFile(handle, { opened = true; ByteArrayInputStream(bytes) }); fail("wrong TLS identity accepted") } catch (error: RemoteRequestException) { assertEquals("file.upload_failed", error.code) }
        assertFalse(opened)
    }
    @Test fun capabilityExpiryClosesAStalledProviderWithoutWaitingForItsReadToFinish(): Unit = runBlocking {
        val api = api()
        service.enqueue(reply(prepared(capability().with("expires_at" to time(2000))), 201))
        val handle = api.registerFile(runtime, session, request, manifest); service.takeRequest()
        val released = CountDownLatch(1); val closed = AtomicBoolean()
        val source = object : InputStream() {
            override fun read(): Int = error("bulk reads required")
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int { released.await(5, TimeUnit.SECONDS); return -1 }
            override fun close() { closed.set(true); released.countDown() }
        }
        objects.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
        try {
            withTimeout(4000) { api.uploadFile(handle, { source }) }
            fail("stalled provider outlived the capability")
        } catch (error: RemoteRequestException) { assertEquals("file.upload_expired", error.code) }
        assertTrue(closed.get())
    }
    @Test fun workflowSavesMetadataBeforeNetworkAndReopensWithoutAStoredSourceOrCapability(): Unit = runBlocking {
        lateinit var config: LoginConfiguration
        val api = api { config = it }
        val owner = CommandOwner(java.util.UUID.randomUUID().toString(), config.organizationId, config.fingerprint, session, request)
        val saved = java.util.concurrent.ConcurrentHashMap<String, StoredFileUpload>()
        val journal = object : FileUploadJournal {
            override val owner = owner
            override suspend fun createUpload(intent: FileUploadIntent, now: Long): StoredFileUpload = saved.computeIfAbsent(intent.requestId) { StoredFileUpload(intent, null, null, now, now) }
            override suspend fun uploads(runtime: String, session: String) = saved.values.filter { it.intent.runtimeId == runtime && it.intent.sessionId == session }
            override suspend fun registeredUpload(id: String, fileId: String, now: Long): StoredFileUpload = saved[id]!!.let { StoredFileUpload(it.intent, fileId, it.messageId, it.createdAt, now).also { next -> saved[id] = next } }
            override suspend fun removeUpload(id: String) { saved.remove(id) }
        }
        val phase = java.util.concurrent.atomic.AtomicReference("scanning")
        val ready = AtomicBoolean()
        val registrations = java.util.concurrent.atomic.AtomicInteger()
        val failure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        service.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = try {
                when {
                    request.path == "/v1/runtimes/$runtime/sessions/$session/files" -> {
                        val body = JsonDocument.parse(request.body.readByteArray()).root
                        assertNotNull(saved[body.string("request_id")]); registrations.incrementAndGet()
                        reply(prepared(), 201)
                    }
                    request.path == "/v1/files/$file/commit" -> reply(jsonObject("file" to status("scanning")), 202)
                    request.path == "/v1/files/$file" -> {
                        val state = phase.get()
                        val body = if (state == "clean") status(state).with("delivery" to if (ready.get()) jsonObject("state" to "ready".json(), "expires_at" to time(4000)) else jsonObject("state" to "waiting".json())) else status(state)
                        reply(jsonObject("file" to body))
                    }
                    else -> MockResponse().setResponseCode(404)
                }
            } catch (error: Throwable) { failure.set(error); MockResponse().setResponseCode(500) }
        }
        objects.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = try { assertEquals(file, saved.values.single().fileId); MockResponse().setResponseCode(200) }
                catch (error: Throwable) { failure.set(error); MockResponse().setResponseCode(500) }
        }
        val closed = AtomicBoolean()
        val source = object : FileInputSource {
            override val name = manifest.name
            override fun open() = ByteArrayInputStream(bytes)
            override fun close() { closed.set(true) }
        }
        val grant = RelayScope(listOf("file.upload"), emptyList(), listOf(session))
        val flow = api.fileUploads(runtime, session, null, grant, journal, this)
        try {
            flow.select(source)
            val scanning = withTimeout(5000) { flow.state.first { !it.busy && it.rows.singleOrNull()?.phase == UploadPhase.SCANNING } }
            val id = scanning.rows.single().stored.intent.requestId
            assertTrue(closed.get()); assertEquals(1, registrations.get())
            phase.set("clean")
            withTimeout(4000) { flow.state.first { it.rows.singleOrNull()?.phase == UploadPhase.WAITING } }
            flow.toggle(id); assertTrue(flow.state.value.selected.isEmpty())
            ready.set(true)
            withTimeout(4000) { flow.state.first { it.rows.singleOrNull()?.ready() == true } }
            flow.toggle(id); assertEquals(listOf(file), flow.selectedFiles())
            assertFalse(String(saved.values.single().intent.bytes()).contains("PRIVATE_CAPABILITY"))
        } finally { flow.close() }
        assertTrue(flow.state.value.rows.isEmpty())
        phase.set("uploading")
        api.fileUploads(runtime, session, null, grant, journal, this).use { reopened ->
            withTimeout(4000) { reopened.state.first { it.rows.singleOrNull()?.phase == UploadPhase.NEEDS_SOURCE } }
            assertEquals(1, registrations.get()); assertEquals(1, saved.size)
        }
        failure.get()?.let { throw AssertionError("workflow fixture failed", it) }
    }
    private fun exportStatus() = status("clean").with("direction" to "from_host".json())
    private fun binary(value: ByteArray = bytes) = MockResponse().setHeader("Content-Type", "application/octet-stream").setHeader("Content-Encoding", "identity")
        .setHeader("X-DSH-Content-SHA256", manifest.sha256).setBody(okio.Buffer().write(value))
    @Test fun exportDownloadUsesCurrentMetadataAndFreshDpopNonceBeforeOpeningPrivateStaging(): Unit = runBlocking {
        val api = api(); val file = RemoteExportStatus.parse(exportStatus())
        service.enqueue(reply(jsonObject("file" to exportStatus())))
        service.enqueue(MockResponse().setResponseCode(401).setHeader("Content-Type", "application/json").setHeader("DPoP-Nonce", "export-download-nonce")
            .setHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"").setBody("{\"ok\":false,\"error\":{\"code\":\"auth.proof_invalid\"}}"))
        service.enqueue(binary())
        val out = java.io.ByteArrayOutputStream(); var opened = 0
        api.downloadExport(file, { opened++; out })
        assertEquals(1, opened); assertArrayEquals(bytes, out.toByteArray())
        val traffic = List(3) { service.takeRequest() }
        assertEquals(listOf("/v1/files/${file.id}", "/v1/files/${file.id}/content", "/v1/files/${file.id}/content"), traffic.map { it.path })
        assertTrue(traffic.all { it.method == "GET" && it.getHeader("Authorization")!!.startsWith("DPoP ") })
        assertEquals("export-download-nonce", proof(traffic.last()).string("nonce"))
        assertEquals("identity", traffic.last().getHeader("Accept-Encoding")); assertNull(traffic.last().getHeader("Range"))
        assertNotEquals(proof(traffic[1]).string("jti"), proof(traffic[2]).string("jti"))
    }
    @Test fun exportDownloadRejectsChangedIdentityCorruptBytesAndRedirects(): Unit = runBlocking {
        val api = api(); val file = RemoteExportStatus.parse(exportStatus())
        val badResponses = listOf(binary("xyz".toByteArray()), binary("ab".toByteArray()), binary().setHeader("X-DSH-Content-SHA256", "b".repeat(64)),
            binary().setHeader("Content-Encoding", "gzip"), binary().setResponseCode(206), MockResponse().setResponseCode(302).setHeader("Location", objects.url("/private")))
        for (response in badResponses) {
            service.enqueue(reply(jsonObject("file" to exportStatus()))); service.enqueue(response)
            try { api.downloadExport(file, { java.io.ByteArrayOutputStream() }); fail("invalid download accepted") } catch (_: RemoteRequestException) { }
        }
        var opened = false
        service.enqueue(reply(jsonObject("file" to exportStatus().with("session_id" to runtime.json()))))
        try { api.downloadExport(file, { opened = true; java.io.ByteArrayOutputStream() }); fail("changed target accepted") } catch (_: RemoteRequestException) { }
        assertFalse(opened); assertEquals(0, objects.requestCount)
    }
    @Test fun exportCancellationClosesPrivateStagingAndDoesNotBlockOrdinaryApiReads(): Unit = runBlocking {
        val api = api(); val file = RemoteExportStatus.parse(exportStatus())
        service.enqueue(reply(jsonObject("file" to exportStatus()))); service.enqueue(binary().throttleBody(1, 1, TimeUnit.SECONDS))
        val out = object : java.io.ByteArrayOutputStream() { val closed = AtomicBoolean(); override fun close() { closed.set(true) } }
        val started = CompletableDeferred<Unit>()
        val task = launch { api.downloadExport(file, { started.complete(Unit); out }) }
        withTimeout(3000) { started.await() }
        service.enqueue(reply(jsonObject("file" to exportStatus())))
        withTimeout(1500) { assertEquals(file.id, api.exportStatus(file.id).id) }
        task.cancelAndJoin(); assertTrue(out.closed.get())
    }

    private fun pushBinding(state: String = "pending", id: String = request) = jsonObject("binding_id" to id.json(), "state" to state.json(), "challenge_expires_at" to time(120_000), "expires_at" to time(600_000))
    @Test fun pushRegistrationConfirmsOnlyTheOriginalProviderChallengeAndReadsFreshReferences(): Unit = runBlocking {
        val api = api()
        val intent = PushRegistration(request, request, "c" + "A".repeat(21), "a".repeat(64))
        service.enqueue(reply(jsonObject("binding" to pushBinding()), 201))
        assertEquals(PushBindingState.PENDING, api.registerPush(intent).state)
        val registration = service.takeRequest()
        assertEquals("/v1/push-bindings", registration.path); assertEquals("POST", registration.method)
        assertEquals(JsonDocument.of(intent.json()).canonicalText(), registration.body.readUtf8()); proof(registration)
        val packet = PushPacket.parse(mapOf("v" to "1", "kind" to "registration_challenge", "binding_id" to request, "challenge" to "A".repeat(43), "expires_at" to java.time.Instant.now().plusSeconds(60).toString())) as PushPacket.Challenge
        service.enqueue(reply(jsonObject("binding" to pushBinding("active"))))
        assertEquals(PushBindingState.ACTIVE, api.confirmPush(request, packet).state)
        val confirmation = service.takeRequest(); assertEquals("/v1/push-bindings/$request/confirm", confirmation.path)
        assertEquals(setOf("challenge"), JsonDocument.parse(confirmation.body.readByteArray()).root.fields.keys)
        val reference = jsonObject("notification_id" to file.json(), "binding_id" to request.json(), "kind" to "approval".json(), "reference_id" to request.json(), "runtime_id" to runtime.json(),
            "runtime_epoch" to request.json(), "session_id" to session.json(), "state" to "pending".json(), "availability" to "online".json(), "expires_at" to time(60_000))
        service.enqueue(reply(jsonObject("reference" to reference)))
        assertTrue(api.notification(file, request).actionable()); assertEquals("GET", service.takeRequest().method)
        service.enqueue(reply(jsonObject("reference" to reference.with("binding_id" to runtime.json()))))
        try { api.notification(file, request); fail("another binding reference accepted") } catch (error: RemoteRequestException) { assertEquals("auth.identity_mismatch", error.code) }
        service.takeRequest()
        var current = true
        current = false
        try { api.registerPush(intent) { if (!current) throw RemoteRequestException("push.stale") }; fail("retired owner mutated the binding") } catch (error: RemoteRequestException) { assertEquals("push.stale", error.code) }
        assertEquals(4, service.requestCount)
    }
    @Test fun logoutPushCleanupIsAnonymousBoundedAndNeverFollowsRedirects(): Unit = runBlocking {
        val secret = "A".repeat(43)
        service.enqueue(MockResponse().setResponseCode(204).setHeader("DPoP-Nonce", "untrusted-cleanup-nonce"))
        http.revokePush(origin, request, secret)
        val cleanup = service.takeRequest(); assertEquals("DELETE", cleanup.method); assertEquals("DSH-Push-Revoke $secret", cleanup.getHeader("Authorization"))
        assertNull(cleanup.getHeader("DPoP")); assertNull(cleanup.getHeader("Cookie")); assertEquals(0, cleanup.bodySize)
        service.enqueue(MockResponse().setResponseCode(307).setHeader("Location", objects.url("/must-not-delete")))
        try { http.revokePush(origin, request, secret); fail("cleanup redirect accepted") } catch (error: RemoteRequestException) { assertEquals("push.cleanup_failed", error.code) }
        assertEquals(0, objects.requestCount)
    }
    @Test fun knownSessionLookupAndScopedAnswerStatusNeverEnumerateOtherSessions(): Unit = runBlocking {
        val api = api()
        val grant = jsonObject("id" to runtime.json(), "host_id" to file.json(), "organization_id" to request.json(), "protocol_version" to 1L.json(),
            "access" to jsonObject("role" to "operator".json(), "grant_version" to 7L.json(), "scope" to RelayScope(listOf("session.read", "question.answer"), emptyList(), listOf(session)).json()))
        val row = jsonObject("session_id" to session.json(), "workspace_id" to JsonNull, "state" to "available".json(), "last_persisted_seq" to (-1L).json(), "updated_at" to Instant.now().toString().json())
        service.enqueue(reply(jsonObject("runtime" to grant, "session" to row)))
        val known = api.sessionTarget(runtime, session)
        assertFalse(known.runtime.canList()); assertTrue(known.runtime.canRead()); assertEquals(session, known.session.id)
        val lookup = service.takeRequest(); assertEquals("/v1/runtimes/$runtime/sessions/$session", lookup.path); proof(lookup)
        service.enqueue(reply(jsonObject("request_id" to request.json(), "session_id" to session.json(), "state" to "settled".json(), "payload_sha256" to "a".repeat(64).json(), "updated_at" to Instant.now().toString().json())))
        assertEquals(RemoteCommandState.SETTLED, api.questionAnswerStatus(runtime, session, request).state)
        val status = service.takeRequest(); assertEquals("/v1/runtimes/$runtime/sessions/$session/question-answers/$request", status.path); proof(status)
        service.enqueue(reply(jsonObject("runtime" to grant, "session" to row.with("session_id" to runtime.json()))))
        try { api.sessionTarget(runtime, session); fail("another session identity accepted") } catch (error: RemoteRequestException) { assertEquals("access.denied", error.code) }
        assertEquals(3, service.requestCount)
    }
    @Test fun questionTicketUsesItsOwnAnswerAuthorityWithoutGenericStatus(): Unit = runBlocking {
        val api = api(); val selected = RelayScope(listOf("session.read", "question.answer"), emptyList(), listOf(session))
        service.enqueue(reply(jsonObject("ticket" to "A".repeat(43).json(), "runtime_id" to runtime.json(), "grant_version" to 7L.json(), "scope" to selected.json(), "expires_at" to Instant.now().plusSeconds(30).toString().json()), 201))
        api.sessionTicket(runtime, request, selected)
        val call = service.takeRequest(); assertEquals("/v1/realtime/tickets", call.path)
        assertEquals(selected.actions, RelayScope.parse(JsonDocument.parse(call.body.readByteArray()).root.obj("scope")).actions)
        assertFalse("command.status" in selected.actions)
    }

}
