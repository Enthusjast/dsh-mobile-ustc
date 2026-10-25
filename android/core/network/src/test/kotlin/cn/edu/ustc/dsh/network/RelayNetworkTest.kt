package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.auth.*
import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import cn.edu.ustc.dsh.command.*
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import okhttp3.*
import okhttp3.mockwebserver.*
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.ByteString
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.net.URI
import java.time.Instant
import java.util.concurrent.atomic.AtomicReference
import java.util.UUID

class RelayNetworkTest {
    private val server = MockWebServer()
    private val certificate = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
    private val serverTLS = HandshakeCertificates.Builder().heldCertificate(certificate).build()
    private val clientTLS = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
    private val http: LoginHttp
    private val issuer = ECKeyGenerator(Curve.P_256).keyID("fixture-issuer").generate()
    private val key = ECKeyGenerator(Curve.P_256).generate()
    private val signer = object : DeviceProofSigner {
        override val publicKey = PublicProofKey(JsonDocument.parse(key.toPublicJWK().toJSONString()).root)
        override fun signJose(signingInput: ByteArray): ByteArray = ECDSASigner(key).sign(JWSHeader(JWSAlgorithm.ES256), signingInput).decode()
    }
    private val device = "22222222-2222-4222-8222-222222222222"
    private val runtime = "33333333-3333-4333-8333-333333333333"
    private val connection = "44444444-4444-4444-8444-444444444444"
    private val challengeId = "55555555-5555-4555-8555-555555555555"
    private val sessionId = "66666666-6666-4666-8666-666666666666"
    private val scope = RelayScope(listOf("session.read"), emptyList(), listOf(sessionId))
    private val token = "A".repeat(43)
    private val peerFailure = AtomicReference<Throwable?>()
    private val heartbeats = java.util.concurrent.atomic.AtomicInteger()
    init {
        server.useHttps(serverTLS.sslSocketFactory(), false); server.start()
        http = LoginHttp.forTests(OkHttpClient.Builder().sslSocketFactory(clientTLS.sslSocketFactory(), clientTLS.trustManager).build())
    }
    @After fun cleanup() { server.shutdown(); peerFailure.get()?.let { throw AssertionError("Relay fixture validation failed", it) } }
    private val origin get() = server.url("/").toString().trimEnd('/')
    private val config get() = LoginConfiguration.parse(JsonDocument.of(jsonObject(
        "issuer" to "$origin/issuer".json(), "client_id" to "mobile".json(), "redirect_uri" to LoginConfiguration.REDIRECT_URI.json(), "resource" to "urn:dsh-remote".json(),
        "audience" to "urn:dsh-remote".json(), "remote_origin" to origin.json(), "organization_id" to "11111111-1111-4111-8111-111111111111".json(),
        "scopes" to JsonArray(listOf("openid".json(), "remote.access".json())), "endpoint_origins" to JsonArray(listOf(origin.json())), "signing_algorithms" to JsonArray(listOf("ES256".json())),
    )).canonicalBytes())
    private fun jwt(claims: JsonObject, type: String) = JWSObject(JWSHeader.Builder(JWSAlgorithm.ES256).keyID(issuer.keyID).type(JOSEObjectType(type)).build(), Payload(JsonDocument.of(claims).canonicalText())).apply { sign(ECDSASigner(issuer)) }.serialize()
    private fun api(): RemoteApi {
        val config = config
        val now = System.currentTimeMillis()
        val discovery = OidcDiscovery.parse(JsonDocument.of(jsonObject("issuer" to config.issuer.json(), "authorization_endpoint" to "$origin/auth".json(), "token_endpoint" to "$origin/token".json(),
            "jwks_uri" to "$origin/jwks".json(), "response_types_supported" to JsonArray(listOf("code".json())), "id_token_signing_alg_values_supported" to JsonArray(listOf("ES256".json())))).canonicalBytes(), config)
        val login = PendingLogin(discovery, signer.publicKey.thumbprint, now)
        val exchange = login.acceptCallback(LoginConfiguration.REDIRECT_URI + "?state=${login.state}&code=opaque", now)
        val base = jsonObject("iss" to config.issuer.json(), "sub" to "school-user".json(), "iat" to (now / 1000).json(), "exp" to (now / 1000 + 300).json())
        val response = jsonObject("access_token" to jwt(base.with("aud" to config.audience.json(), "client_id" to config.clientId.json(), "jti" to "access-id".json(), "scope" to "remote.access".json(), "cnf" to jsonObject("jkt" to signer.publicKey.thumbprint.json())), "at+jwt").json(),
            "id_token" to jwt(base.with("aud" to config.clientId.json(), "nonce" to login.nonce.json()), "JWT").json(), "token_type" to "DPoP".json(), "expires_in" to 300L.json())
        val keys = IssuerKeys.parse(JsonDocument.of(jsonObject("keys" to JsonArray(listOf(JsonDocument.parse(issuer.toPublicJWK().toJSONString()).root)))).canonicalBytes())
        return http.resource(config, TokenVerifier.authorizationCodeResponse(JsonDocument.of(response).canonicalBytes(), exchange, keys, now), signer)
    }
    private fun time(offset: Long) = Instant.ofEpochMilli(System.currentTimeMillis() + offset).toString().json()
    private fun json(root: JsonObject) = MockResponse().setHeader("Content-Type", "application/json").setBody(JsonDocument.of(root).canonicalText())
    private val bindingId = "88888888-8888-4888-8888-888888888888"
    private val bindingCode = "H".repeat(42) + "A"
    private fun bindingData() = jsonObject("enrollment_id" to bindingId.json(), "request_id" to sessionId.json(), "organization_id" to "11111111-1111-4111-8111-111111111111".json(), "organization_name" to "学校夹具".json(),
        "host_id" to device.json(), "host_alias" to "夹具电脑".json(), "installation_id" to connection.json(), "installation_key_jkt" to "A".repeat(43).json(), "runtime_id" to runtime.json(),
        "profile_ref" to "fixture".json(), "protocol_version" to 1L.json(), "state" to "pending".json(), "expires_at" to time(299_000), "host_confirmed" to JsonBoolean(false),
        "user_confirmed" to JsonBoolean(false), "user_confirmed_by_me" to JsonBoolean(false), "workspaces" to JsonArray(listOf(jsonObject("reference" to "project".json(), "workspace_id" to sessionId.json()))))
    private fun bindingReply(data: JsonObject) = json(jsonObject("ok" to JsonBoolean(true), "data" to data))
    private fun confirmed(data: JsonObject, host: Boolean = false) = data.with("state" to (if (host) "approved" else "user_confirmed").json(), "user_confirmed" to JsonBoolean(true), "user_confirmed_by_me" to JsonBoolean(true), "host_confirmed" to JsonBoolean(host))
    private fun confirmReply(data: JsonObject) = bindingReply(JsonObject(data.fields.filterKeys { it in setOf("enrollment_id", "host_id", "runtime_id", "state", "expires_at", "host_confirmed", "user_confirmed") }))

    @Test fun bindingConfirmationRechecksTheExactReviewAndResolvesCurrentActorBeforeSuccess(): Unit = runBlocking {
        val initial = bindingData(); val accepted = confirmed(initial, host = true)
        server.enqueue(bindingReply(initial)); server.enqueue(bindingReply(initial.with("host_confirmed" to JsonBoolean(true))))
        server.enqueue(confirmReply(accepted)); server.enqueue(bindingReply(accepted))
        val request = api().prepareHostBinding(bindingId, bindingCode)
        assertTrue(request.details.canConfirm()); assertFalse(request.toString().contains(bindingCode))
        var dispatches = 0
        val result = request.confirm { dispatches++ }
        assertEquals("approved", result.state); assertTrue(result.confirmedByMe); assertEquals(1, dispatches)
        val traffic = List(4) { server.takeRequest() }
        assertEquals(listOf("/preview", "/preview", "/confirm", ""), traffic.map { it.path!!.removePrefix("/v1/enrollments/$bindingId") })
        assertEquals(listOf("POST", "POST", "POST", "GET"), traffic.map { it.method })
        val proofIds = traffic.map { captured ->
            assertFalse(captured.path!!.contains(bindingCode)); assertTrue(captured.getHeader("Authorization")!!.startsWith("DPoP "))
            val proof = JWSObject.parse(captured.getHeader("DPoP")); assertTrue(proof.verify(ECDSAVerifier(key)))
            JsonDocument.parse(proof.payload.toBytes()).root.string("jti")
        }
        assertEquals(4, proofIds.toSet().size)
        for (captured in traffic.take(3)) assertEquals(setOf("code"), JsonDocument.parse(captured.body.readUtf8()).root.fields.keys)
        assertThrows(HostBindingException::class.java) { runBlocking { request.confirm() } }; assertEquals(4, server.requestCount)
    }

    @Test fun bindingReviewChangeOrExpiryCannotPostAConfirmation(): Unit = runBlocking {
        for (change in listOf("profile_ref" to "changed".json(), "state" to "expired".json())) {
            val initial = bindingData()
            server.enqueue(bindingReply(initial)); server.enqueue(bindingReply(initial.with(change)))
            api().prepareHostBinding(bindingId, bindingCode).use { request ->
                val error = assertThrows(HostBindingException::class.java) { runBlocking { request.confirm() } }
                assertEquals(if (change.first == "state") "binding.expired" else "binding.details_changed", error.code)
            }
            repeat(2) { assertTrue(server.takeRequest().path!!.endsWith("/preview")) }
        }
        assertEquals(4, server.requestCount)
    }

    @Test fun lostBindingReplyIsQueriedWithoutAutomaticallyRepeatingTheWrite(): Unit = runBlocking {
        val resource = api(); val initial = bindingData(); val accepted = confirmed(initial)
        server.enqueue(bindingReply(initial)); server.enqueue(bindingReply(initial))
        server.enqueue(confirmReply(accepted).setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST))
        val prepared = resource.prepareHostBinding(bindingId, bindingCode)
        var dispatched = false
        assertThrows(RemoteRequestException::class.java) { runBlocking { prepared.confirm { dispatched = true } } }
        assertTrue(dispatched); assertEquals(3, server.requestCount)
        server.enqueue(bindingReply(accepted))
        assertTrue(resource.bindingStatus(bindingId).confirmedByMe)
        val captured = List(4) { server.takeRequest() }; assertEquals(1, captured.count { it.path!!.endsWith("/confirm") })
        assertEquals("GET", captured.last().method)
    }

    @Test fun retiringAReviewDuringRevalidationCannotReachTheMutatingEndpoint(): Unit = runBlocking {
        val initial = bindingData()
        server.enqueue(bindingReply(initial)); server.enqueue(bindingReply(initial).setBodyDelay(200, java.util.concurrent.TimeUnit.MILLISECONDS))
        val prepared = api().prepareHostBinding(bindingId, bindingCode)
        server.takeRequest()
        val result = async(Dispatchers.Default) { runCatching { prepared.confirm() }.exceptionOrNull() }
        assertTrue(withContext(Dispatchers.IO) { server.takeRequest(3, java.util.concurrent.TimeUnit.SECONDS) }!!.path!!.endsWith("/preview"))
        prepared.close()
        assertTrue(withTimeout(3000) { result.await() } is CancellationException)
        assertEquals(2, server.requestCount)
    }

    private fun bindingDirectory(data: JsonObject, visible: Boolean = true, expired: Boolean = false): MockResponse {
        var access = jsonObject("role" to "owner".json(), "grant_version" to 1L.json(), "scope" to RelayScope(listOf("session.list", "session.read"), listOf(sessionId), emptyList()).json())
        if (expired) access = access.with("expires_at" to time(-1000))
        return bindingReply(jsonObject("items" to JsonArray(if (!visible) emptyList() else listOf(jsonObject("id" to runtime.json(), "host_id" to data["host_id"], "organization_id" to data["organization_id"],
            "protocol_version" to 1L.json(), "access" to access)))))
    }
    private suspend fun HostBindingFlow.await(phase: HostBindingPhase) = withTimeout(5000) { state.first { it.phase == phase } }

    @Test fun bindingFlowWaitsForIndependentHostConfirmationAndAFreshDirectoryGrant(): Unit = runBlocking {
        val data = bindingData(); val partial = confirmed(data)
        server.enqueue(bindingReply(data)); server.enqueue(bindingReply(data)); server.enqueue(confirmReply(partial)); server.enqueue(bindingReply(partial))
        var ready = 0
        HostBindingFlow(api(), this, null, {}, { ready++ }, HostBindingOptions(60_000, 60_000)).use { flow ->
            flow.foreground(true); flow.preview(bindingId, bindingCode); flow.await(HostBindingPhase.REVIEW)
            assertFalse(flow.state.value.toString().contains(bindingCode)); assertEquals(0, ready)
            flow.confirm(); flow.await(HostBindingPhase.WAITING_HOST)
            assertEquals(bindingId, flow.resumeId); assertEquals(0, ready)
            flow.foreground(false); assertEquals(HostBindingPhase.PAUSED, flow.state.value.phase)
            server.enqueue(bindingReply(confirmed(data, host = true))); server.enqueue(bindingDirectory(data))
            flow.foreground(true); flow.await(HostBindingPhase.READY)
            assertEquals(1, ready)
            val traffic = List(6) { server.takeRequest() }
            assertEquals(1, traffic.count { it.path!!.endsWith("/confirm") })
            assertEquals(listOf("GET", "GET"), traffic.takeLast(2).map { it.method })
        }
    }
    @Test fun backgroundingAnUnsubmittedReviewRetiresItsCodeAndStaleConfirmAction(): Unit = runBlocking {
        server.enqueue(bindingReply(bindingData()))
        HostBindingFlow(api(), this, null, {}, {}).use { flow ->
            flow.foreground(true); flow.preview(bindingId, bindingCode); flow.await(HostBindingPhase.REVIEW)
            flow.foreground(false); assertNull(flow.resumeId); assertNull(flow.state.value.details)
            flow.foreground(true); flow.confirm(); delay(100)
            assertEquals(HostBindingPhase.ENTER, flow.state.value.phase); assertEquals("binding.review_cleared", flow.state.value.error)
            assertEquals(1, server.requestCount)
        }
    }
    @Test fun ambiguousBindingFlowQueriesTheOriginalIntentWithoutReplayingConfirmation(): Unit = runBlocking {
        val data = bindingData(); val partial = confirmed(data)
        server.enqueue(bindingReply(data)); server.enqueue(bindingReply(data)); server.enqueue(confirmReply(partial).setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST))
        HostBindingFlow(api(), this, null, {}, {}, HostBindingOptions(60_000, 60_000)).use { flow ->
            flow.foreground(true); flow.preview(bindingId, bindingCode); flow.await(HostBindingPhase.REVIEW)
            flow.confirm(); flow.await(HostBindingPhase.UNKNOWN); assertEquals(bindingId, flow.resumeId)
            flow.confirm() // A stale/repeated UI action must not issue another write.
            server.enqueue(bindingReply(partial)); flow.lookup(); flow.await(HostBindingPhase.WAITING_HOST)
            val traffic = List(4) { server.takeRequest() }
            assertEquals(1, traffic.count { it.path!!.endsWith("/confirm") }); assertEquals("GET", traffic.last().method)
        }
    }
    @Test fun anotherAccountOrAnAbsentDirectoryGrantCannotBecomeBindingSuccess(): Unit = runBlocking {
        val data = bindingData()
        server.enqueue(bindingReply(confirmed(data).with("user_confirmed_by_me" to JsonBoolean(false))))
        HostBindingFlow(api(), this, null, {}, { fail("another account became ready") }).use { flow ->
            flow.foreground(true); flow.preview(bindingId, bindingCode)
            assertEquals("binding.confirmed_elsewhere", flow.await(HostBindingPhase.UNAVAILABLE).error)
            flow.confirm(); assertEquals(1, server.requestCount)
        }
        server.enqueue(bindingReply(confirmed(data, host = true))); server.enqueue(bindingDirectory(data, visible = false))
        HostBindingFlow(api(), this, null, {}, { fail("no directory grant became ready") }, HostBindingOptions(60_000, 60_000)).use { flow ->
            flow.foreground(true); flow.preview(bindingId, bindingCode); flow.await(HostBindingPhase.WAITING_ACCESS)
            assertEquals(3, server.requestCount)
        }
        server.enqueue(bindingReply(confirmed(data, host = true))); server.enqueue(bindingDirectory(data, expired = true))
        HostBindingFlow(api(), this, null, {}, { fail("expired directory grant became ready") }, HostBindingOptions(60_000, 60_000)).use { flow ->
            flow.foreground(true); flow.preview(bindingId, bindingCode); flow.await(HostBindingPhase.WAITING_ACCESS)
            assertEquals(5, server.requestCount)
        }
    }
    private fun ticketResponse(value: String = token) = json(jsonObject("ok" to JsonBoolean(true), "data" to jsonObject("ticket" to value.json(), "runtime_id" to runtime.json(), "grant_version" to 7L.json(), "scope" to scope.json(), "expires_at" to time(30_000))))
    private suspend fun ticket(nonceChallenge: Boolean = false): RealtimeSessionTicket {
        if (nonceChallenge) server.enqueue(json(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "auth.proof_invalid".json()))).setResponseCode(401)
            .setHeader("DPoP-Nonce", "fresh-resource-ticket-nonce").setHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\""))
        server.enqueue(ticketResponse())
        return api().readTicket(runtime, device, scope).also {
            val first = if (nonceChallenge) server.takeRequest() else null
            val request = server.takeRequest()
            assertEquals("/v1/realtime/tickets", request.path); assertEquals("POST", request.method)
            assertTrue(request.getHeader("Authorization")!!.startsWith("DPoP "))
            val proof = JWSObject.parse(request.getHeader("DPoP")); assertTrue(proof.verify(ECDSAVerifier(key)))
            if (first != null) {
                val initial = JWSObject.parse(first.getHeader("DPoP"))
                assertNotEquals(JsonDocument.parse(initial.payload.toBytes()).root.string("jti"), JsonDocument.parse(proof.payload.toBytes()).root.string("jti"))
                assertEquals("fresh-resource-ticket-nonce", JsonDocument.parse(proof.payload.toBytes()).root.string("nonce"))
                assertEquals(first.body.clone().readUtf8(), request.body.clone().readUtf8())
            }
            val body = JsonDocument.parse(request.body.readByteArray()).root
            assertEquals(runtime, body.string("runtime_id")); assertTrue(scope.same(RelayScope.parse(body.obj("scope"))))
        }
    }
    private fun challenge() = jsonObject("v" to 1L.json(), "type" to "challenge".json(), "payload" to jsonObject("role" to "device".json(), "connection_id" to connection.json(), "challenge_id" to challengeId.json(), "nonce" to "B".repeat(42).plus("A").json(), "expires_at" to time(9000)))
    private fun helloOk() = jsonObject("v" to 1L.json(), "type" to "hello.ok".json(), "payload" to jsonObject(
        "role" to "device".json(), "connection_id" to connection.json(), "device_id" to device.json(), "runtime_id" to runtime.json(), "grant_version" to 7L.json(), "scope" to scope.json(),
        "protocols" to JsonArray(listOf(1L.json())), "capabilities" to JsonArray(listOf("connection.heartbeat.v1".json(), "session.read.v1".json())),
        "server_time" to time(0), "heartbeat_seconds" to 20L.json(), "max_frame_bytes" to RELAY_FRAME_BYTES.toLong().json(), "lease_expires_at" to time(299_000)))
    private fun peer(challenge: JsonObject = challenge(), accepted: JsonObject = helloOk(), protocol: String = RELAY_SUBPROTOCOL, expectedCapabilities: List<String> = listOf("connection.heartbeat.v1", "session.read.v1"), onContent: ((WebSocket, JsonObject) -> Unit)? = null): MockResponse = MockResponse().withWebSocketUpgrade(object : WebSocketListener() {
        override fun onOpen(socket: WebSocket, response: Response) { socket.send(JsonDocument.of(challenge).canonicalText()) }
        override fun onMessage(socket: WebSocket, text: String) {
            try {
                val frame = JsonDocument.parse(text).root
                if (frame.string("type") == "ping") {
                    heartbeats.incrementAndGet()
                    socket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "pong".json(), "payload" to jsonObject("connection_id" to connection.json(), "server_time" to time(0)))).canonicalText())
                    return
                }
                if (frame.string("type") != "hello.proof") { requireNotNull(onContent).invoke(socket, frame); return }
                val hello = frame.obj("payload")
                assertEquals(device, hello.string("device_id"))
                val proof = JWSObject.parse(hello.string("proof")); assertTrue(proof.verify(ECDSAVerifier(key)))
                assertEquals(RELAY_PROOF_TYPE, proof.header.type.toString()); assertNull(proof.header.jwk)
                val claims = JsonDocument.parse(proof.payload.toBytes()).root
                assertEquals(connection, claims.string("connection_id")); assertEquals(challengeId, claims.string("challenge_id")); assertEquals(runtime, claims.string("runtime_id"))
                assertEquals(device, claims.string("iss")); assertEquals(RELAY_PROOF_AUDIENCE, claims.string("aud"))
                assertEquals(DeviceHello(device, expectedCapabilities).digest(), claims.string("hello_sha256"))
                socket.send(JsonDocument.of(accepted).canonicalText())
            } catch (error: Throwable) { peerFailure.set(error); socket.cancel() }
        }
    }).setHeader("Sec-WebSocket-Protocol", protocol)

    private fun user(seq: Long, text: String) = jsonObject("native_seq" to seq.json(), "time" to 1000L.json(), "type" to "user/message".json(), "surface_op" to "append".json(),
        "data" to jsonObject("content" to JsonArray(listOf(jsonObject("type" to "text".json(), "text" to text.json())))))
    private inner class ReadPeer(private val records: List<JsonValue>, private val cut: Long, private val more: Boolean = false) {
        val subscription = UUID.randomUUID().toString()
        val sync = UUID.randomUUID().toString()
        private val epoch = "77777777-7777-4777-8777-777777777777"
        lateinit var socket: WebSocket
        lateinit var request: String
        var onPage: (JsonObject) -> Unit = {}
        var onCommand: (WebSocket, JsonObject) -> Unit = { _, _ -> error("unexpected command") }
        var offline = false
        fun receive(socket: WebSocket, frame: JsonObject) {
            this.socket = socket
            when (frame.string("type")) {
                "session.subscribe" -> {
                    assertEquals(runtime, frame.string("runtime_id")); assertEquals(sessionId, frame.string("session_id"))
                    request = frame.string("request_id")
                    if (offline) {
                        socket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "error".json(), "request_id" to request.json(), "runtime_id" to runtime.json(), "session_id" to sessionId.json(), "payload" to jsonObject("code" to "runtime.offline".json()))).canonicalText())
                        return
                    }
                    send("session.subscribed", jsonObject(), syncId = false)
                    send("session.snapshot", jsonObject("cursor" to cut.json(), "has_more" to JsonBoolean(more), "records" to JsonArray(records), "assistant" to jsonObject("revision" to 0L.json())))
                    send("session.checkpoint", jsonObject("state" to "persisted".json(), "through_seq" to cut.json()))
                }
                "session.page" -> {
                    assertEquals(subscription, frame.string("subscription_id")); assertEquals(epoch, frame.string("runtime_epoch"))
                    onPage(frame)
                }
                "message.submit", "session.cancel" -> onCommand(socket, frame)
                else -> error("unexpected client frame")
            }
        }
        fun send(type: String, payload: JsonObject, requestId: String = request, syncId: Boolean = true) {
            var frame = jsonObject("v" to 1L.json(), "type" to type.json(), "request_id" to requestId.json(), "runtime_id" to runtime.json(), "runtime_epoch" to epoch.json(),
                "session_id" to sessionId.json(), "subscription_id" to subscription.json(), "payload" to payload)
            if (syncId) frame = frame.with("sync_id" to sync.json())
            check(socket.send(JsonDocument.of(frame).canonicalText()))
        }
        fun control(type: String, payload: JsonObject) { check(socket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to type.json(), "payload" to payload)).canonicalText())) }
        fun start() = send("assistant.start", jsonObject("type" to "start".json(), "attemptId" to "live".json(), "revision" to 1L.json(), "startedAfterSeq" to cut.json(), "turn" to 1L.json(), "step" to 1L.json()))
        fun chunk() = send("assistant.chunk", jsonObject("type" to "chunk".json(), "attemptId" to "live".json(), "revision" to 2L.json(), "index" to 0L.json(), "time" to 1000L.json(),
            "chunk" to jsonObject("type" to "text-delta".json(), "index" to 0L.json(), "text" to "streamed text".json())))
        fun enqueue(value: String = token) { server.enqueue(ticketResponse(value)); server.enqueue(peer(onContent = ::receive)) }
    }
    private suspend fun SessionReader.await(test: (SessionReadState) -> Boolean) = withTimeout(5000) { state.first(test) }.also { peerFailure.get()?.let { throw AssertionError(it) } }

    private inner class CommandPeer {
        val granted = RelayScope(listOf("session.read", "message.submit", "command.status", "session.cancel"), emptyList(), listOf(sessionId))
        val journal = MemoryCommandJournal(CommandOwner("99999999-9999-4999-8999-999999999999", config.organizationId, config.fingerprint, "77777777-7777-4777-8777-777777777777", device))
        val feed = ReadPeer(listOf(user(0, "opening")), 0)
        val statuses = java.util.concurrent.ConcurrentHashMap<String, JsonObject>()
        val writes = java.util.concurrent.CopyOnWriteArrayList<JsonObject>()
        var advertisedState = RemoteCommandState.AGENT_QUEUED
        var denyTickets = false
        var leaseMillis = 299_000L
        var cacheWorkspace: String? = null
        var accessUnavailable = false
        var readLeaseMillis = 299_000L
        val accessReads = java.util.concurrent.atomic.AtomicInteger()
        init {
            val capabilities = listOf("connection.heartbeat.v1", "session.read.v1", "command.relay.v1", "session.cancel.v1")
            server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse = when {
                    request.path == "/v1/me" -> bindingReply(jsonObject("issuer" to config.issuer.json(), "subject" to "school-user".json(), "client_id" to config.clientId.json(), "scopes" to JsonArray(listOf("remote.access".json())),
                        "user_id" to journal.owner.userId.json(), "memberships" to JsonArray(listOf(jsonObject("organization_id" to config.organizationId.json(), "role" to "member".json())))))
                    request.path == "/v1/realtime/tickets" -> if (denyTickets) json(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "access.denied".json()))).setResponseCode(403) else ticketResponse().setBody(JsonDocument.of(jsonObject("ok" to JsonBoolean(true), "data" to jsonObject("ticket" to token.json(), "runtime_id" to runtime.json(), "grant_version" to 7L.json(), "scope" to granted.json(), "expires_at" to time(30_000)))).canonicalText())
                    request.path == "/v1/realtime" -> peer(accepted = helloOk().with("payload" to helloOk().obj("payload").with("scope" to granted.json(), "capabilities" to JsonArray(capabilities.map(String::json)), "lease_expires_at" to time(leaseMillis))), expectedCapabilities = capabilities, onContent = feed::receive)
                    request.path == "/v1/runtimes/$runtime/sessions/$sessionId/read-access" -> {
                        accessReads.incrementAndGet()
                        if (accessUnavailable) json(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "internal".json()))).setResponseCode(503)
                        else bindingReply(jsonObject("runtime_id" to runtime.json(), "session_id" to sessionId.json(), "workspace_id" to (cacheWorkspace?.json() ?: JsonNull), "grant_version" to 7L.json(), "issued_at" to time(0), "expires_at" to time(readLeaseMillis)))
                    }
                    request.path!!.startsWith("/v1/commands/") -> {
                        assertEquals(device, request.requestUrl!!.queryParameter("device_id"))
                        statuses[request.requestUrl!!.pathSegments.last()]?.let(::bindingReply) ?: json(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "access.denied".json()))).setResponseCode(403)
                    }
                    else -> MockResponse().setResponseCode(404)
                }
            }
            feed.onCommand = { socket, frame ->
                writes += frame
                val intent = CommandIntent.parse(frame)
                assertTrue(runBlocking { journal.list(runtime, sessionId).single { it.intent.requestId == intent.requestId }.attempts } > 0)
                statuses[intent.requestId] = jsonObject("request_id" to intent.requestId.json(), "session_id" to sessionId.json(), "state" to advertisedState.wire.json(), "payload_sha256" to intent.digest.json(), "updated_at" to time(0))
                // This deliberately claims a stronger fact than REST can report.
                socket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "command.receipt".json(), "runtime_id" to runtime.json(), "runtime_epoch" to "77777777-7777-4777-8777-777777777777".json(),
                    "session_id" to sessionId.json(), "request_id" to intent.requestId.json(), "payload" to jsonObject("state" to "agent_queued".json(), "payload_sha256" to intent.digest.json(), "updated_at" to time(0)))).canonicalText())
            }
        }
        fun reader(owner: CoroutineScope, transcripts: TranscriptCache? = null) = api().chatReader(device, runtime, sessionId, granted, journal, owner, transcripts = transcripts)
    }
    private inner class MemoryTranscriptCache(override val owner: LocalDataOwner) : TranscriptCache {
        val loads = java.util.concurrent.atomic.AtomicInteger()
        @Volatile var value: CachedTranscript? = CachedTranscript("77777777-7777-4777-8777-777777777777", System.currentTimeMillis(), listOf(SessionRecord.parse(user(0, "disk history"))))
        var holdWrites = false
        val writing = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        override suspend fun loadTranscript(runtime: String, session: String, workspace: String?): CachedTranscript? { loads.incrementAndGet(); return value }
        override suspend fun saveTranscript(runtime: String, session: String, workspace: String?, epoch: String, transcript: SessionTranscript, now: Long) {
            writing.complete(Unit); if (holdWrites) release.await()
            assertTrue(transcript.durableOnly); value = CachedTranscript(epoch, now, transcript.records)
        }
        override suspend fun removeTranscript(runtime: String, session: String) { value = null }
        override suspend fun removeRuntimeTranscripts(runtime: String) { value = null }
        override suspend fun retainTranscripts(scopes: Map<String, RelayScope>) = Unit
    }
    @Test fun aFreshKeyProvedConnectionAuthorizesDiskHistoryWhileTheHostIsOffline(): Unit = runBlocking {
        val fixture = CommandPeer(); val disk = MemoryTranscriptCache(fixture.journal.owner); fixture.feed.offline = true
        fixture.reader(this, disk).use { reader ->
            val offline = reader.await { it.phase == SessionReadPhase.OFFLINE && it.window != null }
            assertEquals("disk history", offline.window!!.items.single().blocks.single().text)
            assertEquals(1, disk.loads.get()); assertTrue(fixture.writes.isEmpty())
        }
    }
    @Test fun aDeniedCurrentTicketNeverLoadsTheOldEncryptedHistory(): Unit = runBlocking {
        val fixture = CommandPeer(); fixture.denyTickets = true; val disk = MemoryTranscriptCache(fixture.journal.owner)
        fixture.reader(this, disk).use { reader ->
            val revoked = reader.await { it.phase == SessionReadPhase.REVOKED }
            assertNull(revoked.window); assertEquals(0, disk.loads.get()); assertNull(disk.value)
        }
    }
    @Test fun aSuccessfulWorkspaceHelloCannotExposeHistoryAfterTheSessionsWorkspaceChanged(): Unit = runBlocking {
        val fixture = CommandPeer(); fixture.cacheWorkspace = UUID.randomUUID().toString(); fixture.feed.offline = true
        val disk = MemoryTranscriptCache(fixture.journal.owner)
        assertThrows(ProtocolException::class.java) { api().chatReader(device, runtime, UUID.randomUUID().toString(), fixture.granted, fixture.journal, this, transcripts = disk) }
        fixture.reader(this, disk).use { reader ->
            reader.await { it.phase == SessionReadPhase.REVOKED }
            assertEquals(1, fixture.accessReads.get()); assertEquals(0, disk.loads.get()); assertNull(reader.state.value.window)
        }
    }
    @Test fun aCacheAuthorizationOutageKeepsLiveReadAvailableWithoutUsingDiskHistory(): Unit = runBlocking {
        val fixture = CommandPeer(); fixture.accessUnavailable = true; val disk = MemoryTranscriptCache(fixture.journal.owner)
        fixture.reader(this, disk).use { reader ->
            val ready = reader.await { it.phase == SessionReadPhase.READY }
            assertEquals("opening", ready.window!!.items.single().blocks.single().text)
            assertEquals(0, disk.loads.get()); assertEquals("cache.authorization_unavailable", ready.cacheError)
            fixture.feed.control("server.draining", jsonObject("reason" to "server_draining".json()))
            assertNull(reader.await { it.phase == SessionReadPhase.BACKOFF }.window)
        }
    }
    @Test fun anOfflineCacheViewExpiresWithItsCurrentAuthorityLease(): Unit = runBlocking {
        val fixture = CommandPeer(); fixture.feed.offline = true; fixture.leaseMillis = 1500
        val disk = MemoryTranscriptCache(fixture.journal.owner)
        fixture.reader(this, disk).use { reader ->
            reader.await { it.phase == SessionReadPhase.OFFLINE && it.window != null }
            reader.await { it.window == null }
            assertNotNull(disk.value) // Retention is separate from permission to display.
        }
    }
    @Test fun revocationWaitsForAnInflightCacheWriteThenErasesItsResult(): Unit = runBlocking {
        val fixture = CommandPeer(); val disk = MemoryTranscriptCache(fixture.journal.owner); disk.holdWrites = true
        fixture.reader(this, disk).use { reader ->
            reader.await { it.phase == SessionReadPhase.READY }
            withTimeout(5000) { disk.writing.await() }
            fixture.feed.control("access.revoked", jsonObject("code" to "grant_revoked".json()))
            withTimeout(5000) { reader.commands!!.state.first { !it.connected } }
            assertNull(reader.state.value.window)
            disk.release.complete(Unit)
            reader.await { it.phase == SessionReadPhase.REVOKED }
            assertNull(disk.value); assertNull(reader.state.value.window)
        }
    }
    @Test fun anOnlinePhoneKeepsReceivingRevocationsWhileItsHostIsOffline(): Unit = runBlocking {
        val fixture = CommandPeer(); fixture.feed.offline = true; val disk = MemoryTranscriptCache(fixture.journal.owner)
        fixture.reader(this, disk).use { reader ->
            reader.await { it.phase == SessionReadPhase.OFFLINE && it.window != null }
            fixture.feed.control("access.revoked", jsonObject("code" to "grant_revoked".json()))
            reader.await { it.phase == SessionReadPhase.REVOKED }
            assertNull(reader.state.value.window); assertNull(disk.value)
        }
    }
    @Test fun aCatalogOnlyWorkspaceMoveRetiresAnIdleCachedViewWithoutWaitingForLeaseExpiry(): Unit = runBlocking {
        val fixture = CommandPeer(); fixture.feed.offline = true; val disk = MemoryTranscriptCache(fixture.journal.owner)
        fixture.reader(this, disk).use { reader ->
            reader.await { it.phase == SessionReadPhase.OFFLINE && it.window != null }
            fixture.cacheWorkspace = UUID.randomUUID().toString()
            reader.await { it.phase == SessionReadPhase.REVOKED }
            assertNull(reader.state.value.window); assertNull(disk.value); assertTrue(fixture.accessReads.get() >= 2)
        }
    }
    @Test fun periodicAuthorityChecksCannotExtendTheOriginalCachedViewLease(): Unit = runBlocking {
        val fixture = CommandPeer(); fixture.feed.offline = true; fixture.readLeaseMillis = 2500
        val disk = MemoryTranscriptCache(fixture.journal.owner)
        fixture.reader(this, disk).use { reader ->
            reader.await { it.phase == SessionReadPhase.OFFLINE && it.window != null }
            reader.await { it.phase == SessionReadPhase.OFFLINE && it.window == null }
            assertTrue(fixture.accessReads.get() >= 2); assertNotNull(disk.value)
        }
    }
    @Test fun chatPersistsBeforeWritingAndUsesOneSocketForReadAndCommandFacts(): Unit = runBlocking {
        val fixture = CommandPeer()
        fixture.reader(this).use { reader ->
            reader.await { it.phase == SessionReadPhase.READY }
            val commands = reader.commands!!
            val id = commands.submit("steer", "继续中文🙂")
            val delivered = withTimeout(5000) { commands.state.first { it.records.any { row -> row.intent.requestId == id && row.everAgentQueued } } }.records.single()
            assertEquals(id, fixture.writes.single().string("request_id")); assertEquals(CommandDelivery.CONFIRMED, delivered.delivery)
            assertEquals("steer", delivered.intent.payload.string("mode"))
            assertEquals(1, fixture.writes.size)
        }
    }
    @Test fun aReceiptHintCannotAdvanceBeyondThisDevicesAuthoritativePersistenceFacts(): Unit = runBlocking {
        val fixture = CommandPeer(); fixture.advertisedState = RemoteCommandState.RECEIVED
        fixture.reader(this).use { reader ->
            reader.await { it.phase == SessionReadPhase.READY }
            val commands = reader.commands!!; val id = commands.submit("queue", "original")
            val record = withTimeout(5000) { commands.state.first { it.records.any { row -> row.intent.requestId == id && row.remote == RemoteCommandState.RECEIVED } } }.records.single()
            assertFalse(record.everAgentQueued); assertFalse(record.everHostSaved)
        }
    }
    @Test fun failedDurableAttemptNeverWritesAndAStaleCancellationNeverTargetsANewEpoch(): Unit = runBlocking {
        val fixture = CommandPeer(); fixture.journal.failBegin = true
        fixture.reader(this).use { reader ->
            reader.await { it.phase == SessionReadPhase.READY }
            val commands = reader.commands!!; commands.submit("queue", "do not send")
            withTimeout(5000) { commands.state.first { it.error == "data.unavailable" } }
            assertTrue(fixture.writes.isEmpty())
            assertThrows(CommandDataException::class.java) { runBlocking { commands.cancel("88888888-8888-4888-8888-888888888888") } }
            assertTrue(fixture.writes.isEmpty())
        }
    }
    @Test fun explicitRetryRequeriesReceivedAndReusesTheExactOriginalRequest(): Unit = runBlocking {
        val fixture = CommandPeer(); fixture.advertisedState = RemoteCommandState.RECEIVED
        fixture.reader(this).use { reader ->
            reader.await { it.phase == SessionReadPhase.READY }
            val commands = reader.commands!!; val id = commands.submit("queue", "same request only")
            withTimeout(5000) { commands.state.first { it.records.singleOrNull()?.remote == RemoteCommandState.RECEIVED } }
            val original = JsonDocument.of(fixture.writes.single()).canonicalText()
            commands.sendPending(id)
            withTimeout(5000) { commands.state.first { it.records.singleOrNull()?.attempts == 2L } }
            withTimeout(5000) { while (fixture.writes.size < 2) delay(10) }
            assertEquals(2, fixture.writes.size)
            assertEquals(original, JsonDocument.of(fixture.writes.last()).canonicalText())
        }
    }
    @Test fun aCorrelatedCommandErrorKeepsTheReaderAndOriginalIntentAlive(): Unit = runBlocking {
        val fixture = CommandPeer()
        fixture.feed.onCommand = { socket, frame ->
            fixture.writes += frame
            val intent = CommandIntent.parse(frame)
            fixture.statuses[intent.requestId] = jsonObject("request_id" to intent.requestId.json(), "session_id" to sessionId.json(), "state" to "received".json(), "payload_sha256" to intent.digest.json(), "updated_at" to time(0))
            socket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "error".json(), "request_id" to intent.requestId.json(), "runtime_id" to runtime.json(), "session_id" to sessionId.json(), "payload" to jsonObject("code" to "rate.limited".json()))).canonicalText())
            fixture.feed.send("session.event", user(1, "after command error"))
        }
        fixture.reader(this).use { reader ->
            reader.await { it.phase == SessionReadPhase.READY }
            val id = reader.commands!!.submit("queue", "original body")
            reader.await { it.window?.items?.any { item -> item.blocks.any { block -> block.text == "after command error" } } == true }
            assertEquals(SessionReadPhase.READY, reader.state.value.phase)
            assertEquals(id, fixture.journal.list(runtime, sessionId).single().intent.requestId)
            assertEquals(1L, fixture.journal.list(runtime, sessionId).single().attempts); assertEquals(1, fixture.writes.size)
        }
    }

    @Test fun readerMergesStreamingSettlementAndHistoryWithoutMovingTheOpeningCut(): Unit = runBlocking {
        val fixture = ReadPeer(listOf(user(2, "opening"), user(3, "latest")), 3, true); fixture.enqueue()
        SessionReader(api(), device, runtime, sessionId, scope, this, SessionReaderOptions(heartbeatMillis = 100)).use { reader ->
            reader.await { it.phase == SessionReadPhase.READY && it.window?.persistedThrough == 3L }
            fixture.start(); fixture.chunk()
            reader.await { it.window?.items?.lastOrNull()?.live == true && it.window.items.last().blocks.isNotEmpty() }
            val pageRequest = CompletableDeferred<String>()
            fixture.onPage = { page ->
                assertEquals(3L, page.obj("payload").integer("through_seq", -1)); assertEquals(2L, page.obj("payload").integer("before_seq", 0))
                fixture.send("session.event", user(4, "live user"))
                fixture.send("session.page.result", jsonObject("records" to JsonArray(listOf(user(0, "oldest"), user(1, "older"))), "has_more" to JsonBoolean(false), "through_seq" to 3L.json()), page.string("request_id"))
                pageRequest.complete(page.string("request_id"))
            }
            reader.loadOlder(); withTimeout(5000) { pageRequest.await() }
            val history = reader.await { it.window?.cursor == 4L && !it.window.hasMore }
            assertEquals(3L, history.window!!.openingCursor); assertEquals("oldest", history.window.items.first().blocks.single().text)
            val message = jsonObject("native_seq" to 5L.json(), "time" to 1000L.json(), "type" to "assistant/message".json(), "surface_op" to "append".json(),
                "data" to jsonObject("turn" to 1L.json(), "step" to 1L.json(), "message" to jsonObject("content" to JsonArray(listOf(jsonObject("type" to "text".json(), "text" to "settled".json()))))))
            fixture.send("session.event", message)
            val held = reader.await { it.window?.cursor == 5L }
            assertFalse(held.window!!.items.any { item -> item.blocks.any { it.text == "settled" } })
            fixture.send("assistant.end", jsonObject("type" to "end".json(), "attemptId" to "live".json(), "revision" to 3L.json(), "index" to 1L.json(), "outcome" to jsonObject("kind" to "committed".json(), "eventType" to "assistant/message".json(), "seq" to 5L.json())))
            val settled = reader.await { it.window?.items?.lastOrNull()?.blocks?.singleOrNull()?.text == "settled" }
            assertEquals(1, settled.window!!.items.count { it.role == ConversationRole.ASSISTANT }); assertFalse(settled.window.items.last().live)
            delay(220) // At least two actual application heartbeat exchanges on the same TLS connection.
            assertTrue(heartbeats.get() >= 2)
            assertEquals(SessionReadPhase.READY, reader.state.value.phase)
            assertEquals(2, server.requestCount)
        }
    }

    @Test fun pageTimeoutKeepsTheTransportAndAllowsAFreshCorrelatedRetry(): Unit = runBlocking {
        val fixture = ReadPeer(listOf(user(1, "current")), 1, true); fixture.enqueue()
        SessionReader(api(), device, runtime, sessionId, scope, this, SessionReaderOptions(pageMillis = 120)).use { reader ->
            reader.await { it.phase == SessionReadPhase.READY }
            val requests = java.util.concurrent.CopyOnWriteArrayList<String>()
            fixture.onPage = { requests += it.string("request_id") }
            reader.loadOlder()
            reader.await { it.pageError == "network.page_timeout" && !it.loadingOlder }
            assertEquals(2, server.requestCount)
            fixture.onPage = { page ->
                requests += page.string("request_id")
                fixture.send("session.page.result", jsonObject("records" to JsonArray(listOf(user(0, "older"))), "has_more" to JsonBoolean(false), "through_seq" to 1L.json()), requests.first())
                fixture.send("session.event", user(2, "continued"))
                fixture.send("session.page.result", jsonObject("records" to JsonArray(listOf(user(0, "older"))), "has_more" to JsonBoolean(false), "through_seq" to 1L.json()), page.string("request_id"))
            }
            reader.loadOlder()
            val result = reader.await { it.window?.hasMore == false }
            assertEquals(2L, result.window!!.cursor); assertEquals(3, result.window.records.size)
            assertEquals(2, requests.size); assertNotEquals(requests[0], requests[1]); assertEquals(2, server.requestCount)
        }
    }

    @Test fun denseLiveEventsSurviveIdleAndPageDeadlinesWithoutAReplacement(): Unit = runBlocking {
        val fixture = ReadPeer(listOf(user(1, "opening")), 1, true); fixture.enqueue()
        SessionReader(api(), device, runtime, sessionId, scope, this, SessionReaderOptions(pageMillis = 180)).use { reader ->
            reader.await { it.phase == SessionReadPhase.READY }
            reader.loadOlder() // The peer deliberately leaves this page unanswered.
            for (seq in 2L..17L) { delay(100); fixture.send("session.event", user(seq, "live-$seq")) }
            val current = reader.await { it.window?.cursor == 17L }
            assertEquals((1L..17L).toList(), current.window!!.records.map { it.seq })
            assertEquals(1L, current.window.openingCursor)
            assertEquals("network.page_timeout", current.pageError); assertFalse(current.loadingOlder)
            assertEquals(2, server.requestCount)
        }
    }

    @Test fun disconnectUsesAFreshTicketAndSnapshotAndRevocationClearsAllCachedContent(): Unit = runBlocking {
        val first = ReadPeer(listOf(user(0, "cached")), 0); first.enqueue()
        val reader = SessionReader(api(), device, runtime, sessionId, scope, this, SessionReaderOptions(backoffMillis = { 60_000 }))
        try {
            reader.await { it.window?.persistedThrough == 0L }
            first.start(); first.chunk(); reader.await { it.window?.items?.any { it.live && it.blocks.isNotEmpty() } == true }
            first.socket.close(1001, "fixture disconnect")
            val stale = reader.await { it.phase == SessionReadPhase.BACKOFF }
            assertEquals(listOf("cached"), stale.window!!.items.map { it.blocks.single().text })
            val second = ReadPeer(listOf(user(0, "replacement")), 0); second.enqueue("D".repeat(42) + "A")
            reader.retry()
            val replaced = reader.await { it.phase == SessionReadPhase.READY && it.window?.items?.firstOrNull()?.blocks?.singleOrNull()?.text == "replacement" }
            assertFalse(replaced.window!!.items.any { it.live }); assertNotEquals(first.subscription, second.subscription)
            val traffic = List(4) { server.takeRequest() }
            assertNotEquals(traffic[0].getHeader("DPoP"), traffic[2].getHeader("DPoP"))
            assertNotEquals(traffic[1].getHeader("Authorization"), traffic[3].getHeader("Authorization"))
            second.control("access.revoked", jsonObject("code" to "access.revoked".json()))
            second.socket.close(1001, "revoked")
            assertNull(reader.await { it.phase == SessionReadPhase.REVOKED }.window)
            reader.retry(); delay(100); assertEquals(4, server.requestCount)
        } finally { reader.close() }
        assertNull(reader.state.value.window); assertEquals(SessionReadPhase.CLOSED, reader.state.value.phase)
    }

    @Test fun nativeGapRequestsAReplacementAndExplicitCloseRetiresLateFrames(): Unit = runBlocking {
        val first = ReadPeer(listOf(user(0, "first")), 0); first.enqueue()
        val reader = SessionReader(api(), device, runtime, sessionId, scope, this, SessionReaderOptions(backoffMillis = { 60_000 }))
        try {
            reader.await { it.window?.persistedThrough == 0L }
            first.send("session.event", user(2, "gap"))
            assertEquals("protocol.resync_required", reader.await { it.phase == SessionReadPhase.BACKOFF }.error)
            val second = ReadPeer(listOf(user(1, "rebaseline"), user(2, "gap recovered")), 2, true); second.enqueue()
            reader.retry(); reader.await { it.phase == SessionReadPhase.READY && it.window?.cursor == 2L }
            reader.close(); delay(100)
            assertEquals(SessionReadPhase.CLOSED, reader.state.value.phase); assertNull(reader.state.value.window)
            assertEquals(4, server.requestCount)
        } finally { reader.close() }
    }

    @Test fun httpsTicketAndTlsUpgradeBindTheRegisteredKeyAndConsumeOneSocketCredential(): Unit = runBlocking {
        val ticket = ticket(nonceChallenge = true)
        server.enqueue(peer())
        ticket.connect().use { connection ->
            assertEquals(runtime, connection.identity.runtimeId); assertEquals(7L, connection.identity.grantVersion)
            val upgrade = server.takeRequest()
            assertEquals("/v1/realtime", upgrade.path)
            assertEquals("DSH-Ticket $token", upgrade.getHeader("Authorization"))
            assertEquals(RELAY_SUBPROTOCOL, upgrade.getHeader("Sec-WebSocket-Protocol"))
            assertFalse(upgrade.requestUrl.toString().contains(token))
            connection.send(jsonObject("v" to 1L.json(), "type" to "ping".json(), "payload" to jsonObject()))
            assertEquals("pong", withTimeout(3000) { connection.receive() }.string("type"))
        }
        val count = server.requestCount
        assertThrows(RelayException::class.java) { runBlocking { ticket.connect() } }
        assertEquals(count, server.requestCount)
    }

    @Test fun challengeRoleNegotiatedProtocolAndReturnedAuthorityCannotBeSubstituted(): Unit = runBlocking {
        for ((challenge, accepted, protocol) in listOf(
            Triple(challenge().with("payload" to challenge().obj("payload").with("role" to "installation".json())), helloOk(), RELAY_SUBPROTOCOL),
            Triple(challenge(), helloOk().with("payload" to helloOk().obj("payload").with("device_id" to runtime.json())), RELAY_SUBPROTOCOL),
            Triple(challenge(), helloOk(), "other.protocol"),
        )) {
            val ticket = ticket(); server.enqueue(peer(challenge, accepted, protocol))
            assertThrows(Exception::class.java) { runBlocking { withTimeout(4000) { ticket.connect() } } }
            server.takeRequest()
        }
    }

    @Test fun ordinaryUpgradeFailureDoesNotRedirectOrReuseTheTicket(): Unit = runBlocking {
        val ticket = ticket()
        server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", "https://other.invalid/stolen"))
        assertThrows(RelayException::class.java) { runBlocking { ticket.connect() } }
        val request = server.takeRequest(); assertEquals("DSH-Ticket $token", request.getHeader("Authorization"))
        assertEquals(2, server.requestCount)
        assertThrows(RelayException::class.java) { runBlocking { ticket.connect() } }
        assertEquals(2, server.requestCount)
    }
}
