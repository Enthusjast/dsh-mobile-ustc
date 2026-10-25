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
    private fun peer(challenge: JsonObject = challenge(), accepted: JsonObject = helloOk(), protocol: String = RELAY_SUBPROTOCOL, expectedCapabilities: List<String> = listOf("connection.heartbeat.v1", "session.read.v1","question.blocking.v1","question.timed.v1"), onContent: ((WebSocket, JsonObject) -> Unit)? = null): MockResponse = MockResponse().withWebSocketUpgrade(object : WebSocketListener() {
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
        var onClaim: (WebSocket,JsonObject)->Unit={_,_->error("unexpected claim")}
        var onApproval: (WebSocket, JsonObject) -> Unit = { _, _ -> error("unexpected approval") }
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
                "message.submit", "session.cancel", "session.archive", "question.answer","question.timed.answer" -> onCommand(socket, frame)
                "question.claim","question.release"->onClaim(socket,frame)
                "approval.subscribe", "approval.status.get", "approval.details.get" -> onApproval(socket, frame)
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

    private inner class CommandPeer(questions: Boolean=false, archive: Boolean=false, archiveOnly: Boolean=false, advertiseFiles: Boolean=true) {
        val granted = RelayScope(listOf("session.read", "command.status") + (if (archiveOnly) emptyList() else listOf("message.submit", "session.cancel")) +
            (if (archive) listOf("session.archive") else emptyList()) + (if(questions) listOf("question.answer") else emptyList()), emptyList(), listOf(sessionId))
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
            val capabilities = listOf("connection.heartbeat.v1", "session.read.v1", "question.blocking.v1","question.timed.v1","command.relay.v1") +
                (if ("message.submit" in granted.actions) listOf(FILE_MESSAGE_CAPABILITY) else emptyList()) +
                (if (archiveOnly) emptyList() else listOf("session.cancel.v1")) + (if (archive) listOf("session.archive.v1") else emptyList())
            server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse = when {
                    request.path == "/v1/me" -> bindingReply(jsonObject("issuer" to config.issuer.json(), "subject" to "school-user".json(), "client_id" to config.clientId.json(), "scopes" to JsonArray(listOf("remote.access".json())),
                        "user_id" to journal.owner.userId.json(), "memberships" to JsonArray(listOf(jsonObject("organization_id" to config.organizationId.json(), "role" to "member".json())))))
                    request.path == "/v1/realtime/tickets" -> if (denyTickets) json(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "access.denied".json()))).setResponseCode(403) else ticketResponse().setBody(JsonDocument.of(jsonObject("ok" to JsonBoolean(true), "data" to jsonObject("ticket" to token.json(), "runtime_id" to runtime.json(), "grant_version" to 7L.json(), "scope" to granted.json(), "expires_at" to time(30_000)))).canonicalText())
                    request.path == "/v1/realtime" -> peer(accepted = helloOk().with("payload" to helloOk().obj("payload").with("scope" to granted.json(), "capabilities" to JsonArray(capabilities.filter { advertiseFiles || it != FILE_MESSAGE_CAPABILITY }.map(String::json)), "lease_expires_at" to time(leaseMillis))), expectedCapabilities = capabilities, onContent = feed::receive)
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
    private inner class ApprovalPeer(large: Boolean = false, workspaceScope: Boolean = false) {
        val owner = CommandOwner("99999999-9999-4999-8999-999999999999", config.organizationId, config.fingerprint, "77777777-7777-4777-8777-777777777777", device)
        val commands = MemoryCommandJournal(owner)
        val journal = MemoryApprovalDecisionJournal(owner)
        val approvalKey = ECKeyGenerator(Curve.P_256).generate()
        val registered = RegisteredApprovalKey.parse(jsonObject("user_id" to owner.userId.json(), "device_id" to device.json(), "key_version" to 1L.json(),
            "active" to JsonBoolean(true), "public_jwk" to JsonDocument.parse(approvalKey.toPublicJWK().toJSONString()).root, "approval_key_jkt" to approvalKey.computeThumbprint().toString().json()))
        val granted = RelayScope(listOf("session.read", "approval.decide"), if (workspaceScope) listOf(sessionId) else emptyList(), if (workspaceScope) emptyList() else listOf(sessionId))
        val feed = ReadPeer(listOf(user(0, "opening")), 0)
        val resource = api()
        val body = run {
            val now = System.currentTimeMillis()
            ApprovalContext.from(JsonDocument.of(jsonObject("domain" to APPROVAL_CONTEXT_DOMAIN.json(), "protocol_version" to 1L.json(), "host_id" to bindingId.json(),
                "installation_id" to UUID.randomUUID().toString().json(), "runtime_id" to runtime.json(), "runtime_epoch" to owner.userId.json(), "session_id" to sessionId.json(),
                "dsh_session_id" to "opaque-fixture-native".json(), "approval_id" to UUID.randomUUID().toString().json(), "execution_id" to UUID.randomUUID().toString().json(),
                "call_id" to "native-call".json(), "tool" to "bash".json(), "arguments" to jsonObject("command" to (if (large) "中🙂".repeat(17_500) else "echo fixture").json()),
                "workspace" to jsonObject("workspace_id" to sessionId.json(), "root_sha256" to "c".repeat(64).json()), "resources" to JsonArray(emptyList()),
                "nonce" to Contract.base64url(ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }).json(), "policy_version" to 1L.json(),
                "required_assurance" to jsonObject("profile" to "fixture/step-up".json(), "max_auth_age_seconds" to 60L.json()),
                "created_at" to Contract.timestamp(now).json(), "expires_at" to Contract.timestamp(now + 120_000).json())))
        }
        val pending = jsonObject("approval_id" to body.root["approval_id"], "runtime_id" to runtime.json(), "runtime_epoch" to body.root["runtime_epoch"], "session_id" to sessionId.json(),
            "execution_id" to body.root["execution_id"], "binding_sha256" to body.bindingSha256.json(), "expires_at" to Contract.timestamp(body.expiresAt).json(), "state" to "pending".json())
        val status = AtomicReference(pending)
        val posts = java.util.concurrent.atomic.AtomicInteger()
        val queries = java.util.concurrent.atomic.AtomicInteger()
        val proofs = java.util.concurrent.CopyOnWriteArrayList<String>()
        val requestedStatuses = java.util.concurrent.CopyOnWriteArrayList<String>()
        val posted = java.util.concurrent.CountDownLatch(1)
        var waitPost: java.util.concurrent.CountDownLatch? = null
        var waitDirectory: java.util.concurrent.CountDownLatch? = null
        val directoryEntered = java.util.concurrent.CountDownLatch(1)
        @Volatile var nonceChallenge = false
        @Volatile var loseReply = false
        @Volatile var publishDecision = true
        @Volatile var support = true
        @Volatile var denyApproval: String? = null
        @Volatile var dropBeforeCommit = false
        @Volatile var holdDetails = false
        @Volatile var lateDetails: JsonObject? = null
        @Volatile var statusOverride: JsonObject? = null
        @Volatile var denyStatus = false
        private var watch: String? = null
        private lateinit var socket: WebSocket
        init {
            val requested = listOf("connection.heartbeat.v1", "session.read.v1", "question.blocking.v1", "question.timed.v1", SIGNED_APPROVAL_CAPABILITY)
            server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse = try { when {
                    request.path == "/v1/me" -> bindingReply(jsonObject("issuer" to config.issuer.json(), "subject" to "school-user".json(), "client_id" to config.clientId.json(),
                        "scopes" to JsonArray(listOf("remote.access".json())), "user_id" to owner.userId.json(), "memberships" to JsonArray(listOf(jsonObject("organization_id" to config.organizationId.json(), "role" to "member".json())))))
                    request.path == "/v1/realtime/tickets" -> bindingReply(jsonObject("ticket" to token.json(), "runtime_id" to runtime.json(), "grant_version" to 7L.json(), "scope" to granted.json(), "expires_at" to time(30_000)))
                    request.path == "/v1/realtime" -> peer(accepted = helloOk().with("payload" to helloOk().obj("payload").with("scope" to granted.json(),
                        "capabilities" to JsonArray(requested.filter { support || it != SIGNED_APPROVAL_CAPABILITY }.map(String::json)))), expectedCapabilities = requested, onContent = feed::receive)
                    request.path == "/v1/runtimes" -> { directoryEntered.countDown(); check(waitDirectory!!.await(10, java.util.concurrent.TimeUnit.SECONDS)); bindingReply(jsonObject("items" to JsonArray(emptyList()))) }
                    request.path == "/v1/approvals/${body.root.string("approval_id")}/decisions" -> post(request)
                    else -> MockResponse().setResponseCode(404)
                } } catch (failure: Throwable) { peerFailure.set(failure); MockResponse().setResponseCode(500) }
            }
            feed.onApproval = approval@ { link, frame ->
                socket = link
                when (frame.string("type")) {
                    "approval.subscribe" -> {
                        watch = frame.string("request_id")
                        val items = if (status.get().string("state") in setOf("pending", "decision_received")) listOf(status.get()) else emptyList()
                        send("approval.snapshot", frame.string("request_id"), jsonObject("items" to JsonArray(items)), scoped = false)
                    }
                    "approval.status.get" -> {
                        queries.incrementAndGet(); requestedStatuses += frame.obj("payload").string("approval_id")
                        if (denyStatus) send("error", frame.string("request_id"), jsonObject("code" to "access.denied".json()), scoped = false)
                        else send("approval.reference", frame.string("request_id"), jsonObject("status" to (statusOverride ?: status.get())))
                    }
                    "approval.details.get" -> {
                        if (holdDetails) { lateDetails = frame; return@approval }
                        val bytes = body.document.canonicalBytes()
                        if (bytes.size < 50 * 1024) send("approval.details", frame.string("request_id"), jsonObject("context" to body.root))
                        else {
                            val parts = bytes.toList().chunked(40 * 1024).map { it.toByteArray() }; val transfer = UUID.randomUUID().toString()
                            parts.forEachIndexed { index, part -> send("approval.fragment", frame.string("request_id"), jsonObject("kind" to "approval.details".json(), "transfer_id" to transfer.json(),
                                "index" to index.toLong().json(), "count" to parts.size.toLong().json(), "data" to java.util.Base64.getEncoder().encodeToString(part).json())) }
                        }
                    }
                    else -> error("unexpected approval control")
                }
            }
        }
        private fun post(request: RecordedRequest): MockResponse {
            val proof = JWSObject.parse(request.getHeader("DPoP")); assertTrue(proof.verify(ECDSAVerifier(key)))
            val claims = JsonDocument.parse(proof.payload.toBytes()).root
            assertEquals("POST", claims.string("htm")); assertEquals(origin + request.path, claims.string("htu")); proofs += claims.string("jti")
            val input = JsonDocument.parse(request.body.readByteArray()).root; input.exactKeys("connection_id", "decision_jws"); assertEquals(connection, input.string("connection_id"))
            val signed = ApprovalSignatures.verify(input.string("decision_jws"), registered, body, System.currentTimeMillis())
            val local = runBlocking { journal.list(runtime, sessionId).single() }
            assertTrue(local.attempts > 0); assertEquals(ApprovalDecisionDelivery.RECONCILE, local.delivery); assertTrue(local.intent.signed.compact == signed.compact)
            val number = posts.incrementAndGet()
            denyApproval?.let { return json(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to it.json()))).setResponseCode(403) }
            if (nonceChallenge && number == 1) return json(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "auth.proof_invalid".json())))
                .setResponseCode(401).setHeader("DPoP-Nonce", "N".repeat(42) + "A").setHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"")
            if (nonceChallenge) assertEquals("N".repeat(42) + "A", claims.string("nonce"))
            if (dropBeforeCommit) return MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST)
            posted.countDown(); waitPost?.let { check(it.await(10, java.util.concurrent.TimeUnit.SECONDS)) }
            val accepted = pending.with("state" to "decision_received".json(), "decision" to signed.decision.choice.wire.json(), "decision_payload_sha256" to signed.payloadSha256.json())
            status.set(accepted)
            if (publishDecision) reference(accepted)
            val result = bindingReply(jsonObject("status" to accepted, "delivery" to "forwarded".json()))
            return if (loseReply) result.setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST) else result
        }
        fun reference(value: JsonObject) { status.set(value); watch?.let { send("approval.reference", it, jsonObject("status" to value)) } }
        fun finishLateDetails() { send("approval.details", lateDetails!!.string("request_id"), jsonObject("context" to body.root)) }
        private fun send(type: String, request: String, payload: JsonObject, scoped: Boolean = true) {
            var frame = jsonObject("v" to 1L.json(), "type" to type.json(), "request_id" to request.json(), "runtime_id" to runtime.json(), "payload" to payload)
            if (scoped) frame = frame.with("runtime_epoch" to body.root["runtime_epoch"], "session_id" to sessionId.json())
            check(socket.send(JsonDocument.of(frame).canonicalText()))
        }
        fun reader(scope: CoroutineScope) = resource.chatReader(device, runtime, sessionId, granted, commands, scope, approvalAccount = SessionApprovalAccount(bindingId, registered, journal))
        fun finish(prepared: PreparedApprovalSignature): SignedApprovalDecision {
            val signature = java.security.Signature.getInstance("SHA256withECDSA").run { initSign(approvalKey.toECPrivateKey()); update(prepared.signingInput()); sign() }
            return prepared.finishDerSignature(signature, System.currentTimeMillis())
        }
        suspend fun seed(context: ApprovalContext = body): ApprovalDecisionIntent {
            val signed = finish(ApprovalSignatures.prepare(context, ApprovalChoice.ALLOW_ONCE, registered, System.currentTimeMillis()))
            val intent = ApprovalDecisionIntent.create(UUID.randomUUID().toString(), owner, registered, context, signed, System.currentTimeMillis())
            journal.create(intent); journal.beginAttempt(intent.requestId)
            return intent
        }
        suspend fun review(reader: SessionReader): Pair<SessionApprovalClient, ApprovalReviewHandle> {
            val client = reader.approvals!!
            client.await { it.connected && it.contentReady && it.view.loaded && it.view.items.isNotEmpty() }
            client.requestDetails(body.root.string("approval_id"))
            val view = client.await { it.view.items.any { item -> item.handle != null } }.view.items.single { it.handle != null }
            assertEquals(body.bindingSha256, view.context!!.bindingSha256)
            return client to view.handle!!
        }
    }
    private suspend fun SessionApprovalClient.await(test: (ApprovalClientState) -> Boolean) = withTimeout(8000) { state.first(test) }.also { peerFailure.get()?.let { throw AssertionError(it) } }

    @Test fun approvalUsesCompleteFragmentedContextAndAPersistedOriginalWithFreshHttpProofs(): Unit = runBlocking {
        val fixture = ApprovalPeer(large = true); fixture.nonceChallenge = true
        fixture.reader(this).use { reader ->
            val (client, handle) = fixture.review(reader)
            val signed = fixture.finish(client.prepareSignature(handle, ApprovalChoice.ALLOW_ONCE))
            val id = client.submit(handle, signed)
            val accepted = client.await { it.records.any { row -> row.intent.requestId == id && row.delivery == ApprovalDecisionDelivery.ACCEPTED } }.records.single()
            val remote = accepted.remote!!
            assertTrue(accepted.intent.signed.compact == signed.compact); assertNull(remote.hostState); assertNull(remote.outcome)
            assertEquals(2, fixture.posts.get()); assertEquals(2, fixture.proofs.toSet().size)
            assertTrue(client.state.value.view.items.all { it.context == null })
            assertEquals(0L, reader.state.value.window!!.cursor)
        }
    }
    @Test fun anApprovalAttemptCommitFailureNeverPostsTheSignedDecision(): Unit = runBlocking {
        val fixture = ApprovalPeer(); fixture.journal.failBegin = true
        fixture.reader(this).use { reader ->
            val (client, handle) = fixture.review(reader)
            val signed = fixture.finish(client.prepareSignature(handle, ApprovalChoice.REJECT))
            assertThrows(CommandDataException::class.java) { runBlocking { client.submit(handle, signed) } }
            assertEquals(0, fixture.posts.get()); assertEquals(0L, fixture.journal.list(runtime, sessionId).single().attempts)
        }
    }
    @Test fun aLostApprovalReplyAndReaderReplacementRecoverTheOriginalWithoutReposting(): Unit = runBlocking {
        val fixture = ApprovalPeer(); fixture.loseReply = true; fixture.publishDecision = false
        val original = fixture.reader(this).use { reader ->
            val (client, handle) = fixture.review(reader)
            val signed = fixture.finish(client.prepareSignature(handle, ApprovalChoice.REJECT))
            assertThrows(RemoteRequestException::class.java) { runBlocking { client.submit(handle, signed) } }
            client.await { it.records.singleOrNull()?.delivery == ApprovalDecisionDelivery.ACCEPTED }.records.single().intent
        }
        fixture.feed.offline = true
        fixture.status.set(fixture.status.get().with("state" to "allowed".json(), "host_state" to "consumed".json()))
        fixture.reader(this).use { reader ->
            reader.await { it.phase == SessionReadPhase.OFFLINE }
            val restored = reader.approvals!!.await { it.records.singleOrNull()?.remote?.hostState == ApprovalHostState.CONSUMED }.records.single()
            assertEquals(original.requestId, restored.intent.requestId); assertTrue(original.signed.compact == restored.intent.signed.compact)
            assertEquals(1L, restored.attempts); assertEquals(1, fixture.posts.get())
            assertTrue(reader.approvals.state.value.view.items.all { it.context == null })
            assertFalse(reader.approvals.state.value.contentReady)
        }
    }
    @Test fun revocationIsProcessedWhileAnApprovalHttpResponseIsHeld(): Unit = runBlocking {
        val fixture = ApprovalPeer(); val release = java.util.concurrent.CountDownLatch(1); fixture.waitPost = release; fixture.publishDecision = false
        try { fixture.reader(this).use { reader ->
            val (client, handle) = fixture.review(reader)
            val signed = fixture.finish(client.prepareSignature(handle, ApprovalChoice.ALLOW_ONCE))
            val send = async { runCatching { client.submit(handle, signed) } }
            withTimeout(5000) { while (fixture.posted.count != 0L) delay(5) }
            fixture.feed.control("access.revoked", jsonObject("code" to "access.revoked".json()))
            reader.await { it.phase == SessionReadPhase.REVOKED }
            assertTrue(client.state.value.view.items.isEmpty())
            release.countDown(); withTimeout(5000) { send.await() }
        } } finally { release.countDown() }
    }
    @Test fun aCompetingDecisionWhileHttpIsQueuedRetiresTheSignatureBeforeAnyPost(): Unit = runBlocking {
        val fixture = ApprovalPeer(); val release = java.util.concurrent.CountDownLatch(1); fixture.waitDirectory = release
        try { fixture.reader(this).use { reader ->
            val (client, handle) = fixture.review(reader)
            val signed = fixture.finish(client.prepareSignature(handle, ApprovalChoice.ALLOW_ONCE))
            val directory = async(Dispatchers.IO) { fixture.resource.runtimes() }
            withTimeout(5000) { while (fixture.directoryEntered.count != 0L) delay(5) }
            val send = async { runCatching { client.submit(handle, signed) } }
            withTimeout(5000) { while (fixture.journal.list(runtime, sessionId).singleOrNull()?.attempts != 1L) delay(5) }
            fixture.reference(fixture.pending.with("state" to "denied".json(), "decision" to "reject".json(), "decision_payload_sha256" to "d".repeat(64).json()))
            client.await { it.view.items.all { item -> item.context == null } }
            release.countDown(); directory.await()
            assertTrue(send.await().isFailure); assertEquals(0, fixture.posts.get())
        } } finally { release.countDown() }
    }
    @Test fun anUnnegotiatedApprovalCapabilityKeepsReadingAvailableWithoutLoadingAForm(): Unit = runBlocking {
        val fixture = ApprovalPeer(); fixture.support = false
        fixture.reader(this).use { reader ->
            reader.await { it.phase == SessionReadPhase.READY }
            assertFalse(reader.approvals!!.state.value.supported)
            assertThrows(ApprovalStateException::class.java) { runBlocking { reader.approvals.requestDetails(fixture.body.root.string("approval_id")) } }
            assertEquals(0, fixture.posts.get())
        }
    }
    @Test fun schoolAssuranceFailureRemainsAnUnconfirmedOriginalWithoutInventingLocalMfa(): Unit = runBlocking {
        val fixture = ApprovalPeer(); fixture.denyApproval = "approval.assurance_required"
        fixture.reader(this).use { reader ->
            val (client, handle) = fixture.review(reader)
            val signed = fixture.finish(client.prepareSignature(handle, ApprovalChoice.ALLOW_ONCE))
            val rejected = assertThrows(RemoteRequestException::class.java) { runBlocking { client.submit(handle, signed) } }
            assertEquals("approval.assurance_required", rejected.code)
            assertEquals(ApprovalDecisionDelivery.RECONCILE, fixture.journal.list(runtime, sessionId).single().delivery)
            assertEquals(1, fixture.posts.get()); assertTrue(client.state.value.view.items.any { it.context != null })
        }
    }
    @Test fun anExplicitPendingRetryReusesTheSameSignedBytesAndRequiresANewAttemptCommit(): Unit = runBlocking {
        val fixture = ApprovalPeer(); fixture.dropBeforeCommit = true
        fixture.reader(this).use { reader ->
            val (client, handle) = fixture.review(reader)
            val signed = fixture.finish(client.prepareSignature(handle, ApprovalChoice.REJECT))
            assertThrows(RemoteRequestException::class.java) { runBlocking { client.submit(handle, signed) } }
            val original = fixture.journal.list(runtime, sessionId).single()
            fixture.dropBeforeCommit = false
            client.sendPending(handle, original.intent.requestId)
            val confirmed = client.await { it.records.singleOrNull()?.delivery == ApprovalDecisionDelivery.ACCEPTED }.records.single()
            assertEquals(original.intent.requestId, confirmed.intent.requestId); assertTrue(confirmed.intent.signed.compact == signed.compact)
            assertEquals(2L, confirmed.attempts); assertEquals(2, fixture.posts.get())
        }
    }
    @Test fun aRetryThatDiscoversAcceptanceSavesItWithoutAnotherPost(): Unit = runBlocking {
        val fixture = ApprovalPeer(); fixture.loseReply = true; fixture.publishDecision = false; fixture.statusOverride = fixture.pending
        fixture.reader(this).use { reader ->
            val (client, handle) = fixture.review(reader)
            val signed = fixture.finish(client.prepareSignature(handle, ApprovalChoice.ALLOW_ONCE))
            assertThrows(RemoteRequestException::class.java) { runBlocking { client.submit(handle, signed) } }
            val original = fixture.journal.list(runtime, sessionId).single()
            fixture.statusOverride = null
            assertThrows(CommandDataException::class.java) { runBlocking { client.sendPending(handle, original.intent.requestId) } }
            client.await { it.records.singleOrNull()?.delivery == ApprovalDecisionDelivery.ACCEPTED }
            assertEquals(1, fixture.posts.get()); assertEquals(1L, fixture.journal.list(runtime, sessionId).single().attempts)
        }
    }
    @Test fun aCompetingDecisionRetiresAnInflightDetailResponseBeforeItCanExposeArguments(): Unit = runBlocking {
        val fixture = ApprovalPeer(); fixture.holdDetails = true
        fixture.reader(this).use { reader ->
            val client = reader.approvals!!
            client.await { it.connected && it.contentReady && it.view.loaded }
            client.requestDetails(fixture.body.root.string("approval_id"))
            withTimeout(5000) { while (fixture.lateDetails == null) delay(5) }
            fixture.reference(fixture.pending.with("state" to "cancelled".json()))
            client.await { it.view.loadingId == null && it.view.items.none { item -> item.canReview } }
            fixture.finishLateDetails()
            fixture.feed.send("session.event", user(1, "after retired details"))
            reader.await { it.window?.cursor == 1L }
            assertTrue(client.state.value.view.items.all { it.context == null }); assertEquals(0, fixture.posts.get())
        }
    }
    @Test fun anUnavailableOriginalStatusDoesNotRevokeAnOtherwiseAuthorizedSessionRead(): Unit = runBlocking {
        val fixture = ApprovalPeer(); fixture.seed(); fixture.denyStatus = true
        fixture.reader(this).use { reader ->
            reader.await { it.phase == SessionReadPhase.READY }
            reader.approvals!!.await { it.error == "approval.status_unavailable" }
            assertEquals(SessionReadPhase.READY, reader.state.value.phase)
            assertEquals(1, reader.approvals.state.value.records.size)
        }
    }
    @Test fun currentTicketResourcesFilterStoredApprovalBodiesAndAutomaticStatusQueries(): Unit = runBlocking {
        val fixture = ApprovalPeer(workspaceScope = true); val visible = fixture.seed()
        val foreign = ApprovalContext.from(JsonDocument.of(fixture.body.root.with("approval_id" to UUID.randomUUID().toString().json(), "execution_id" to UUID.randomUUID().toString().json(),
            "workspace" to fixture.body.root.obj("workspace").with("workspace_id" to bindingId.json()),
            "nonce" to Contract.base64url(ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }).json())))
        fixture.seed(foreign)
        fixture.reader(this).use { reader ->
            val client = reader.approvals!!
            val retained = client.await { it.connected && it.contentReady && it.records.singleOrNull()?.remote != null }.records.single()
            assertEquals(visible.requestId, retained.intent.requestId)
            client.query(); withTimeout(5000) { while (fixture.queries.get() < 2) delay(5) }
            assertTrue(fixture.requestedStatuses.all { it == visible.approvalId })
            assertEquals(2, fixture.journal.list(runtime, sessionId).size)
        }
    }
    @Test fun aLateSignatureCancellationCannotCancelANewerPerUsePreparation(): Unit = runBlocking {
        val fixture = ApprovalPeer()
        fixture.reader(this).use { reader ->
            val (client, handle) = fixture.review(reader)
            val first = client.prepareSignature(handle, ApprovalChoice.ALLOW_ONCE)
            client.cancelSignature(first)
            val second = client.prepareSignature(handle, ApprovalChoice.REJECT)
            client.cancelSignature(first)
            assertTrue(client.state.value.signing)
            client.submit(handle, fixture.finish(second))
            client.await { it.records.singleOrNull()?.delivery == ApprovalDecisionDelivery.ACCEPTED }
            assertEquals(1, fixture.posts.get())
        }
    }
    @Test fun discardingOnlyAnUnattemptedOriginalRequiresAnotherOnlineReview(): Unit = runBlocking {
        val fixture = ApprovalPeer(); fixture.journal.failBegin = true
        fixture.reader(this).use { reader ->
            val (client, handle) = fixture.review(reader)
            val signed = fixture.finish(client.prepareSignature(handle, ApprovalChoice.ALLOW_ONCE))
            assertThrows(CommandDataException::class.java) { runBlocking { client.submit(handle, signed) } }
            val local = fixture.journal.list(runtime, sessionId).single()
            client.discardUnsent(local.intent.requestId)
            assertTrue(fixture.journal.list(runtime, sessionId).isEmpty()); assertTrue(client.state.value.view.items.all { it.handle == null })
            fixture.journal.failBegin = false
            val (_, fresh) = fixture.review(reader)
            assertNotEquals(handle, fresh)
            client.submit(fresh, fixture.finish(client.prepareSignature(fresh, ApprovalChoice.REJECT)))
            val attempted = fixture.journal.list(runtime, sessionId).single()
            assertThrows(CommandDataException::class.java) { runBlocking { client.discardUnsent(attempted.intent.requestId) } }
            assertEquals(1, fixture.posts.get())
        }
    }

    private fun questionPayload(timed: Boolean=false,phase: String="open",revision: Long=1,detail: String="Review this plan") : JsonObject {
        var item=jsonObject("question_id" to "99999999-9999-4999-8999-999999999999".json(),"expires_at" to (if(timed) JsonNull else time(60_000)),"questions" to JsonArray(listOf(jsonObject("id" to "plan".json(),"question" to "Continue?".json(),"detail" to detail.json(),"options" to JsonArray(listOf(jsonObject("label" to "Continue".json()),jsonObject("label" to "Cancel".json()))),"intent" to jsonObject("kind" to "plan-review".json(),"approve" to "Continue".json())))))
        if(timed) item=item.with("state" to phase.json())
        return jsonObject("revision" to revision.json(),"items" to JsonArray(listOf(item)))
    }
    @Test fun aCurrentBlockingPlanAcceptsOneCompleteAnswerAndUsesAuthoritativeSettlement(): Unit=runBlocking {
        val fixture=CommandPeer(true);fixture.advertisedState=RemoteCommandState.SETTLED
        fixture.reader(this).use {reader->
            reader.await {it.phase==SessionReadPhase.READY};fixture.feed.send("question.snapshot",questionPayload())
            val view=reader.await {it.questions.items.isNotEmpty()}.questions.items.single()
            assertTrue(reader.state.value.questions.canAnswer)
            assertThrows(QuestionStateException::class.java) {runBlocking {reader.answerQuestion(view.handle,QuestionAnswers(view.batch.id,listOf(QuestionAnswer("plan",listOf("bad")))))}}
            val answers=QuestionAnswers(view.batch.id,listOf(QuestionAnswer("plan",listOf("Continue"),"中文答复")))
            val id=reader.answerQuestion(view.handle,answers)
            withTimeout(5000) {reader.commands!!.state.first {it.records.any {row->row.intent.requestId==id && row.remote==RemoteCommandState.SETTLED}}}
            assertFalse(fixture.journal.list(runtime,sessionId).single().everAgentQueued)
            assertThrows(CommandDataException::class.java) {runBlocking {reader.answerQuestion(view.handle,answers)}}
            fixture.feed.send("question.snapshot",jsonObject("revision" to 2L.json(),"items" to JsonArray(emptyList())))
            reader.await {it.questions.blockingLoaded && it.questions.items.isEmpty()}
            assertEquals(0L,reader.state.value.window!!.cursor);assertEquals(1,fixture.writes.size)
        }
    }
    @Test fun readPermissionCanDisplayQuestionsButCannotClaimOrAnswer(): Unit=runBlocking {
        val fixture=CommandPeer()
        fixture.reader(this).use {reader->
            reader.await {it.phase==SessionReadPhase.READY};fixture.feed.send("question.timed.snapshot",questionPayload(true))
            val view=reader.await {it.questions.items.isNotEmpty()}.questions.items.single()
            assertFalse(reader.state.value.questions.canAnswer)
            assertThrows(RemoteRequestException::class.java) {runBlocking {reader.claimQuestion(view.handle)}}
            assertThrows(RemoteRequestException::class.java) {runBlocking {reader.answerQuestion(view.handle,QuestionAnswers(view.batch.id,listOf(QuestionAnswer("plan",emptyList()))))}}
            assertTrue(fixture.journal.list(runtime,sessionId).isEmpty());assertTrue(fixture.writes.isEmpty())
        }
    }
    @Test fun timedClaimReleaseAndLateAnswerUseTheCurrentSubscriptionWithoutRepeatingTheCallback(): Unit=runBlocking {
        val fixture=CommandPeer(true);var claim: String?=null
        fixture.feed.onClaim={_,frame->when(frame.string("type")) {
            "question.claim"->{claim=frame.string("request_id");Thread.sleep(150);fixture.feed.send("question.claimed",jsonObject("question_id" to frame.obj("payload").string("question_id").json(),"remaining_ms" to 1500L.json(),"expires_at" to time(1500)),requestId=claim!!)}
            "question.release"->{assertEquals(claim,frame.obj("payload").string("claim_id"));fixture.feed.send("question.released",jsonObject("claim_id" to claim!!.json()),requestId=frame.string("request_id"));fixture.feed.send("question.timed.snapshot",questionPayload(true,"continued",2))}
        }}
        fixture.reader(this).use {reader->
            reader.await {it.phase==SessionReadPhase.READY};fixture.feed.send("question.timed.snapshot",questionPayload(true))
            val view=reader.await {it.questions.items.isNotEmpty()}.questions.items.single()
            assertNull(view.remainingMillis);reader.claimQuestion(view.handle)
            val active=reader.await {it.questions.items.single().claim?.phase==ClaimPhase.ACTIVE}.questions.items.single()
            assertTrue(active.remainingMillis!!<1500)
            reader.releaseQuestion(view.handle)
            val continued=reader.await {it.questions.items.single().batch.phase==QuestionPhase.CONTINUED}.questions.items.single()
            reader.answerQuestion(continued.handle,QuestionAnswers(continued.batch.id,listOf(QuestionAnswer("plan",emptyList(),"late answer"))))
            withTimeout(5000) {reader.commands!!.state.first {it.records.singleOrNull()?.everAgentQueued==true}}
            assertEquals("question.timed.answer",fixture.writes.single().string("type"))
        }
    }
    @Test fun disconnectAndRevocationNeverRetainAnAnswerableQuestionInTheCachedTranscript(): Unit=runBlocking {
        val fixture=CommandPeer(true)
        fixture.reader(this).use {reader->
            reader.await {it.phase==SessionReadPhase.READY};fixture.feed.send("question.snapshot",questionPayload())
            val old=reader.await {it.questions.items.isNotEmpty()}.questions.items.single()
            fixture.feed.control("server.draining",jsonObject("reason" to "server_draining".json()))
            val closed=reader.await {it.phase==SessionReadPhase.BACKOFF}
            assertTrue(closed.questions.items.isEmpty())
            assertThrows(QuestionStateException::class.java) {runBlocking {reader.answerQuestion(old.handle,QuestionAnswers(old.batch.id,listOf(QuestionAnswer("plan",listOf("Continue")))))}}
        }
    }
    @Test fun aStoredAnswerCannotBeTransferredToChangedQuestionContentOnReconnect(): Unit=runBlocking {
        val fixture=CommandPeer(true);fixture.advertisedState=RemoteCommandState.RECEIVED
        fixture.reader(this).use {reader->
            reader.await {it.phase==SessionReadPhase.READY};fixture.feed.send("question.snapshot",questionPayload())
            val original=reader.await {it.questions.items.isNotEmpty()}.questions.items.single()
            val id=reader.answerQuestion(original.handle,QuestionAnswers(original.batch.id,listOf(QuestionAnswer("plan",listOf("Continue")))))
            withTimeout(5000) {reader.commands!!.state.first {it.records.singleOrNull()?.remote==RemoteCommandState.RECEIVED}}
            fixture.feed.control("server.draining",jsonObject("reason" to "server_draining".json()))
            reader.await {it.phase==SessionReadPhase.BACKOFF};reader.await {it.phase==SessionReadPhase.READY}
            fixture.feed.send("question.snapshot",questionPayload(detail="A changed plan"))
            reader.await {it.questions.items.firstOrNull()?.batch?.definition?.let {hash->hash!=original.batch.definition}==true}
            reader.commands!!.sendPending(id)
            withTimeout(5000) {reader.commands.state.first {it.error=="question.stale"}}
            assertEquals(1,fixture.writes.size);assertEquals(1L,fixture.journal.list(runtime,sessionId).single().attempts)
        }
    }
    @Test fun strongerStatusProofIsSavedEvenWhenItMakesExplicitRetryIneligible(): Unit=runBlocking {
        val fixture=CommandPeer();fixture.advertisedState=RemoteCommandState.RECEIVED
        fixture.reader(this).use {reader->
            reader.await {it.phase==SessionReadPhase.READY};val commands=reader.commands!!
            val id=commands.submit("queue","one original")
            withTimeout(5000) {commands.state.first {it.records.singleOrNull()?.remote==RemoteCommandState.RECEIVED}}
            fixture.statuses.compute(id) {_,value->value!!.with("state" to "settled".json(),"updated_at" to time(0))}
            commands.sendPending(id)
            withTimeout(5000) {commands.state.first {it.error=="command.reconcile_required" && it.records.singleOrNull()?.remote==RemoteCommandState.SETTLED}}
            assertEquals(1,fixture.writes.size);assertEquals(1L,fixture.journal.list(runtime,sessionId).single().attempts)
        }
    }
    private inner class CreationPeer {
        val workspace="88888888-8888-4888-8888-888888888888"
        val granted=RelayScope(listOf("session.create","command.status"),listOf(workspace),emptyList())
        val journal=MemoryCommandJournal(CommandOwner("99999999-9999-4999-8999-999999999999",config.organizationId,config.fingerprint,"77777777-7777-4777-8777-777777777777",device))
        val statuses=java.util.concurrent.ConcurrentHashMap<String,JsonObject>()
        val writes=java.util.concurrent.CopyOnWriteArrayList<JsonObject>()
        var epoch="44444444-4444-4444-8444-444444444444"
        var offline=false
        var loseReply=false
        val nativeCreates=java.util.concurrent.atomic.AtomicInteger()
        private val caps=listOf("connection.heartbeat.v1","command.relay.v1","session.create.v1","session.create_options.v1")
        init {
            server.dispatcher=object : okhttp3.mockwebserver.Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse=when {
                    request.path=="/v1/me"->bindingReply(jsonObject("issuer" to config.issuer.json(),"subject" to "school-user".json(),"client_id" to config.clientId.json(),"scopes" to JsonArray(listOf("remote.access".json())),"user_id" to journal.owner.userId.json(),"memberships" to JsonArray(listOf(jsonObject("organization_id" to config.organizationId.json(),"role" to "member".json())))))
                    request.path=="/v1/realtime/tickets"->bindingReply(jsonObject("ticket" to token.json(),"runtime_id" to runtime.json(),"grant_version" to 7L.json(),"scope" to granted.json(),"expires_at" to time(30_000))).setResponseCode(201)
                    request.path=="/v1/realtime"->peer(accepted=helloOk().with("payload" to helloOk().obj("payload").with("scope" to granted.json(),"capabilities" to JsonArray(caps.map(String::json)))),expectedCapabilities=caps,onContent=::receive)
                    request.path!!.startsWith("/v1/commands/")->{
                        assertEquals(device,request.requestUrl!!.queryParameter("device_id"))
                        statuses[request.requestUrl!!.pathSegments.last()]?.let(::bindingReply) ?: json(jsonObject("ok" to JsonBoolean(false),"error" to jsonObject("code" to "access.denied".json()))).setResponseCode(403)
                    }
                    else->MockResponse().setResponseCode(404)
                }
            }
        }
        private fun receive(socket: WebSocket,frame: JsonObject) {
            when(frame.string("type")) {
                "session.create.options.get"->{
                    val result=if(offline) jsonObject("v" to 1L.json(),"type" to "error".json(),"request_id" to frame.string("request_id").json(),"runtime_id" to runtime.json(),"payload" to jsonObject("code" to "runtime.offline".json())) else jsonObject("v" to 1L.json(),"type" to "session.create.options.result".json(),"request_id" to frame.string("request_id").json(),"runtime_id" to runtime.json(),"runtime_epoch" to epoch.json(),"payload" to jsonObject("workspaces" to JsonArray(listOf(jsonObject("workspace_id" to workspace.json(),"label" to "Project".json()))),"presets" to JsonArray(listOf("standard".json()))))
                    socket.send(JsonDocument.of(result).canonicalText())
                }
                "session.create"->{
                    val intent=CommandIntent.parse(frame); writes+=frame
                    assertEquals(epoch,intent.epoch); assertEquals(workspace,intent.workspaceId)
                    assertTrue(runBlocking {journal.listCreations(runtime).single {it.intent.requestId==intent.requestId}.attempts}>0)
                    statuses.computeIfAbsent(intent.requestId) {nativeCreates.incrementAndGet();status(intent)}
                    if(loseReply) {loseReply=false;socket.close(1001,"fixture receipt lost");return}
                    val proof=statuses[intent.requestId]!!
                    socket.send(JsonDocument.of(jsonObject("v" to 1L.json(),"type" to "command.receipt".json(),"request_id" to intent.requestId.json(),"runtime_id" to runtime.json(),"runtime_epoch" to epoch.json(),"session_id" to sessionId.json(),"payload" to JsonObject(proof.fields.filterKeys {it in setOf("state","payload_sha256","updated_at","workspace_id")}))).canonicalText())
                }
                else->error("unexpected creation frame")
            }
        }
        fun status(intent: CommandIntent)=jsonObject("request_id" to intent.requestId.json(),"workspace_id" to workspace.json(),"session_id" to sessionId.json(),"state" to "settled".json(),"payload_sha256" to intent.digest.json(),"updated_at" to time(0))
        fun flow(owner: CoroutineScope)=api().sessionCreator(device,runtime,granted,journal,owner)
    }
    private suspend fun SessionCreationFlow.await(test: (SessionCreationState)->Boolean)=withTimeout(10_000) {state.first(test)}.also {peerFailure.get()?.let {throw AssertionError(it)}}
    @Test fun creationUsesWorkspaceOptionsAndPersistsASeparateResultWithoutAReadSubscription(): Unit=runBlocking {
        val fixture=CreationPeer()
        fixture.flow(this).use {flow->
            val options=flow.await {it.phase==SessionCreationPhase.READY}.options!!
            assertThrows(RemoteRequestException::class.java) {runBlocking {flow.create(fixture.workspace,"../standard",options.epoch)}}
            val id=flow.create(fixture.workspace,"standard",options.epoch)
            assertEquals(id,flow.state.value.outbox.records.single().intent.requestId)
            val settled=flow.await {it.outbox.records.singleOrNull()?.createdSessionId==sessionId}.outbox.records.single()
            assertNull(settled.intent.sessionId); assertEquals(fixture.workspace,settled.intent.workspaceId); assertEquals(1,fixture.nativeCreates.get())
            assertFalse(settled.everAgentQueued); assertEquals(1L,settled.attempts)
        }
    }
    @Test fun aLostCreationReceiptReconcilesTheSameIdAndCannotReplayItsSettledResult(): Unit=runBlocking {
        val fixture=CreationPeer(); fixture.loseReply=true
        fixture.flow(this).use {flow->
            val options=flow.await {it.phase==SessionCreationPhase.READY}.options!!
            val id=flow.create(fixture.workspace,"standard",options.epoch)
            flow.await {it.phase==SessionCreationPhase.READY && it.outbox.records.singleOrNull()?.createdSessionId==sessionId}
            flow.sendPending(id)
            flow.await {it.outbox.error=="command.reconcile_required"}
            assertEquals(1,fixture.nativeCreates.get());assertEquals(1,fixture.writes.size);assertEquals(1L,fixture.journal.listCreations(runtime).single().attempts)
        }
    }
    @Test fun anOldEpochCreationIsNotRetargetedToANewOptionsSnapshot(): Unit=runBlocking {
        val fixture=CreationPeer()
        val original=CommandIntent.createSession(UUID.randomUUID().toString(),runtime,fixture.workspace,"standard",fixture.epoch)
        fixture.journal.create(original); fixture.epoch=UUID.randomUUID().toString()
        fixture.flow(this).use {flow->
            flow.await {it.phase==SessionCreationPhase.READY && it.outbox.records.isNotEmpty()}
            flow.sendPending(original.requestId)
            assertEquals("runtime.changed",flow.state.value.error)
            assertTrue(fixture.writes.isEmpty());assertEquals(0L,fixture.journal.listCreations(runtime).single().attempts)
            assertEquals(original.epoch,fixture.journal.listCreations(runtime).single().intent.epoch)
        }
    }
    @Test fun creationStatusReconciliationWorksEvenWhenTheHostCannotProvideOptions(): Unit=runBlocking {
        val fixture=CreationPeer();fixture.offline=true
        val original=CommandIntent.createSession(UUID.randomUUID().toString(),runtime,fixture.workspace,"standard",fixture.epoch)
        fixture.journal.create(original);fixture.journal.beginAttempt(original.requestId);fixture.statuses[original.requestId]=fixture.status(original)
        fixture.flow(this).use {flow->
            flow.await {it.phase==SessionCreationPhase.OFFLINE && it.outbox.records.singleOrNull()?.createdSessionId==sessionId}
            assertTrue(fixture.writes.isEmpty());assertEquals(0,fixture.nativeCreates.get())
        }
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
    @Test fun negotiatedFileIdsAreSavedBeforeWritingAndAnOlderPeerNeverGetsThem(): Unit = runBlocking {
        val fixture = CommandPeer()
        fixture.reader(this).use { reader ->
            reader.await { it.phase == SessionReadPhase.READY }
            val commands = reader.commands!!
            withTimeout(5000) { commands.state.first { it.canAttachFiles } }
            val file = UUID.randomUUID().toString()
            val id = commands.submit("queue", "", fileIds = listOf(file))
            val saved = withTimeout(5000) { commands.state.first { state -> state.records.any { it.intent.requestId == id && it.everAgentQueued } } }.records.single()
            assertEquals(listOf(file), saved.intent.fileIds()); assertEquals("", saved.intent.text())
            assertEquals(file, fixture.writes.single().obj("payload").array("content").let { (it.single() as JsonObject).string("file_id") })
        }
        val older = CommandPeer(advertiseFiles = false)
        older.reader(this).use { reader ->
            reader.await { it.phase == SessionReadPhase.READY }
            val commands = reader.commands!!
            assertFalse(commands.state.value.canAttachFiles)
            val id = commands.submit("queue", "original", fileIds = listOf(UUID.randomUUID().toString()))
            withTimeout(5000) { commands.state.first { it.error == "file.unsupported" } }
            assertTrue(older.writes.isEmpty()); assertEquals(0, older.journal.list(runtime, sessionId).single { it.intent.requestId == id }.attempts)
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
    @Test fun archiveOnlyScopePersistsOriginalBeforeWritingAndReconcilesWithoutReplay(): Unit = runBlocking {
        val fixture = CommandPeer(archive = true, archiveOnly = true)
        fixture.advertisedState = RemoteCommandState.SETTLED
        var id = ""
        fixture.reader(this).use { reader ->
            val ready = reader.await { it.phase == SessionReadPhase.READY }
            val commands = reader.commands!!
            withTimeout(5000) { commands.state.first { it.connected && it.canArchive } }
            assertThrows(CommandDataException::class.java) { runBlocking { commands.archive(false, false, runtime) } }
            assertThrows(ProtocolException::class.java) { runBlocking { commands.archive(false, true, ready.runtimeEpoch!!) } }
            assertTrue(fixture.writes.isEmpty())
            id = commands.archive(false, false, ready.runtimeEpoch!!)
            val saved = withTimeout(5000) { commands.state.first { it.records.singleOrNull()?.remote == RemoteCommandState.SETTLED } }.records.single()
            assertEquals(CommandKind.ARCHIVE, saved.intent.kind); assertFalse(saved.everAgentQueued)
            assertEquals(JsonBoolean(false), saved.intent.payload["archived"])
            assertEquals(1L, saved.attempts)
        }
        fixture.reader(this).use { reopened ->
            reopened.await { it.phase == SessionReadPhase.READY }
            val rows = withTimeout(5000) { reopened.commands!!.state.first { it.records.singleOrNull()?.intent?.requestId == id } }.records
            assertEquals(RemoteCommandState.SETTLED, rows.single().remote)
            delay(150)
            assertEquals(1, fixture.writes.size)
        }
    }
    @Test fun unsupportedArchiveAndFailedArchiveDurabilityNeverReachTheSocket(): Unit = runBlocking {
        val unsupported = CommandPeer()
        unsupported.reader(this).use { reader ->
            val ready = reader.await { it.phase == SessionReadPhase.READY }
            assertFalse(reader.commands!!.state.value.canArchive)
            assertThrows(RemoteRequestException::class.java) { runBlocking { reader.commands!!.archive(true, false, ready.runtimeEpoch!!) } }
            assertTrue(unsupported.writes.isEmpty())
        }
        val fixture = CommandPeer(archive = true)
        fixture.journal.failBegin = true
        fixture.reader(this).use { reader ->
            val ready = reader.await { it.phase == SessionReadPhase.READY }
            reader.commands!!.archive(true, true, ready.runtimeEpoch!!)
            withTimeout(5000) { reader.commands!!.state.first { it.error == "data.unavailable" } }
            assertTrue(fixture.writes.isEmpty())
            assertEquals(0L, fixture.journal.list(runtime, sessionId).single().attempts)
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
