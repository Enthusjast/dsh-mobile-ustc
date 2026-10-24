package cn.edu.ustc.dsh.mobile

import android.content.Context
import cn.edu.ustc.dsh.auth.*
import cn.edu.ustc.dsh.crypto.PublicProofKey
import cn.edu.ustc.dsh.keystore.*
import cn.edu.ustc.dsh.network.LoginHttp
import cn.edu.ustc.dsh.network.RemoteApi
import cn.edu.ustc.dsh.protocol.*
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import okhttp3.*
import okhttp3.mockwebserver.*
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import java.net.URLDecoder
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** Test APK only: local TLS, generated issuer credentials and real Android key handles. */
internal class AccountFixture(private val context: Context) : AutoCloseable {
    val slot = "fixture-" + UUID.randomUUID()
    val ledgerName = slot + "-keys"
    val accountId = UUID.randomUUID().toString()
    val organizationId = "11111111-1111-4111-8111-111111111111"
    val userId = "22222222-2222-4222-8222-222222222222"
    val deviceId = "33333333-3333-4333-8333-333333333333"
    val runtimeId = "55555555-5555-4555-8555-555555555555"
    val sessionId = "66666666-6666-4666-8666-666666666666"
    val bindingId = "88888888-8888-4888-8888-888888888888"
    val bindingCode = "J".repeat(42) + "A"
    val subject = "school-fixture-user"
    private val server = MockWebServer()
    private val issuerKey = ECKeyGenerator(Curve.P_256).keyID("local-account-issuer").generate()
    private val installationKey = ECKeyGenerator(Curve.P_256).generate()
    private val certificate = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
    private val serverCertificates = HandshakeCertificates.Builder().heldCertificate(certificate).build()
    private val clientCertificates = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
    val failure = AtomicReference<String?>()
    val refreshRequests = AtomicInteger()
    val registrationRequests = AtomicInteger()
    val meRequests = AtomicInteger()
    val hostRequests = AtomicInteger()
    val sessionRequests = AtomicInteger()
    val ticketRequests = AtomicInteger()
    val subscriptions = AtomicInteger()
    val relayClosures = AtomicInteger()
    val bindingPreviews = AtomicInteger()
    val bindingWrites = AtomicInteger()
    val bindingStatusReads = AtomicInteger()
    val commandWrites = AtomicInteger()
    val commandStatuses = java.util.concurrent.ConcurrentHashMap<String, JsonObject>()
    @Volatile var chatMode = false
    @Volatile var runtimeOffline = false
    @Volatile var dropNextCommandReply = false
    @Volatile var bindingMode = false
    @Volatile var bindingUserConfirmed = false
    @Volatile var bindingHostConfirmed = false
    @Volatile var bindingConfirmedElsewhere = false
    @Volatile var dropBindingReply = false
    @Volatile var holdBindingPreview = false
    @Volatile var bindingProfile = "fixture-profile"
    @Volatile var bindingExpiresAt = System.currentTimeMillis() + 299_000
    val bindingApproved get() = bindingUserConfirmed && bindingHostConfirmed
    @Volatile var allowSessionRead = true
    @Volatile var holdSessions = false
    private val directoryScope get() = RelayScope((if (allowSessionRead) listOf("session.list", "session.read") else listOf("session.list")) +
        if (chatMode) listOf("message.submit", "command.status", "session.cancel") else emptyList(), emptyList(), listOf(sessionId))
    private val currentRelay = AtomicReference<WebSocket?>()
    @Volatile var relayProofReceived = false
    private var relayScope: RelayScope? = null
    private var relayProofKey: ECKey? = null
    private var relayAccessExpiresAt = 0L
    private val relayToken = "C".repeat(42) + "A"
    @Volatile var active = false
    @Volatile var revoked = false
    @Volatile var member = true
    @Volatile var serviceUserId = userId
    @Volatile var browserSubject = subject
    @Volatile var browserNonce = ""
    @Volatile var browserChallenge = ""
    @Volatile var dropRegistrationReply = false
    @Volatile var dropRefreshReply = false
    @Volatile var holdRefresh = false
    @Volatile var proofJkt: String? = null
    @Volatile var approvalJkt: String? = null
    private var refreshSecret = "fixture-refresh-1"
    private var grantNumber = 1
    private val seenProofs = hashSetOf<String>()
    private val resourceNonces = hashSetOf<String>()
    // Avoid calling MockWebServer.before() from a dispatcher while shutdown()
    // holds that server monitor and awaits its dispatch queues.
    val origin: String
    val issuer: String get() = origin + "/issuer"
    val configBytes: ByteArray get() = JsonDocument.of(jsonObject(
        "issuer" to issuer.json(), "client_id" to "mobile".json(), "redirect_uri" to LoginConfiguration.REDIRECT_URI.json(),
        "resource" to "urn:dsh-fixture".json(), "audience" to "urn:dsh-fixture".json(), "remote_origin" to origin.json(),
        "organization_id" to organizationId.json(), "scopes" to JsonArray(listOf("openid".json(), "remote.access".json())),
        "endpoint_origins" to JsonArray(listOf(origin.json())), "signing_algorithms" to JsonArray(listOf("ES256".json())),
    )).canonicalBytes()
    val config: LoginConfiguration get() = LoginConfiguration.parse(configBytes)
    val vault get() = AccountVault(context, slot)
    private val reference get() = ScopeReference(accountId, organizationId)
    val http: LoginHttp
    private val transport: OkHttpClient
    init {
        server.useHttps(serverCertificates.sslSocketFactory(), false)
        server.dispatcher = object : okhttp3.mockwebserver.Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = try { respond(request) }
            catch (error: Exception) {
                val location = error.stackTrace.firstOrNull { it.className.contains("AccountFixture") }
                failure.set("fixture protocol failure: ${error.javaClass.simpleName} at $location")
                response(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "internal".json())), 500)
            }
        }
        server.start()
        origin = server.url("/").toString().trimEnd('/')
        transport = OkHttpClient.Builder().sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager)
            .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false).cookieJar(CookieJar.NO_COOKIES)
            .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS).readTimeout(5, java.util.concurrent.TimeUnit.SECONDS).callTimeout(10, java.util.concurrent.TimeUnit.SECONDS).build()
        // The production factory still trusts system TLS only. Reflection is confined to this test APK.
        http = LoginHttp::class.java.getDeclaredConstructor(OkHttpClient::class.java).apply { isAccessible = true }.newInstance(transport)
    }
    fun environment(minimumValidity: Long = 0) = LoginEnvironment({ configBytes }, slot, ledgerName, refreshLeadMillis = 0, minimumValidityMillis = minimumValidity)
    private fun discovery() = jsonObject("issuer" to issuer.json(), "authorization_endpoint" to "$origin/authorize".json(),
        "token_endpoint" to "$origin/token".json(), "jwks_uri" to "$origin/jwks".json(),
        "response_types_supported" to JsonArray(listOf("code".json())), "id_token_signing_alg_values_supported" to JsonArray(listOf("ES256".json())))
    private fun jwt(claims: JsonObject, type: String) = JWSObject(JWSHeader.Builder(JWSAlgorithm.ES256).keyID(issuerKey.keyID).type(JOSEObjectType(type)).build(), Payload(JsonDocument.of(claims).canonicalText())).apply { sign(ECDSASigner(issuerKey)) }.serialize()
    private fun tokenReply(jkt: String, userSubject: String, nonce: String?, ttl: Long): JsonObject {
        val now = System.currentTimeMillis() / 1000
        val common = jsonObject("iss" to issuer.json(), "sub" to userSubject.json(), "iat" to now.json(), "exp" to (now + ttl).json())
        val access = jwt(common.with("aud" to config.audience.json(), "client_id" to config.clientId.json(), "jti" to UUID.randomUUID().toString().json(), "scope" to "remote.access".json(), "cnf" to jsonObject("jkt" to jkt.json())), "at+jwt")
        var reply = jsonObject("access_token" to access.json(), "token_type" to "DPoP".json(), "expires_in" to ttl.json(), "refresh_token" to refreshSecret.json())
        if (nonce != null) reply = reply.with("id_token" to jwt(common.with("aud" to config.clientId.json(), "nonce" to nonce.json()), "JWT").json())
        return reply
    }
    private fun response(root: JsonObject, status: Int = 200) = MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json").setBody(JsonDocument.of(root).canonicalText())
    private fun data(value: JsonObject) = jsonObject("ok" to JsonBoolean(true), "data" to value)
    private fun hash(value: String) = Contract.base64url(MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)))
    private fun dpop(request: RecordedRequest, access: String? = null): JsonObject {
        val proof = JWSObject.parse(request.getHeader("DPoP"))
        require(proof.header.type.toString() == "dpop+jwt" && proof.header.algorithm == JWSAlgorithm.ES256)
        require(proof.verify(ECDSAVerifier(proof.header.jwk as ECKey)))
        val claims = JsonDocument.parse(proof.payload.toBytes()).root
        require(claims.string("htm") == request.method && claims.string("htu") == origin + request.requestUrl!!.encodedPath)
        require(seenProofs.add(claims.string("jti")))
        if (access == null) require("ath" !in claims.fields) else require(claims.string("ath") == hash(access))
        return claims
    }
    @Synchronized private fun respond(request: RecordedRequest): MockResponse {
        val path = request.requestUrl!!.encodedPath
        if (path == "/issuer/.well-known/openid-configuration") return response(discovery())
        if (path == "/jwks") return response(jsonObject("keys" to JsonArray(listOf(JsonDocument.parse(issuerKey.toPublicJWK().toJSONString()).root))))
        if (path == "/token") {
            require(request.getHeader("Authorization") == null)
            dpop(request)
            val jkt = JWSObject.parse(request.getHeader("DPoP")).header.jwk.computeThumbprint().toString()
            val form = request.body.readUtf8().split('&').associate { part -> val fields = part.split('=', limit = 2); URLDecoder.decode(fields[0], "UTF-8") to URLDecoder.decode(fields[1], "UTF-8") }
            require(form["client_id"] == config.clientId && form["resource"] == config.resource)
            if (form["grant_type"] == "refresh_token") {
                refreshRequests.incrementAndGet()
                require(form["refresh_token"] == refreshSecret && jkt == proofJkt)
                grantNumber++; refreshSecret = "fixture-refresh-$grantNumber"
                if (holdRefresh) return response(tokenReply(jkt, subject, null, 300)).setBodyDelay(2, java.util.concurrent.TimeUnit.SECONDS)
                val reply = response(tokenReply(jkt, subject, null, 300))
                return if (dropRefreshReply) reply.setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST) else reply
            }
            require(form["grant_type"] == "authorization_code" && form["code"] == "fixture-code" && form["redirect_uri"] == LoginConfiguration.REDIRECT_URI)
            require(hash(form["code_verifier"]!!) == browserChallenge)
            grantNumber++; refreshSecret = "fixture-refresh-$grantNumber"
            return response(tokenReply(jkt, browserSubject, browserNonce, 120))
        }
        if (path == "/v1/realtime") {
            require(request.getHeader("Authorization") == "DSH-Ticket $relayToken" && request.getHeader("Sec-WebSocket-Protocol") == RELAY_SUBPROTOCOL)
            val connectionId = UUID.randomUUID().toString(); val challengeId = UUID.randomUUID().toString(); val nonce = "D".repeat(42) + "A"
            val subscribedScope = relayScope!!
            val proofKey = relayProofKey!!
            val leaseExpires = minOf(relayAccessExpiresAt, System.currentTimeMillis() + 299_000)
            return MockResponse().withWebSocketUpgrade(object : WebSocketListener() {
                private val epoch = "77777777-7777-4777-8777-777777777777"
                private val subscription = UUID.randomUUID().toString()
                private val sync = UUID.randomUUID().toString()
                private fun send(socket: WebSocket, type: String, request: String, payload: JsonObject) {
                    var frame = jsonObject("v" to 1L.json(), "type" to type.json(), "request_id" to request.json(), "runtime_id" to runtimeId.json(), "runtime_epoch" to epoch.json(),
                        "session_id" to sessionId.json(), "subscription_id" to subscription.json(), "payload" to payload)
                    if (type != "session.subscribed") frame = frame.with("sync_id" to sync.json())
                    require(socket.send(JsonDocument.of(frame).canonicalText()))
                }
                private fun user(seq: Long, text: String) = jsonObject("native_seq" to seq.json(), "time" to 1000L.json(), "type" to "user/message".json(), "surface_op" to "append".json(),
                    "data" to jsonObject("content" to JsonArray(listOf(jsonObject("type" to "text".json(), "text" to text.json())))))
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    currentRelay.set(webSocket)
                    webSocket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "challenge".json(), "payload" to jsonObject(
                        "connection_id" to connectionId.json(), "challenge_id" to challengeId.json(), "nonce" to nonce.json(), "role" to "device".json(),
                        "expires_at" to java.time.Instant.ofEpochMilli(System.currentTimeMillis() + 9000).toString().json()))).canonicalText())
                }
                override fun onMessage(webSocket: WebSocket, text: String) {
                    try {
                        val frame = JsonDocument.parse(text).root
                        val payload = frame.obj("payload")
                        when (frame.string("type")) {
                            "ping" -> {
                                webSocket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "pong".json(), "payload" to jsonObject("connection_id" to connectionId.json(), "server_time" to java.time.Instant.now().toString().json()))).canonicalText())
                                return
                            }
                            "session.subscribe" -> {
                                require(frame.string("runtime_id") == runtimeId && frame.string("session_id") == sessionId && sessionId in subscribedScope.sessions)
                                val requestId = frame.string("request_id")
                                if (runtimeOffline) {
                                    webSocket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "error".json(), "request_id" to requestId.json(), "runtime_id" to runtimeId.json(), "session_id" to sessionId.json(), "payload" to jsonObject("code" to "runtime.offline".json()))).canonicalText())
                                    return
                                }
                                send(webSocket, "session.subscribed", requestId, jsonObject())
                                send(webSocket, "session.snapshot", requestId, jsonObject("cursor" to 2L.json(), "has_more" to JsonBoolean(true), "records" to JsonArray(listOf(user(2, "电脑当前消息"))), "assistant" to jsonObject("revision" to 0L.json())))
                                send(webSocket, "session.checkpoint", requestId, jsonObject("state" to "persisted".json(), "through_seq" to 2L.json()))
                                subscriptions.incrementAndGet()
                                return
                            }
                            "session.page" -> {
                                require(frame.string("runtime_epoch") == epoch && frame.string("subscription_id") == subscription && payload.integer("through_seq", -1) == 2L && payload.integer("before_seq") == 2L)
                                send(webSocket, "session.page.result", frame.string("request_id"), jsonObject("records" to JsonArray(listOf(user(0, "最早的消息"), user(1, "更早的消息"))), "has_more" to JsonBoolean(false), "through_seq" to 2L.json()))
                                return
                            }
                            "message.submit", "session.cancel" -> {
                                require(chatMode && frame.string("runtime_id") == runtimeId && frame.string("session_id") == sessionId)
                                val intent = cn.edu.ustc.dsh.command.CommandIntent.parse(frame)
                                require(intent.kind.wire in subscribedScope.actions)
                                commandWrites.incrementAndGet()
                                val state = if (intent.kind == cn.edu.ustc.dsh.command.CommandKind.MESSAGE) "agent_queued" else "settled"
                                val status = jsonObject("request_id" to intent.requestId.json(), "session_id" to sessionId.json(), "state" to state.json(), "payload_sha256" to intent.digest.json(), "updated_at" to java.time.Instant.now().toString().json())
                                commandStatuses[intent.requestId] = status
                                if (dropNextCommandReply) { dropNextCommandReply = false; webSocket.close(1001, "fixture response lost"); return }
                                webSocket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "command.receipt".json(), "request_id" to intent.requestId.json(), "runtime_id" to runtimeId.json(), "runtime_epoch" to epoch.json(), "session_id" to sessionId.json(),
                                    "payload" to JsonObject(status.fields.filterKeys { it in setOf("state", "payload_sha256", "updated_at") }))).canonicalText())
                                return
                            }
                        }
                        require(frame.string("type") == "hello.proof")
                        val proof = JWSObject.parse(payload.string("proof"))
                        require(proof.header.type.toString() == RELAY_PROOF_TYPE && proof.header.jwk == null && proof.verify(ECDSAVerifier(proofKey)))
                        val claims = JsonDocument.parse(proof.payload.toBytes()).root
                        require(claims.string("iss") == deviceId && claims.string("runtime_id") == "55555555-5555-4555-8555-555555555555" && claims.string("aud") == RELAY_PROOF_AUDIENCE)
                        require(claims.string("connection_id") == connectionId && claims.string("challenge_id") == challengeId && claims.string("nonce") == nonce)
                        val capabilities = payload.array("capabilities").map { (it as JsonString).value }
                        require(capabilities.toSet().all { it in setOf("connection.heartbeat.v1", "session.read.v1", "command.relay.v1", "session.cancel.v1") })
                        require(claims.string("hello_sha256") == DeviceHello(deviceId, capabilities).digest())
                        relayProofReceived = true
                        webSocket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "hello.ok".json(), "payload" to jsonObject(
                            "role" to "device".json(), "connection_id" to connectionId.json(), "device_id" to deviceId.json(), "runtime_id" to "55555555-5555-4555-8555-555555555555".json(),
                            "grant_version" to 7L.json(), "scope" to subscribedScope.json(), "protocols" to JsonArray(listOf(1L.json())),
                            "capabilities" to JsonArray(capabilities.map(String::json)), "heartbeat_seconds" to 20L.json(), "max_frame_bytes" to RELAY_FRAME_BYTES.toLong().json(),
                            "server_time" to java.time.Instant.now().toString().json(), "lease_expires_at" to java.time.Instant.ofEpochMilli(leaseExpires).toString().json()))).canonicalText())
                    } catch (_: Exception) { failure.set("native Relay proof validation failed"); webSocket.cancel() }
                }
                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) { relayClosures.incrementAndGet() }
                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) { relayClosures.incrementAndGet() }
            }).setHeader("Sec-WebSocket-Protocol", RELAY_SUBPROTOCOL)
        }
        require(path.startsWith("/v1/"))
        val access = request.getHeader("Authorization")!!.removePrefix("DPoP ")
        val token = JWSObject.parse(access)
        require(token.header.type.toString() == "at+jwt" && token.verify(ECDSAVerifier(issuerKey)))
        val claims = JsonDocument.parse(token.payload.toBytes()).root
        require(claims.string("iss") == issuer && claims.string("client_id") == config.clientId && claims.string("aud") == config.audience)
        val proof = dpop(request, access)
        val requestJkt = JWSObject.parse(request.getHeader("DPoP")).header.jwk.computeThumbprint().toString()
        require(claims.obj("cnf").string("jkt") == requestJkt)
        val supplied = (proof.fields["nonce"] as? JsonString)?.value
        val nonce = UUID.randomUUID().toString()
        val acceptedNonce = supplied != null && resourceNonces.remove(supplied)
        resourceNonces += nonce
        if (!acceptedNonce) return response(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "auth.proof_invalid".json())), 401)
            .setHeader("DPoP-Nonce", nonce).setHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"")
        fun resourceResponse(root: JsonObject, status: Int = 200) = response(root, status).setHeader("DPoP-Nonce", nonce)
        if (path == "/v1/me") {
            meRequests.incrementAndGet()
            return resourceResponse(data(jsonObject("issuer" to issuer.json(), "subject" to claims.string("sub").json(), "client_id" to config.clientId.json(),
                "scopes" to JsonArray(listOf("remote.access".json())), "user_id" to serviceUserId.json(),
                "memberships" to JsonArray(if (member) listOf(jsonObject("organization_id" to organizationId.json(), "role" to "member".json())) else emptyList()))))
        }
        if (path == "/v1/devices") {
            val body = JsonDocument.parse(request.body.readByteArray()).root
            val approval = ECKey.parse(JsonDocument.of(body.obj("approval_public_jwk")).canonicalText())
            val possession = JWSObject.parse(body.string("approval_proof"))
            require(possession.header.type.toString() == "dsh-device-registration-proof+jwt" && possession.verify(ECDSAVerifier(approval)))
            val binding = JsonDocument.parse(possession.payload.toBytes()).root
            require(binding.string("dpop_jti") == proof.string("jti") && binding.string("proof_key_jkt") == requestJkt && binding.string("approval_key_jkt") == approval.computeThumbprint().toString())
            require(binding.string("device_name_sha256") == hash(body.string("name")) && binding.string("iss") == issuer && binding.string("sub") == subject)
            proofJkt = requestJkt; approvalJkt = approval.computeThumbprint().toString(); active = true
            registrationRequests.incrementAndGet()
            val reply = resourceResponse(data(jsonObject("device_id" to deviceId.json(), "key_version" to 1L.json())), 201)
            return if (dropRegistrationReply) reply.setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST) else reply
        }
        if (path == "/v1/devices/current") {
            val value = if (!active || requestJkt != proofJkt) jsonObject("state" to "unregistered".json()) else jsonObject("state" to (if (revoked) "revoked" else "active").json(), "device" to jsonObject(
                "device_id" to deviceId.json(), "key_version" to 1L.json(), "approval_key_jkt" to approvalJkt!!.json(), "proof_key_jkt" to proofJkt!!.json()))
            return resourceResponse(data(value))
        }
        if (!active || revoked || requestJkt != proofJkt) return resourceResponse(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "access.denied".json())), 403)
        if (path.startsWith("/v1/commands/")) {
            require(chatMode && request.requestUrl!!.queryParameter("device_id") == deviceId)
            val status = commandStatuses[path.substringAfterLast('/')]
            return if (status != null) resourceResponse(data(status)) else resourceResponse(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "access.denied".json())), 403)
        }
        if (bindingMode && path.startsWith("/v1/enrollments/")) {
            require(path.startsWith("/v1/enrollments/$bindingId"))
            fun denied() = resourceResponse(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "access.denied".json())), 403)
            if (!member) return denied()
            when (path) {
                "/v1/enrollments/$bindingId/preview" -> {
                    val body = JsonDocument.parse(request.body.readByteArray()).root; body.exactKeys("code")
                    if (body.string("code") != bindingCode || System.currentTimeMillis() >= bindingExpiresAt) return denied()
                    bindingPreviews.incrementAndGet()
                    val result = resourceResponse(data(bindingDetails()))
                    return if (holdBindingPreview) result.setHeadersDelay(2, java.util.concurrent.TimeUnit.SECONDS) else result
                }
                "/v1/enrollments/$bindingId/confirm" -> {
                    val body = JsonDocument.parse(request.body.readByteArray()).root; body.exactKeys("code")
                    if (body.string("code") != bindingCode || bindingConfirmedElsewhere || System.currentTimeMillis() >= bindingExpiresAt) return denied()
                    bindingWrites.incrementAndGet(); bindingUserConfirmed = true
                    val fields = bindingDetails().fields.filterKeys { it in setOf("enrollment_id", "host_id", "runtime_id", "state", "expires_at", "host_confirmed", "user_confirmed") }
                    val result = resourceResponse(data(JsonObject(fields)))
                    return if (dropBindingReply) result.setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST) else result
                }
                "/v1/enrollments/$bindingId" -> {
                    bindingStatusReads.incrementAndGet()
                    if (!bindingUserConfirmed || bindingConfirmedElsewhere) return denied()
                    return resourceResponse(data(bindingDetails()))
                }
                else -> error("unsupported binding fixture operation")
            }
        }
        if (path == "/v1/realtime/tickets") {
            if (!allowSessionRead) return resourceResponse(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "access.denied".json())), 403)
            val body = JsonDocument.parse(request.body.readByteArray()).root
            require(body.string("runtime_id") == "55555555-5555-4555-8555-555555555555")
            relayScope = RelayScope.parse(body.obj("scope"))
            require("session.read" in relayScope!!.actions && relayScope!!.actions.all { it in setOf("session.read", "message.submit", "session.cancel", "command.status") })
            relayProofKey = JWSObject.parse(request.getHeader("DPoP")).header.jwk as ECKey
            relayAccessExpiresAt = claims.integer("exp") * 1000
            ticketRequests.incrementAndGet()
            return resourceResponse(data(jsonObject("ticket" to relayToken.json(), "runtime_id" to body.string("runtime_id").json(), "grant_version" to 7L.json(), "scope" to relayScope!!.json(),
                "expires_at" to java.time.Instant.ofEpochMilli(System.currentTimeMillis() + 30_000).toString().json())), 201)
        }
        if (path == "/v1/runtimes/$runtimeId/sessions") {
            sessionRequests.incrementAndGet()
            val result = resourceResponse(data(jsonObject("items" to JsonArray(listOf(jsonObject("session_id" to sessionId.json(), "workspace_id" to JsonNull, "state" to "available".json(), "last_persisted_seq" to 2L.json(), "updated_at" to java.time.Instant.now().toString().json()))))))
            return if (holdSessions) result.setHeadersDelay(2, java.util.concurrent.TimeUnit.SECONDS) else result
        }
        if (path == "/v1/hosts") {
            hostRequests.incrementAndGet()
            return resourceResponse(data(jsonObject("items" to JsonArray(listOf(jsonObject("id" to "44444444-4444-4444-8444-444444444444".json(), "alias" to "夹具电脑".json(), "state" to "active".json()))))))
        }
        require(path == "/v1/runtimes")
        if (bindingMode && (!bindingApproved || bindingConfirmedElsewhere)) return resourceResponse(data(jsonObject("items" to JsonArray(emptyList()))))
        return resourceResponse(data(jsonObject("items" to JsonArray(listOf(jsonObject("id" to runtimeId.json(), "host_id" to "44444444-4444-4444-8444-444444444444".json(), "organization_id" to organizationId.json(), "protocol_version" to 1L.json(), "dsh_version" to "0.2.1-rc.2".json(),
            "access" to jsonObject("role" to (if (bindingMode) "owner" else if (chatMode) "operator" else "viewer").json(), "grant_version" to (if (allowSessionRead) 7L else 8L).json(), "scope" to directoryScope.json())))))))
    }

    fun bindingDetails(): JsonObject = jsonObject("enrollment_id" to bindingId.json(), "request_id" to "99999999-9999-4999-8999-999999999999".json(), "organization_id" to organizationId.json(),
        "organization_name" to "学校夹具".json(), "host_id" to "44444444-4444-4444-8444-444444444444".json(), "host_alias" to "夹具电脑".json(),
        "installation_id" to "77777777-7777-4777-8777-777777777777".json(), "installation_key_jkt" to installationKey.computeThumbprint().toString().json(), "runtime_id" to runtimeId.json(),
        "profile_ref" to bindingProfile.json(), "protocol_version" to 1L.json(), "dsh_version" to "0.2.1-rc.2".json(),
        "state" to (if (bindingApproved) "approved" else if (System.currentTimeMillis() >= bindingExpiresAt) "expired" else if (bindingUserConfirmed) "user_confirmed" else "pending").json(),
        "expires_at" to java.time.Instant.ofEpochMilli(bindingExpiresAt).toString().json(), "host_confirmed" to JsonBoolean(bindingHostConfirmed), "user_confirmed" to JsonBoolean(bindingUserConfirmed),
        "user_confirmed_by_me" to JsonBoolean(bindingUserConfirmed && !bindingConfirmedElsewhere), "workspaces" to JsonArray(listOf(jsonObject("reference" to "project".json(), "workspace_id" to sessionId.json()))))

    fun revokeSession() {
        allowSessionRead = false
        require(currentRelay.get()!!.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "access.revoked".json(), "payload" to jsonObject("code" to "access.revoked".json()))).canonicalText()))
    }

    fun seed(registering: Boolean = false, refreshing: Boolean = false) {
        val now = System.currentTimeMillis()
        val ledger = PendingKeyLedger(context, ledgerName); ledger.add(reference)
        DeviceKeyStore(context).use { owner ->
            val proof = owner.create(reference.scope(), DeviceKeyPurpose.PROOF, 1)
            val approval = owner.create(reference.scope(), DeviceKeyPurpose.APPROVAL, 1)
            proofJkt = proof.thumbprint; approvalJkt = approval.thumbprint; active = true
            val attempt = PendingLogin(OidcDiscovery.parse(JsonDocument.of(discovery()).canonicalBytes(), config), proof.thumbprint, now)
            val exchange = attempt.acceptCallback(LoginConfiguration.REDIRECT_URI + "?state=${attempt.state}&code=seed", now)
            val session = TokenVerifier.authorizationCodeResponse(JsonDocument.of(tokenReply(proof.thumbprint, subject, attempt.nonce, 120)).canonicalBytes(), exchange, IssuerKeys.parse(JsonDocument.of(jsonObject("keys" to JsonArray(listOf(JsonDocument.parse(issuerKey.toPublicJWK().toJSONString()).root)))).canonicalBytes()), System.currentTimeMillis())
            var saved = AccountCheckpoint.create(accountId, config, userId, session, System.currentTimeMillis()).withApprovalKey(approval.thumbprint, System.currentTimeMillis()).beginEnrollment("校园夹具手机", System.currentTimeMillis())
            if (!registering) saved = saved.deviceAccepted(deviceId, 1, System.currentTimeMillis())
            if (refreshing) saved = saved.beginRefresh(System.currentTimeMillis())
            vault.save(accountId, organizationId, config.fingerprint, saved.authenticatedStorageBytes(), 0)
        }
    }
    fun checkpoint(): AccountCheckpoint? = vault.read()?.use { opened ->
        DeviceKeyStore(context).use { owner ->
            val key = owner.load(DeviceKeyScope(opened.accountId, opened.organizationId), DeviceKeyPurpose.PROOF, 1)
            AccountCheckpoint.parseAuthenticated(opened.bytes(), config, key.thumbprint, System.currentTimeMillis(), opened.accountId)
        }
    }
    fun orphanProof(): ScopeReference {
        val abandoned = ScopeReference(UUID.randomUUID().toString(), organizationId)
        PendingKeyLedger(context, ledgerName).add(abandoned)
        DeviceKeyStore(context).use { it.create(abandoned.scope(), DeviceKeyPurpose.PROOF, 1) }
        return abandoned
    }
    fun readApi(proof: DeviceKeyHandle): RemoteApi {
        val now = System.currentTimeMillis()
        proofJkt = proof.thumbprint; relayProofKey = ECKey.parse(JsonDocument.of(proof.publicJwk).canonicalText()); active = true
        val login = PendingLogin(OidcDiscovery.parse(JsonDocument.of(discovery()).canonicalBytes(), config), proof.thumbprint, now)
        val exchange = login.acceptCallback(LoginConfiguration.REDIRECT_URI + "?state=${login.state}&code=network-fixture", now)
        val keys = IssuerKeys.parse(JsonDocument.of(jsonObject("keys" to JsonArray(listOf(JsonDocument.parse(issuerKey.toPublicJWK().toJSONString()).root)))).canonicalBytes())
        val verified = TokenVerifier.authorizationCodeResponse(JsonDocument.of(tokenReply(proof.thumbprint, subject, login.nonce, 300)).canonicalBytes(), exchange, keys, System.currentTimeMillis())
        return http.resource(config, verified, proof.proofSigner())
    }
    override fun close() {
        currentRelay.getAndSet(null)?.close(1001, "fixture complete")
        transport.dispatcher.cancelAll(); transport.connectionPool.evictAll(); transport.dispatcher.executorService.shutdownNow()
        vault.clear(); PendingKeyLedger(context, ledgerName).recover(); server.shutdown()
    }
}
