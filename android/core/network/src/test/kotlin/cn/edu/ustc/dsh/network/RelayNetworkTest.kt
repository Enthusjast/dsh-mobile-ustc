package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.auth.*
import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.protocol.*
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import kotlinx.coroutines.*
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
    private suspend fun ticket(nonceChallenge: Boolean = false): RealtimeReadTicket {
        if (nonceChallenge) server.enqueue(json(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "auth.proof_invalid".json()))).setResponseCode(401)
            .setHeader("DPoP-Nonce", "fresh-resource-ticket-nonce").setHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\""))
        server.enqueue(json(jsonObject("ok" to JsonBoolean(true), "data" to jsonObject("ticket" to token.json(), "runtime_id" to runtime.json(), "grant_version" to 7L.json(), "scope" to scope.json(), "expires_at" to time(30_000)))))
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
    private fun peer(challenge: JsonObject = challenge(), accepted: JsonObject = helloOk(), protocol: String = RELAY_SUBPROTOCOL): MockResponse = MockResponse().withWebSocketUpgrade(object : WebSocketListener() {
        override fun onOpen(socket: WebSocket, response: Response) { socket.send(JsonDocument.of(challenge).canonicalText()) }
        override fun onMessage(socket: WebSocket, text: String) {
            try {
                val frame = JsonDocument.parse(text).root
                if (frame.string("type") == "ping") {
                    socket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "pong".json(), "payload" to jsonObject("connection_id" to connection.json(), "server_time" to time(0)))).canonicalText())
                    return
                }
                val hello = frame.obj("payload")
                assertEquals(device, hello.string("device_id"))
                val proof = JWSObject.parse(hello.string("proof")); assertTrue(proof.verify(ECDSAVerifier(key)))
                assertEquals(RELAY_PROOF_TYPE, proof.header.type.toString()); assertNull(proof.header.jwk)
                val claims = JsonDocument.parse(proof.payload.toBytes()).root
                assertEquals(connection, claims.string("connection_id")); assertEquals(challengeId, claims.string("challenge_id")); assertEquals(runtime, claims.string("runtime_id"))
                assertEquals(device, claims.string("iss")); assertEquals(RELAY_PROOF_AUDIENCE, claims.string("aud"))
                assertEquals(DeviceHello(device, listOf("connection.heartbeat.v1", "session.read.v1")).digest(), claims.string("hello_sha256"))
                socket.send(JsonDocument.of(accepted).canonicalText())
            } catch (error: Throwable) { peerFailure.set(error); socket.cancel() }
        }
    }).setHeader("Sec-WebSocket-Protocol", protocol)

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
