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
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.*
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.net.URLEncoder

class LoginHttpTest {
    private val server = MockWebServer()
    private val certificate = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
    private val serverCertificates = HandshakeCertificates.Builder().heldCertificate(certificate).build()
    private val clientCertificates = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
    private val http: LoginHttp
    private val issuerKey = ECKeyGenerator(Curve.P_256).keyID("test-issuer").generate()
    private val proofKey = ECKeyGenerator(Curve.P_256).generate()
    private val signer = object : DeviceProofSigner {
        override val publicKey = PublicProofKey(JsonDocument.parse(proofKey.toPublicJWK().toJSONString()).root)
        override fun signJose(signingInput: ByteArray): ByteArray = ECDSASigner(proofKey).sign(JWSHeader(JWSAlgorithm.ES256), signingInput).decode()
    }
    init {
        server.useHttps(serverCertificates.sslSocketFactory(), false); server.start()
        http = LoginHttp.forTests(OkHttpClient.Builder().sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager).build())
    }
    @After fun clean() { server.shutdown() }
    private val origin: String get() = server.url("/").toString().trimEnd('/')
    private fun config() = LoginConfiguration.parse(JsonDocument.of(jsonObject(
        "issuer" to "$origin/issuer".json(), "client_id" to "mobile".json(), "redirect_uri" to LoginConfiguration.REDIRECT_URI.json(),
        "resource" to "urn:dsh-remote".json(), "audience" to "urn:dsh-remote".json(), "remote_origin" to origin.json(),
        "organization_id" to "11111111-1111-4111-8111-111111111111".json(), "scopes" to JsonArray(listOf("openid".json(), "remote.access".json())),
        "endpoint_origins" to JsonArray(listOf(origin.json())), "signing_algorithms" to JsonArray(listOf("ES256".json())),
    )).canonicalBytes())
    private fun response(body: String, status: Int = 200) = MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json").setBody(body)
    private fun discovery(): String = JsonDocument.of(jsonObject(
        "issuer" to "$origin/issuer".json(), "authorization_endpoint" to "$origin/authorize".json(), "token_endpoint" to "$origin/token?tenant=school".json(),
        "jwks_uri" to "$origin/jwks".json(), "response_types_supported" to JsonArray(listOf("code".json())), "id_token_signing_alg_values_supported" to JsonArray(listOf("ES256".json())),
    )).canonicalText()
    private fun me(config: LoginConfiguration, userId: String = "22222222-2222-4222-8222-222222222222", memberships: List<JsonValue> = listOf(jsonObject("organization_id" to config.organizationId.json(), "role" to "member".json()))): String = JsonDocument.of(jsonObject(
        "ok" to JsonBoolean(true), "data" to jsonObject("issuer" to config.issuer.json(), "subject" to "school-user".json(), "client_id" to config.clientId.json(),
            "scopes" to JsonArray(listOf("remote.access".json())), "user_id" to userId.json(), "memberships" to JsonArray(memberships)),
    )).canonicalText()
    private fun jwt(claims: JsonObject, type: String): String {
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).keyID(issuerKey.keyID).type(JOSEObjectType(type)).build()
        return JWSObject(header, Payload(JsonDocument.of(claims).canonicalText())).apply { sign(ECDSASigner(issuerKey)) }.serialize()
    }

    @Test fun realHttpsExchangesPkceAndKeepsResourceAndIssuerNonceScopesSeparate(): Unit = runBlocking {
        val config = config()
        server.enqueue(response(discovery()))
        val discovery = http.discovery(config)
        assertEquals("/issuer/.well-known/openid-configuration", server.takeRequest().path)
        val login = PendingLogin(discovery, signer.publicKey.thumbprint, System.currentTimeMillis())
        val exchange = login.acceptCallback(LoginConfiguration.REDIRECT_URI + "?state=${login.state}&code=opaque-code", System.currentTimeMillis())
        val now = System.currentTimeMillis() / 1000
        val base = jsonObject("iss" to config.issuer.json(), "sub" to "school-user".json(), "iat" to now.json(), "exp" to (now + 300).json())
        val access = jwt(base.with("aud" to config.audience.json(), "client_id" to config.clientId.json(), "jti" to "access-id".json(),
            "scope" to "remote.access".json(), "cnf" to jsonObject("jkt" to signer.publicKey.thumbprint.json())), "at+jwt")
        val id = jwt(base.with("aud" to config.clientId.json(), "nonce" to login.nonce.json()), "JWT")
        server.enqueue(response("{\"error\":\"use_dpop_nonce\"}", 400).setHeader("DPoP-Nonce", "issuer-nonce"))
        server.enqueue(response(JsonDocument.of(jsonObject("access_token" to access.json(), "id_token" to id.json(), "token_type" to "DPoP".json(), "expires_in" to 300L.json())).canonicalText()))
        val raw = http.tokenEndpoint(discovery, signer).exchange(exchange)
        val first = server.takeRequest(); val second = server.takeRequest()
        fun claims(request: RecordedRequest): JsonObject {
            val signed = JWSObject.parse(request.getHeader("DPoP"))
            assertTrue(signed.verify(ECDSAVerifier(proofKey)))
            assertEquals(signer.publicKey.thumbprint, signed.header.jwk.computeThumbprint().toString())
            return JsonDocument.parse(signed.payload.toBytes()).root
        }
        val initial = claims(first); val retried = claims(second)
        assertEquals("$origin/token", initial.string("htu"))
        assertFalse("ath" in initial.fields); assertFalse("nonce" in initial.fields)
        assertNotEquals(initial.string("jti"), retried.string("jti"))
        assertEquals("issuer-nonce", retried.string("nonce"))
        assertNull(first.getHeader("Authorization"))
        val form = second.body.readUtf8()
        assertTrue(form.contains("code_verifier=" + URLEncoder.encode(exchange.form()["code_verifier"], "UTF-8")))
        server.enqueue(response(JsonDocument.of(jsonObject("keys" to JsonArray(listOf(JsonDocument.parse(issuerKey.toPublicJWK().toJSONString()).root)))).canonicalText()))
        val keys = http.keys(discovery); server.takeRequest()
        val session = TokenVerifier.authorizationCodeResponse(raw, exchange, keys, System.currentTimeMillis())
        val api = http.resource(config, session, signer)
        server.enqueue(response("{\"ok\":false,\"error\":{\"code\":\"auth.proof_invalid\"}}", 401).setHeader("DPoP-Nonce", "resource-one").setHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\""))
        server.enqueue(response(me(config)).setHeader("DPoP-Nonce", "resource-two"))
        assertEquals("22222222-2222-4222-8222-222222222222", api.me().userId)
        val resourceFirst = server.takeRequest(); val resourceSecond = server.takeRequest()
        assertFalse("nonce" in claims(resourceFirst).fields)
        assertEquals("resource-one", claims(resourceSecond).string("nonce"))
        assertEquals(Contract.base64url(java.security.MessageDigest.getInstance("SHA-256").digest(access.toByteArray())), claims(resourceSecond).string("ath"))
        assertEquals("DPoP $access", resourceSecond.getHeader("Authorization"))
        server.enqueue(response("{\"ok\":true,\"data\":[]}"))
        api.runtimes()
        assertEquals("resource-two", claims(server.takeRequest()).string("nonce"))
        server.enqueue(response(me(config)).setHeader("DPoP-Nonce", "registration-nonce"))
        val approvalKey = ECKeyGenerator(Curve.P_256).generate()
        val approvalPublic = PublicProofKey(JsonDocument.parse(approvalKey.toPublicJWK().toJSONString()).root)
        val registration = api.prepareRegistration(approvalPublic, "校园手机")
        server.takeRequest()
        val der = java.security.Signature.getInstance("SHA256withECDSA").run {
            initSign(approvalKey.toECPrivateKey()); update(registration.signatureRequest.signingInput()); sign()
        }
        val signed = registration.signatureRequest.finishDerSignature(der, System.currentTimeMillis())
        server.enqueue(response("{\"ok\":true,\"data\":{\"device_id\":\"22222222-2222-4222-8222-222222222222\",\"key_version\":1}}", 201))
        assertEquals(1L, registration.submit(signed).keyVersion)
        val registrationHttp = server.takeRequest()
        assertEquals("/v1/devices", registrationHttp.path)
        val registrationDpop = claims(registrationHttp)
        assertEquals("registration-nonce", registrationDpop.string("nonce"))
        val body = JsonDocument.parse(registrationHttp.body.readByteArray()).root
        val possession = JWSObject.parse(body.string("approval_proof"))
        assertTrue(possession.verify(ECDSAVerifier(approvalKey)))
        val possessionClaims = JsonDocument.parse(possession.payload.toBytes()).root
        assertEquals(registrationDpop.string("jti"), possessionClaims.string("dpop_jti"))
        assertEquals(approvalPublic.thumbprint, possessionClaims.string("approval_key_jkt"))
        assertEquals(signer.publicKey.thumbprint, possessionClaims.string("proof_key_jkt"))
        assertEquals("校园手机", body.string("name"))
        assertThrows(RemoteRequestException::class.java) { runBlocking { registration.submit(signed) } }
        fun current(state: String, approvalJkt: String = approvalPublic.thumbprint, version: Long = 1): String =
            JsonDocument.of(jsonObject("ok" to JsonBoolean(true), "data" to jsonObject("state" to state.json(), "device" to jsonObject(
                "device_id" to "22222222-2222-4222-8222-222222222222".json(), "key_version" to version.json(),
                "approval_key_jkt" to approvalJkt.json(), "proof_key_jkt" to signer.publicKey.thumbprint.json(),
            )))).canonicalText()
        server.enqueue(response(me(config)))
        val uncertain = api.prepareRegistration(approvalPublic, "校园手机")
        server.takeRequest()
        val uncertainDer = java.security.Signature.getInstance("SHA256withECDSA").run {
            initSign(approvalKey.toECPrivateKey()); update(uncertain.signatureRequest.signingInput()); sign()
        }
        val uncertainProof = uncertain.signatureRequest.finishDerSignature(uncertainDer, System.currentTimeMillis())
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST))
        val beforeWrite = server.requestCount
        assertThrows(RemoteRequestException::class.java) { runBlocking { uncertain.submit(uncertainProof) } }
        assertEquals(beforeWrite + 1, server.requestCount)
        assertEquals("POST", server.takeRequest().method)
        server.enqueue(response(me(config))); server.enqueue(response(current("active")))
        assertEquals("22222222-2222-4222-8222-222222222222", api.currentDevice(approvalPublic)!!.deviceId)
        assertEquals("/v1/me", server.takeRequest().path)
        val reconciliation = server.takeRequest()
        assertEquals("GET", reconciliation.method); assertEquals("/v1/devices/current", reconciliation.path)
        server.enqueue(response(me(config))); server.enqueue(response("{\"ok\":true,\"data\":{\"state\":\"unregistered\"}}"))
        assertNull(api.currentDevice(approvalPublic)); server.takeRequest(); server.takeRequest()
        for ((body, code) in listOf(current("revoked") to "device.invalid", current("active", version = 2) to "device.invalid", current("active", approvalJkt = signer.publicKey.thumbprint) to "auth.identity_mismatch")) {
            server.enqueue(response(me(config))); server.enqueue(response(body))
            assertEquals(code, assertThrows(RemoteRequestException::class.java) { runBlocking { api.currentDevice(approvalPublic) } }.code)
            server.takeRequest(); server.takeRequest()
        }
        server.enqueue(response(me(config, userId = "33333333-3333-4333-8333-333333333333")))
        assertEquals("auth.identity_mismatch", assertThrows(RemoteRequestException::class.java) { runBlocking { api.me() } }.code)
        server.takeRequest()
        server.enqueue(response(me(config, memberships = emptyList())))
        val requestsBefore = server.requestCount
        assertEquals("access.organization_missing", assertThrows(RemoteRequestException::class.java) { runBlocking { api.prepareRegistration(approvalPublic, "校园手机") } }.code)
        server.takeRequest()
        assertEquals(requestsBefore + 1, server.requestCount) // Only GET /me, no enrollment write.
    }

    @Test fun redirectsOversizedBodiesAndCancellationCannotDiscloseCredentialsOrHangCalls(): Unit = runBlocking {
        server.enqueue(response("{}", 302).setHeader("Location", "https://other.example.edu/stolen"))
        assertThrows(RemoteRequestException::class.java) { runBlocking { http.discovery(config()) } }
        assertEquals(1, server.requestCount)
        server.enqueue(response("a".repeat(JsonDocument.MAX_BYTES + 1)))
        assertThrows(RemoteRequestException::class.java) { runBlocking { http.discovery(config()) } }
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
        assertThrows(TimeoutCancellationException::class.java) { runBlocking { withTimeout(300) { http.discovery(config()) } } }
    }
}
