package cn.edu.ustc.dsh.mobile

import android.content.Context
import cn.edu.ustc.dsh.auth.*
import cn.edu.ustc.dsh.crypto.PublicProofKey
import cn.edu.ustc.dsh.keystore.*
import cn.edu.ustc.dsh.network.LoginHttp
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
    val subject = "school-fixture-user"
    private val server = MockWebServer()
    private val issuerKey = ECKeyGenerator(Curve.P_256).keyID("local-account-issuer").generate()
    private val certificate = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
    private val serverCertificates = HandshakeCertificates.Builder().heldCertificate(certificate).build()
    private val clientCertificates = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
    val failure = AtomicReference<String?>()
    val refreshRequests = AtomicInteger()
    val registrationRequests = AtomicInteger()
    val meRequests = AtomicInteger()
    val hostRequests = AtomicInteger()
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
    val origin: String get() = server.url("/").toString().trimEnd('/')
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
        val client = OkHttpClient.Builder().sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager)
            .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false).cookieJar(CookieJar.NO_COOKIES)
            .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS).readTimeout(5, java.util.concurrent.TimeUnit.SECONDS).callTimeout(10, java.util.concurrent.TimeUnit.SECONDS).build()
        // The production factory still trusts system TLS only. Reflection is confined to this test APK.
        http = LoginHttp::class.java.getDeclaredConstructor(OkHttpClient::class.java).apply { isAccessible = true }.newInstance(client)
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
        if (path == "/v1/hosts") {
            hostRequests.incrementAndGet()
            return resourceResponse(data(jsonObject("items" to JsonArray(listOf(jsonObject("id" to "44444444-4444-4444-8444-444444444444".json(), "alias" to "夹具电脑".json(), "state" to "active".json()))))))
        }
        require(path == "/v1/runtimes")
        return resourceResponse(data(jsonObject("items" to JsonArray(listOf(jsonObject("id" to "55555555-5555-4555-8555-555555555555".json(), "host_id" to "44444444-4444-4444-8444-444444444444".json(), "dsh_version" to "0.2.1-rc.2".json()))))))
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
    override fun close() { vault.clear(); PendingKeyLedger(context, ledgerName).recover(); server.shutdown() }
}
