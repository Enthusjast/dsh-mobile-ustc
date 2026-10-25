package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.auth.*
import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okhttp3.*
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.URI
import java.net.InetSocketAddress
import java.net.Socket
import java.net.Proxy
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import javax.net.ssl.SSLSocket

class RemoteRequestException(val code: String = "network.unavailable") : IllegalStateException(code)

/** No redirects, implicit retries, cookies, logging interceptor or disk response cache. */
class LoginHttp private constructor(private val client: OkHttpClient) {
    companion object {
        fun create(): LoginHttp = LoginHttp(secure(OkHttpClient.Builder()).build())
        internal fun forTests(client: OkHttpClient): LoginHttp = LoginHttp(secure(client.newBuilder()).build())
        private fun secure(builder: OkHttpClient.Builder): OkHttpClient.Builder = builder
            .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false).cache(null)
            .cookieJar(CookieJar.NO_COOKIES).authenticator(Authenticator.NONE).proxyAuthenticator(Authenticator.NONE)
            .connectTimeout(10, TimeUnit.SECONDS).readTimeout(15, TimeUnit.SECONDS).callTimeout(20, TimeUnit.SECONDS)
    }

    suspend fun discovery(config: LoginConfiguration): OidcDiscovery {
        val url = config.issuer.trimEnd('/') + "/.well-known/openid-configuration"
        return OidcDiscovery.parse(get(url), config)
    }
    suspend fun keys(discovery: OidcDiscovery): IssuerKeys = IssuerKeys.parse(get(discovery.jwksUri))
    fun tokenEndpoint(discovery: OidcDiscovery, signer: DeviceProofSigner): TokenEndpoint = TokenEndpoint(this, discovery, signer)
    fun resource(config: LoginConfiguration, session: LoginSession, signer: DeviceProofSigner): RemoteApi {
        if (session.issuer != config.issuer || session.clientId != config.clientId || session.deploymentFingerprint != config.fingerprint || session.proofKeyThumbprint != signer.publicKey.thumbprint) throw RemoteRequestException("auth.identity_mismatch")
        return RemoteApi(this, config, session, signer)
    }

    internal suspend fun relaySocket(uri: URI, ticket: String): BoundedWebSocket = suspendCancellableCoroutine { continuation ->
        val raw = Socket()
        val secured = java.util.concurrent.atomic.AtomicReference<SSLSocket?>()
        fun closeNetwork() { runCatching { raw.close() }; runCatching { secured.get()?.close() } }
        val task = CoroutineScope(Dispatchers.IO).launch(start = CoroutineStart.LAZY) {
            var link: BoundedWebSocket? = null
            try {
                if (uri.scheme != "wss" || uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null || uri.path != "/v1/realtime") throw RelayException("network.insecure_endpoint")
                val proxies = client.proxy?.let { listOf(it) } ?: client.proxySelector.select(URI("https://${uri.rawAuthority}${uri.path}"))
                if (proxies.isEmpty() || proxies.first().type() != Proxy.Type.DIRECT) throw RelayException("network.proxy_unsupported")
                raw.connect(InetSocketAddress(uri.host, if (uri.port < 0) 443 else uri.port), 10_000)
                raw.tcpNoDelay = true
                val tls = client.sslSocketFactory.createSocket(raw, uri.host, if (uri.port < 0) 443 else uri.port, true) as SSLSocket
                secured.set(tls)
                if (!continuation.isActive) throw CancellationException()
                tls.soTimeout = 10_000
                val spec = client.connectionSpecs.firstOrNull { it.isTls } ?: throw RelayException("network.tls_rejected")
                val versions = spec.tlsVersions?.map { it.javaName } ?: tls.enabledProtocols.toList()
                tls.enabledProtocols = tls.supportedProtocols.filter { it in versions && (it == "TLSv1.2" || it == "TLSv1.3") }.toTypedArray()
                spec.cipherSuites?.let { suites ->
                    val names = suites.map { it.javaName.removePrefix("SSL_").removePrefix("TLS_") }.toSet()
                    tls.enabledCipherSuites = tls.enabledCipherSuites.filter { it.removePrefix("SSL_").removePrefix("TLS_") in names }.toTypedArray()
                }
                tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                tls.startHandshake()
                if (!client.hostnameVerifier.verify(uri.host, tls.session)) throw RelayException("network.tls_rejected")
                client.certificatePinner.check(uri.host, tls.session.peerCertificates.toList())
                tls.soTimeout = 45_000
                if (!continuation.isActive) throw CancellationException()
                link = BoundedWebSocket(uri, ticket, tls, ::closeNetwork)
                continuation.resume(link, onCancellation = { _, value, _ -> value.close() })
            } catch (error: Exception) {
                link?.close(); closeNetwork()
                if (continuation.isActive) continuation.resumeWithException(if (error is RelayException) error else RelayException("network.tls_or_connection_failed"))
            }
        }
        continuation.invokeOnCancellation { task.cancel(); closeNetwork() }
        task.start()
    }

    private suspend fun get(url: String): ByteArray = checked(execute(Request.Builder().url(url).header("Accept", "application/json").header("Cache-Control", "no-store").build())).bytes

    internal suspend fun execute(request: Request): HttpReply {
        if (request.url.scheme != "https" || request.url.username.isNotEmpty() || request.url.password.isNotEmpty()) throw RemoteRequestException("network.insecure_endpoint")
        return suspendCancellableCoroutine { continuation ->
            val call = client.newCall(request)
            continuation.invokeOnCancellation { call.cancel() }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    if (continuation.isActive) continuation.resumeWithException(RemoteRequestException())
                }
                override fun onResponse(call: Call, response: Response) {
                    try {
                        val reply = response.use {
                            val body = it.body ?: throw RemoteRequestException("network.invalid_response")
                            if (body.contentLength() > JsonDocument.MAX_BYTES) throw RemoteRequestException("network.response_too_large")
                            val source = body.source()
                            source.request(JsonDocument.MAX_BYTES.toLong() + 1)
                            if (source.buffer.size > JsonDocument.MAX_BYTES) throw RemoteRequestException("network.response_too_large")
                            val type = body.contentType()
                            if (type?.type != "application" || (type.subtype != "json" && !type.subtype.endsWith("+json")) || type.charset(Charsets.UTF_8) != Charsets.UTF_8) throw RemoteRequestException("network.invalid_response")
                            HttpReply(it.code, it.headers, source.buffer.readByteArray())
                        }
                        if (continuation.isActive) continuation.resume(reply)
                    } catch (error: Exception) {
                        if (continuation.isActive) continuation.resumeWithException(if (error is RemoteRequestException) error else RemoteRequestException("network.invalid_response"))
                    }
                }
            })
        }
    }

    internal fun checked(reply: HttpReply): HttpReply {
        if (reply.status !in 200..299) {
            val code = runCatching { JsonDocument.parse(reply.bytes).root.obj("error").string("code") }.getOrNull()
            // Only protocol codes reach presentation; untrusted error bodies/messages do not.
            throw RemoteRequestException(if (code in setOf("auth.expired", "auth.proof_invalid", "access.denied", "access.revoked", "device.invalid", "device.registration_conflict", "internal")) code!! else "network.request_failed")
        }
        return reply
    }
}

internal class HttpReply(val status: Int, val headers: Headers, val bytes: ByteArray) {
    fun nonce(): String? {
        val nonces = headers.values("DPoP-Nonce")
        if (nonces.size > 1) throw RemoteRequestException("auth.proof_invalid")
        return nonces.singleOrNull()?.let { DeviceProofs.nonce(it) }
    }
}

class TokenEndpoint internal constructor(private val http: LoginHttp, private val discovery: OidcDiscovery, private val signer: DeviceProofSigner) {
    private var nonce: String? = null
    private val mutex = Mutex()
    suspend fun exchange(exchange: CodeExchange, now: () -> Long = System::currentTimeMillis): ByteArray = mutex.withLock {
        if (exchange.login.discovery !== discovery || exchange.login.proofKeyThumbprint != signer.publicKey.thumbprint) throw RemoteRequestException("auth.identity_mismatch")
        request(exchange.form(), now)
    }

    suspend fun refresh(previous: LoginSession, now: () -> Long = System::currentTimeMillis): ByteArray = mutex.withLock {
        if (previous.deploymentFingerprint != discovery.configuration.fingerprint || previous.proofKeyThumbprint != signer.publicKey.thumbprint) throw RemoteRequestException("auth.identity_mismatch")
        if (!discovery.refreshAllowed) throw RemoteRequestException("auth.reauthentication_required")
        val refreshToken = previous.consumeRefreshTokenForRequest()
        request(mapOf("grant_type" to "refresh_token", "client_id" to discovery.configuration.clientId, "resource" to discovery.configuration.resource, "refresh_token" to refreshToken), now)
    }

    private suspend fun request(parameters: Map<String, String>, now: () -> Long): ByteArray {
        val url = discovery.tokenEndpoint.toHttpUrl()
        val form = FormBody.Builder().apply { parameters.forEach { (name, value) -> add(name, value) } }.build()
        repeat(2) { attempt ->
            val proof = DeviceProofs.dpop(signer, "POST", url.toString(), now(), nonce)
            nonce = null
            val reply = http.execute(Request.Builder().url(url).post(form).header("DPoP", proof.compact).header("Accept", "application/json").header("Cache-Control", "no-store").build())
            nonce = reply.nonce()
            val challenge = reply.status == 400 && runCatching { JsonDocument.parse(reply.bytes).root.string("error") == "use_dpop_nonce" }.getOrDefault(false)
            if (attempt == 0 && challenge && nonce != null) return@repeat
            if (reply.status !in 200..299) {
                val rejected = runCatching { JsonDocument.parse(reply.bytes).root.string("error") }.getOrNull()
                throw RemoteRequestException(if (reply.status == 400 && rejected in setOf("invalid_grant", "unsupported_grant_type")) "auth.reauthentication_required" else "auth.token_exchange_failed")
            }
            return reply.bytes
        }
        throw RemoteRequestException("auth.token_exchange_failed")
    }
}

class RemoteApi internal constructor(private val http: LoginHttp, private val config: LoginConfiguration, private val session: LoginSession, private val signer: DeviceProofSigner) {
    private var nonce: String? = null
    private var mappedUserId: String? = null
    private val mutex = Mutex()

    /** Current identity can be queried before registering a device and obtains a fresh nonce. */
    suspend fun me(): ServiceAccountIdentity = mutex.withLock { identity() }

    private suspend fun identity(): ServiceAccountIdentity {
        val data = JsonDocument.parse(read("/v1/me")).root
        data.exactKeys("ok", "data")
        if (data["ok"] != JsonBoolean(true)) throw RemoteRequestException("network.invalid_response")
        val account = ServiceAccountIdentity.parse(data.obj("data"), session.issuer, session.subject, session.clientId, session.scopes, config.organizationId)
        if (mappedUserId != null && account.userId != mappedUserId) throw RemoteRequestException("auth.identity_mismatch")
        mappedUserId = account.userId
        return account
    }

    suspend fun runtimes(): JsonObject = mutex.withLock { JsonDocument.parse(read("/v1/runtimes")).root }
    suspend fun hosts(): JsonObject = mutex.withLock { JsonDocument.parse(read("/v1/hosts")).root }
    suspend fun sessions(runtimeId: String): JsonObject = mutex.withLock {
        Contract.uuid(runtimeId)
        JsonDocument.parse(read("/v1/runtimes/$runtimeId/sessions")).root
    }
    fun reader(deviceId: String, runtimeId: String, sessionId: String, scope: RelayScope, owner: CoroutineScope): SessionReader =
        SessionReader(this, deviceId, runtimeId, sessionId, scope, owner)
    fun sessionCreator(deviceId: String, runtimeId: String, scope: RelayScope, journal: CommandJournal, owner: CoroutineScope): SessionCreationFlow {
        Contract.uuid(deviceId); Contract.uuid(runtimeId)
        if(journal.owner.deviceId!=deviceId || journal.owner.organizationId!=config.organizationId || journal.owner.deploymentHash!=config.fingerprint || mappedUserId!=null && mappedUserId!=journal.owner.userId) throw RemoteRequestException("auth.identity_mismatch")
        if(scope.actions!=setOf("session.create","command.status") || scope.workspaces.isEmpty() || scope.sessions.isNotEmpty()) throw RemoteRequestException("access.denied")
        return SessionCreationFlow(this,deviceId,runtimeId,scope,journal,owner)
    }
    fun chatReader(deviceId: String, runtimeId: String, sessionId: String, scope: RelayScope, journal: CommandJournal, owner: CoroutineScope,
        transcripts: cn.edu.ustc.dsh.session.TranscriptCache? = null, workspaceId: String? = null): SessionReader {
        if (journal.owner.deviceId != deviceId || journal.owner.organizationId != config.organizationId || journal.owner.deploymentHash != config.fingerprint ||
            mappedUserId != null && mappedUserId != journal.owner.userId) throw RemoteRequestException("auth.identity_mismatch")
        if (transcripts != null && transcripts.owner.fingerprint != journal.owner.fingerprint) throw RemoteRequestException("auth.identity_mismatch")
        if (transcripts != null) scope.session(sessionId, workspaceId, setOf("session.read"))
        return SessionReader(this, deviceId, runtimeId, sessionId, scope, owner, journal = journal, transcripts = transcripts, workspaceId = workspaceId)
    }
    suspend fun commandStatus(id: String, deviceId: String): CommandReceipt = mutex.withLock {
        Contract.uuid(id); Contract.uuid(deviceId)
        val root = JsonDocument.parse(read("/v1/commands/$id?device_id=$deviceId")).root; root.exactKeys("ok", "data")
        if (root["ok"] != JsonBoolean(true)) throw RemoteRequestException("network.invalid_response")
        CommandReceipt.status(root.obj("data")).also { if (it.requestId != id) throw RemoteRequestException("network.invalid_response") }
    }
    /** Current session membership and read permission, including when its host is offline. */
    internal suspend fun cachedReadUntil(runtime: String, sessionId: String, workspace: String?, grantVersion: Long): Long = mutex.withLock {
        Contract.uuid(runtime); Contract.uuid(sessionId); workspace?.let(Contract::uuid)
        val requestedAt = System.currentTimeMillis(); val started = System.nanoTime()
        val root = JsonDocument.parse(read("/v1/runtimes/$runtime/sessions/$sessionId/read-access")).root
        root.exactKeys("ok", "data")
        if (root["ok"] != JsonBoolean(true)) throw RemoteRequestException("network.invalid_response")
        val data = root.obj("data"); data.exactKeys("runtime_id", "session_id", "workspace_id", "grant_version", "issued_at", "expires_at")
        val actualWorkspace = when (val value = data["workspace_id"]) { JsonNull -> null; is JsonString -> Contract.uuid(value.value); else -> throw ProtocolException() }
        if (data.string("runtime_id") != runtime || data.string("session_id") != sessionId || actualWorkspace != workspace || data.integer("grant_version", 1) != grantVersion) throw RemoteRequestException("access.denied")
        val issued = relayTime(data.string("issued_at")); val expires = relayTime(data.string("expires_at")); val now = System.currentTimeMillis()
        val remaining = expires - issued - (System.nanoTime() - started) / 1_000_000
        if (issued < requestedAt - 30_000 || issued > now + 30_000 || expires <= issued || expires - issued > 300_000 || remaining <= 0) throw RemoteRequestException("auth.expired")
        now + remaining
    }
    fun hostBinding(owner: CoroutineScope, resumeId: String? = null, onAuthorityFailure: (String) -> Unit = {}, onReady: () -> Unit = {}): HostBindingFlow =
        HostBindingFlow(this, owner, resumeId, onAuthorityFailure, onReady)

    suspend fun bindingStatus(id: String): HostBindingDetails = mutex.withLock {
        bindingDetails(read("/v1/enrollments/${Contract.uuid(id)}"), id)
    }
    suspend fun prepareHostBinding(id: String, code: String): HostBindingRequest = mutex.withLock {
        Contract.uuid(id); Contract.nonce(code)
        HostBindingRequest(this, bindingDetails(request("POST", "/v1/enrollments/$id/preview", jsonObject("code" to code.json())), id), code)
    }
    private fun bindingDetails(bytes: ByteArray, id: String): HostBindingDetails {
        val root = JsonDocument.parse(bytes).root
        root.exactKeys("ok", "data")
        if (root["ok"] != JsonBoolean(true)) throw RemoteRequestException("network.invalid_response")
        return HostBindingDetails.parse(root.obj("data"), config.organizationId, id)
    }
    internal suspend fun confirmReviewedBinding(reviewed: HostBindingDetails, code: String, current: () -> Unit, onDispatch: () -> Unit): HostBindingDetails = mutex.withLock {
        val prefix = "/v1/enrollments/${reviewed.id}"
        current()
        val fresh = bindingDetails(request("POST", "$prefix/preview", jsonObject("code" to code.json()), current), reviewed.id)
        if (fresh.reviewHash != reviewed.reviewHash) throw HostBindingException("binding.details_changed")
        current()
        if (fresh.confirmedByMe) return@withLock fresh
        if (fresh.userConfirmed) throw HostBindingException("binding.confirmed_elsewhere")
        if (!fresh.canConfirm()) throw HostBindingException(if (fresh.expired()) "binding.expired" else "binding.unavailable")
        val root = JsonDocument.parse(request("POST", "$prefix/confirm", jsonObject("code" to code.json())) { current(); onDispatch() }).root
        root.exactKeys("ok", "data")
        if (root["ok"] != JsonBoolean(true)) throw RemoteRequestException("network.invalid_response")
        val result = root.obj("data")
        result.exactKeys("enrollment_id", "host_id", "runtime_id", "state", "expires_at", "host_confirmed", "user_confirmed")
        val user = (result["user_confirmed"] as? JsonBoolean)?.value ?: throw ProtocolException()
        val host = (result["host_confirmed"] as? JsonBoolean)?.value ?: throw ProtocolException()
        if (result.string("enrollment_id") != fresh.id || result.string("host_id") != fresh.hostId || result.string("runtime_id") != fresh.runtimeId || relayTime(result.string("expires_at")) != fresh.expiresAt ||
            !user || result.string("state") != if (host) "approved" else "user_confirmed") throw ProtocolException()
        current()
        val accepted = bindingDetails(request("GET", prefix, beforeSend = current), reviewed.id)
        if (!accepted.confirmedByMe || accepted.reviewHash != reviewed.reviewHash) throw HostBindingException("binding.details_changed")
        accepted
    }

    suspend fun readTicket(runtimeId: String, deviceId: String, scope: RelayScope): RealtimeSessionTicket = mutex.withLock {
        if (scope.actions != setOf("session.read") || scope.workspaces.isEmpty() && scope.sessions.isEmpty()) throw RemoteRequestException("access.denied")
        issueSessionTicket(runtimeId, deviceId, scope)
    }
    suspend fun sessionTicket(runtimeId: String, deviceId: String, scope: RelayScope): RealtimeSessionTicket = mutex.withLock {
        if ("session.read" !in scope.actions || scope.actions.any { it !in setOf("session.read", "message.submit", "session.cancel", "command.status") } ||
            scope.actions.any { it in setOf("message.submit", "session.cancel") } && "command.status" !in scope.actions || scope.workspaces.isEmpty() && scope.sessions.isEmpty()) throw RemoteRequestException("access.denied")
        issueSessionTicket(runtimeId, deviceId, scope)
    }
    internal suspend fun creationTicket(runtimeId: String, deviceId: String, scope: RelayScope): RealtimeSessionTicket = mutex.withLock {
        if (scope.actions != setOf("session.create", "command.status") || scope.workspaces.isEmpty() || scope.sessions.isNotEmpty()) throw RemoteRequestException("access.denied")
        issueSessionTicket(runtimeId, deviceId, scope)
    }
    private suspend fun issueSessionTicket(runtimeId: String, deviceId: String, scope: RelayScope): RealtimeSessionTicket {
        Contract.uuid(runtimeId); Contract.uuid(deviceId)
        val body = jsonObject("runtime_id" to runtimeId.json(), "scope" to scope.json())
        val requestedAt = System.currentTimeMillis()
        val root = JsonDocument.parse(request("POST", "/v1/realtime/tickets", body)).root
        root.exactKeys("ok", "data")
        if (root["ok"] != JsonBoolean(true)) throw RemoteRequestException("network.invalid_response")
        val data = root.obj("data"); data.exactKeys("ticket", "runtime_id", "grant_version", "scope", "expires_at")
        val token = data.string("ticket")
        if (Contract.base64url(token).size != 32 || data.string("runtime_id") != runtimeId || !scope.same(RelayScope.parse(data.obj("scope")))) throw RemoteRequestException("auth.identity_mismatch")
        val expires = relayTime(data.string("expires_at"))
        if (expires <= System.currentTimeMillis() || expires > requestedAt + 60_000) throw RemoteRequestException("auth.expired")
        return RealtimeSessionTicket(http, config, signer, deviceId, runtimeId, data.integer("grant_version"), scope, expires, session.accessExpiresAt, token)
    }

    /** Reconciliation only: never creates or revives a device and never replays a write. */
    suspend fun currentDevice(approvalKey: PublicProofKey): RegisteredDevice? = mutex.withLock {
        identity()
        val root = JsonDocument.parse(read("/v1/devices/current")).root
        root.exactKeys("ok", "data")
        if (root["ok"] != JsonBoolean(true)) throw RemoteRequestException("network.invalid_response")
        val data = root.obj("data")
        if (data.string("state") == "unregistered") {
            data.exactKeys("state")
            return@withLock null
        }
        data.exactKeys("state", "device")
        val state = data.string("state")
        if (state !in setOf("active", "revoked")) throw RemoteRequestException("network.invalid_response")
        val device = data.obj("device"); device.exactKeys("device_id", "key_version", "approval_key_jkt", "proof_key_jkt")
        if (device.string("approval_key_jkt") != approvalKey.thumbprint || device.string("proof_key_jkt") != signer.publicKey.thumbprint) throw RemoteRequestException("auth.identity_mismatch")
        val id = Contract.uuid(device.string("device_id"))
        val version = device.integer("key_version", 1, 9_007_199_254_740_991)
        if (state == "revoked" || version != 1L) throw RemoteRequestException("device.invalid")
        RegisteredDevice(id, version)
    }

    suspend fun prepareRegistration(approvalKey: PublicProofKey, name: String): RegistrationRequest = mutex.withLock {
        // A successful /me request obtains a nonce before asking for user auth.
        identity()
        val jti = DeviceProofs.randomId()
        val prepared = PreparedDeviceRegistration.prepare(session.issuer, session.subject, name, approvalKey, signer.publicKey, jti, System.currentTimeMillis())
        val reserved = nonce; nonce = null
        RegistrationRequest(prepared, approvalKey, name, jti, reserved)
    }

    inner class RegistrationRequest internal constructor(
        val signatureRequest: PreparedDeviceRegistration, private val approvalKey: PublicProofKey, private val name: String, private val jti: String, private val reservedNonce: String?,
    ) {
        private val once = java.util.concurrent.atomic.AtomicBoolean()
        suspend fun submit(signed: DeviceRegistrationProof): RegisteredDevice = mutex.withLock {
            if (!once.compareAndSet(false, true) || signed.dpopJti != jti) throw RemoteRequestException("auth.proof_invalid")
            val access = session.accessTokenForRequest(System.currentTimeMillis())
            val url = (config.remoteOrigin + "/v1/devices").toHttpUrl()
            val proof = DeviceProofs.dpop(signer, "POST", url.toString(), System.currentTimeMillis(), reservedNonce, access, jti)
            val body = JsonDocument.of(jsonObject("name" to name.json(), "approval_public_jwk" to approvalKey.document.root,
                "approval_proof" to signed.compact.json(), "proof_public_jwk" to signer.publicKey.document.root)).canonicalBytes().toRequestBody("application/json".toMediaType())
            val reply = http.execute(Request.Builder().url(url).post(body).header("Authorization", "DPoP $access").header("DPoP", proof.compact).header("Accept", "application/json").build())
            nonce = reply.nonce()
            // No automatic retry: a new DPoP jti needs a new approval-key proof
            // and explicit local authentication. Transport loss is ambiguous.
            val result = JsonDocument.parse(http.checked(reply).bytes).root
            result.exactKeys("ok", "data")
            if (result["ok"] != JsonBoolean(true)) throw RemoteRequestException("network.invalid_response")
            val data = result.obj("data"); data.exactKeys("device_id", "key_version")
            RegisteredDevice(Contract.uuid(data.string("device_id")), data.integer("key_version", 1, 1))
        }
        fun cancel() { once.set(true); signatureRequest.cancel() }
    }

    private suspend fun read(path: String): ByteArray = request("GET", path)

    private suspend fun request(method: String, path: String, body: JsonObject? = null, beforeSend: () -> Unit = {}): ByteArray {
        val url = (config.remoteOrigin + path).toHttpUrl()
        repeat(2) { attempt ->
            currentCoroutineContext().ensureActive()
            val access = session.accessTokenForRequest(System.currentTimeMillis())
            val proof = DeviceProofs.dpop(signer, method, url.toString(), System.currentTimeMillis(), nonce, access)
            nonce = null
            val builder = Request.Builder().url(url).header("Authorization", "DPoP $access").header("DPoP", proof.compact).header("Accept", "application/json").header("Cache-Control", "no-store")
            if (body != null) builder.post(JsonDocument.of(body).canonicalBytes().toRequestBody("application/json".toMediaType()))
            currentCoroutineContext().ensureActive(); beforeSend()
            val reply = http.execute(builder.build())
            nonce = reply.nonce()
            val challenge = reply.status == 401 && reply.headers.values("WWW-Authenticate").any { it == "DPoP error=\"use_dpop_nonce\"" }
            if (attempt == 0 && challenge && nonce != null) return@repeat
            return http.checked(reply).bytes
        }
        throw RemoteRequestException("auth.proof_invalid")
    }
}

class RegisteredDevice(val deviceId: String, val keyVersion: Long)
