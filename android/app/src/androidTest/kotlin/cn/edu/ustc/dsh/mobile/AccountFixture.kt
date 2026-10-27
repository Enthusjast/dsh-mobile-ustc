package cn.edu.ustc.dsh.mobile

import android.content.Context
import cn.edu.ustc.dsh.auth.*
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.data.SqlCommandJournal
import cn.edu.ustc.dsh.crypto.*
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
    val ticketScopes = java.util.concurrent.CopyOnWriteArrayList<RelayScope>()
    val subscriptions = AtomicInteger()
    val relayClosures = AtomicInteger()
    val bindingPreviews = AtomicInteger()
    val bindingWrites = AtomicInteger()
    val bindingStatusReads = AtomicInteger()
    val commandWrites = AtomicInteger()
    @Volatile var appUpdateMode = false
    @Volatile var appUpdateRelease: AppRelease? = null
    @Volatile var appUpdateBytes = ByteArray(0)
    @Volatile var holdAppUpdateMetadata = false
    @Volatile var slowAppUpdateDownload = false
    val appUpdateQueries = AtomicInteger()
    val appUpdateDownloads = AtomicInteger()
    val appUpdateDownloadFailure = AtomicReference<String?>()
    val appUpdateFlowFailure = AtomicReference<String?>()
    val commandStatuses = java.util.concurrent.ConcurrentHashMap<String, JsonObject>()
    @Volatile var pushMode = false
    @Volatile var pushCleanupUnavailable = false
    @Volatile var pushReferenceAvailability = "online"
    @Volatile var pushReferenceState = "pending"
    @Volatile var pushReferenceKind = "approval"
    @Volatile var pushReferenceId: String? = null
    @Volatile var holdPushReference = false
    val pushRegistrations = AtomicInteger()
    val pushConfirmations = AtomicInteger()
    val pushCleanups = AtomicInteger()
    val pushReads = AtomicInteger()
    val pushStates = java.util.concurrent.ConcurrentHashMap<String, String>()
    private val pushIntents = java.util.concurrent.ConcurrentHashMap<String, JsonObject>()
    var pushDeliver: ((Map<String, String>) -> Unit)? = null
    val pushNonce = "Q".repeat(42) + "A"
    val pushNotificationId = UUID.randomUUID().toString()
    @Volatile var chatMode = false
    @Volatile var fileMode = false
    @Volatile var exportMode = false
    @Volatile var exportSlow = false
    val exportSelections = AtomicInteger()
    val exportDownloads = AtomicInteger()
    val exportSourceId = UUID.randomUUID().toString()
    val exportFileId = UUID.randomUUID().toString()
    val exportBytes = "public APK export fixture\n".repeat(6000).toByteArray()
    private val exportRequests = java.util.concurrent.ConcurrentHashMap<String, JsonObject>()
    @Volatile var fileState = "scanning"
    @Volatile var fileReady = false
    private class FileEntry(val id: String, val requestId: String, val manifest: FileManifest, val createdAt: Long) {
        @Volatile var uploaded = false
        @Volatile var committed = false
        @Volatile var messageId: String? = null
    }
    private val files = java.util.concurrent.ConcurrentHashMap<String, FileEntry>()
    val fileRegistrations = AtomicInteger()
    val filePuts = AtomicInteger()
    val fileMessage = AtomicReference<CommandIntent?>()
    @Volatile var archiveMode = false
    @Volatile var archived = false
    val archiveWrites = AtomicInteger()
    @Volatile var creationMode = false
    @Volatile var questionMode=false
    @Volatile var approvalMode = false
    @Volatile var approvalRole = "owner"
    @Volatile var approvalAssurance = true
    @Volatile var dropApprovalReply = false
    @Volatile var approvalNativeResult = true
    val approvalWrites = AtomicInteger()
    val approvalQueries = AtomicInteger()
    val approvalDetails = AtomicInteger()
    val lastApproval = AtomicReference<SignedApprovalDecision?>()
    private var approvalPublic: JsonObject? = null
    private class ApprovalEndpoint(val id: String, val scope: RelayScope)
    private val approvalEndpoint = AtomicReference<ApprovalEndpoint?>()
    private val publishApproval = AtomicReference<(() -> Unit)?>(null)
    val approvalBody: ApprovalContext by lazy {
        val now = System.currentTimeMillis()
        ApprovalContext.from(JsonDocument.of(jsonObject("domain" to APPROVAL_CONTEXT_DOMAIN.json(), "protocol_version" to 1L.json(),
            "host_id" to "44444444-4444-4444-8444-444444444444".json(), "installation_id" to "77777777-7777-4777-8777-777777777777".json(),
            "runtime_id" to runtimeId.json(), "runtime_epoch" to "77777777-7777-4777-8777-777777777777".json(), "session_id" to sessionId.json(),
            "dsh_session_id" to "native-platform-approval".json(), "approval_id" to UUID.randomUUID().toString().json(), "execution_id" to UUID.randomUUID().toString().json(),
            "call_id" to "platform-call".json(), "tool" to "bash".json(), "arguments" to jsonObject("command" to "printf platform-fixture".json()),
            "workspace" to jsonObject("workspace_id" to workspaceId.json(), "root_sha256" to "a".repeat(64).json()), "resources" to JsonArray(emptyList()),
            "nonce" to Contract.base64url(ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }).json(), "policy_version" to 7L.json(),
            "required_assurance" to jsonObject("profile" to "fixture/step-up".json(), "max_auth_age_seconds" to 60L.json()),
            "created_at" to Contract.timestamp(now).json(), "expires_at" to Contract.timestamp(now + 120_000).json())))
    }
    val approvalStatus = AtomicReference<JsonObject?>()
    fun currentApprovalStatus(): JsonObject = approvalStatus.get() ?: jsonObject("approval_id" to approvalBody.root["approval_id"], "runtime_id" to runtimeId.json(),
        "runtime_epoch" to approvalBody.root["runtime_epoch"], "session_id" to sessionId.json(), "execution_id" to approvalBody.root["execution_id"],
        "binding_sha256" to approvalBody.bindingSha256.json(), "expires_at" to Contract.timestamp(approvalBody.expiresAt).json(), "state" to "pending".json())
    fun reportApproval(status: JsonObject) { approvalStatus.set(status); publishApproval.get()?.invoke() }
    fun endApproval(state: String = "cancelled") = reportApproval(currentApprovalStatus().with("state" to state.json()))
    @Volatile var blockingPending=true
    @Volatile var timedQuestionState: String?=null
    val ordinaryQuestionId="90000000-0000-4000-8000-000000000001"
    val timedQuestionId="90000000-0000-4000-8000-000000000002"
    val questionWrites=AtomicInteger()
    private val questionRequestIds = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
    val claimWrites=AtomicInteger()
    val releaseWrites=AtomicInteger()
    private val publishQuestions=AtomicReference<(() -> Unit)?>(null)
    val workspaceId="99999999-9999-4999-8999-999999999999"
    val creationWrites=AtomicInteger()
    val createdSessions=java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
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
    @Volatile var allowSessionList = true
    @Volatile var allowHostList = false
    @Volatile var allowCommandStatus = true
    @Volatile var holdSessionTarget = false
    val targetRequests = AtomicInteger()
    val answerStatusRequests = AtomicInteger()
    @Volatile var holdSessions = false
    private val directoryScope get() = RelayScope((if (allowSessionList) listOf("session.list") else emptyList()) + (if (allowHostList) listOf("host.list") else emptyList()) + (if (allowSessionRead) listOf("session.read") else emptyList()) +
        (if (chatMode || creationMode || questionMode) listOf("message.submit", "session.cancel") + (if (allowCommandStatus) listOf("command.status") else emptyList()) else emptyList())+
        (if(questionMode) listOf("question.answer") else emptyList())+
        (if(archiveMode) listOf("session.archive") else emptyList())+
        (if(approvalMode) listOf("approval.decide", "grant.manage") else emptyList())+
        (if(creationMode) listOf("session.create") else emptyList()) + (if(fileMode) listOf("file.upload") else emptyList()) + (if(exportMode) listOf("file.download") else emptyList()), if(creationMode) listOf(workspaceId) else emptyList(), listOf(sessionId))
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
    private var schoolAuthenticatedAt = System.currentTimeMillis() / 1000
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
            .eventListener(object : EventListener() {
                override fun callFailed(call: Call, ioe: java.io.IOException) {
                    if (call.request().url.encodedPath == "/app-updates/candidate.apk") appUpdateDownloadFailure.set(ioe.stackTraceToString())
                }
            })
            .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false).cookieJar(CookieJar.NO_COOKIES)
            .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS).readTimeout(5, java.util.concurrent.TimeUnit.SECONDS).callTimeout(10, java.util.concurrent.TimeUnit.SECONDS).build()
        // The production factory still trusts system TLS only. Reflection is confined to this test APK.
        http = LoginHttp::class.java.getDeclaredConstructor(OkHttpClient::class.java).apply { isAccessible = true }.newInstance(transport)
    }
    fun environment(minimumValidity: Long = 0, approvalPromptMillis: Long = MAX_DECISION_AGE_MS, pushProvider: ((NotificationCenter) -> DevicePushProvider)? = null,
        appUpdateConfiguration: (() -> ByteArray)? = null) = LoginEnvironment({ configBytes }, slot, ledgerName, refreshLeadMillis = 0, minimumValidityMillis = minimumValidity, approvalPromptMillis = approvalPromptMillis, pushProvider = pushProvider, appUpdateConfiguration = appUpdateConfiguration,
            appUpdateDiagnosticFailure = { appUpdateFlowFailure.set(it.stackTraceToString()) })
    private fun discovery() = jsonObject("issuer" to issuer.json(), "authorization_endpoint" to "$origin/authorize".json(),
        "token_endpoint" to "$origin/token".json(), "jwks_uri" to "$origin/jwks".json(),
        "response_types_supported" to JsonArray(listOf("code".json())), "id_token_signing_alg_values_supported" to JsonArray(listOf("ES256".json())))
    private fun jwt(claims: JsonObject, type: String) = JWSObject(JWSHeader.Builder(JWSAlgorithm.ES256).keyID(issuerKey.keyID).type(JOSEObjectType(type)).build(), Payload(JsonDocument.of(claims).canonicalText())).apply { sign(ECDSASigner(issuerKey)) }.serialize()
    private fun tokenReply(jkt: String, userSubject: String, nonce: String?, ttl: Long): JsonObject {
        val now = System.currentTimeMillis() / 1000
        val common = jsonObject("iss" to issuer.json(), "sub" to userSubject.json(), "iat" to now.json(), "exp" to (now + ttl).json())
        if (nonce != null) schoolAuthenticatedAt = now
        var resource = common.with("aud" to config.audience.json(), "client_id" to config.clientId.json(), "jti" to UUID.randomUUID().toString().json(), "scope" to "remote.access".json(), "cnf" to jsonObject("jkt" to jkt.json()))
        if (approvalMode) resource = resource.with("auth_time" to schoolAuthenticatedAt.json(), "acr" to (if (approvalAssurance) "fixture:2" else "fixture:1").json(), "amr" to JsonArray(listOf((if (approvalAssurance) "otp" else "pwd").json())))
        val access = jwt(resource, "at+jwt")
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
        if (appUpdateMode && path == "/app-updates/candidate.apk") {
            require(request.method == "GET" && listOf("Authorization", "DPoP", "Cookie").all { request.getHeader(it) == null })
            appUpdateDownloads.incrementAndGet()
            val reply = MockResponse().setHeader("Content-Type", "application/vnd.android.package-archive").setBody(okio.Buffer().write(appUpdateBytes))
            return if (slowAppUpdateDownload) reply.setBodyDelay(2, java.util.concurrent.TimeUnit.SECONDS) else reply
        }
        if (pushMode && request.method == "DELETE" && path.startsWith("/v1/push-bindings/")) {
            require(request.getHeader("DPoP") == null && request.getHeader("Cookie") == null)
            val id = path.substringAfterLast('/')
            val secret = request.getHeader("Authorization")!!.removePrefix("DSH-Push-Revoke ")
            require(sha256(secret.toByteArray()) == pushIntents[id]!!.string("revoke_secret_sha256"))
            if (pushCleanupUnavailable) return response(jsonObject("ok" to JsonBoolean(false)), 503)
            pushStates[id] = "disabled"; pushCleanups.incrementAndGet(); return MockResponse().setResponseCode(204)
        }
        if (path.startsWith("/quarantine/")) {
            require(fileMode && request.method == "PUT")
            require(listOf("Authorization", "DPoP", "Cookie").all { request.getHeader(it) == null })
            val file = files[path.substringAfterLast('/')]!!
            val bytes = request.body.readByteArray()
            require(bytes.size.toLong() == file.manifest.sizeBytes && sha256(bytes) == file.manifest.sha256)
            require(bytes.contentEquals(FixtureDocumentProvider.BYTES))
            file.uploaded = true; filePuts.incrementAndGet()
            return MockResponse().setResponseCode(200)
        }
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
                private var currentSession=sessionId
                private var subscribeRequest: String?=null
                private var questionRevision=0L
                private var activeClaim: String?=null
                private var approvalWatch: String? = null
                private fun approvalFrame(socket: WebSocket, type: String, request: String, payload: JsonObject, scoped: Boolean = true) {
                    var frame = jsonObject("v" to 1L.json(), "type" to type.json(), "request_id" to request.json(), "runtime_id" to runtimeId.json(), "payload" to payload)
                    if (scoped) frame = frame.with("runtime_epoch" to epoch.json(), "session_id" to sessionId.json())
                    socket.send(JsonDocument.of(frame).canonicalText())
                }
                private val questionExpiry=java.time.Instant.now().plusSeconds(180).toString()
                private fun questionItems(timed: Boolean): JsonArray {
                    if(if(timed) timedQuestionState==null else !blockingPending) return JsonArray(emptyList())
                    val prompt=if(timed) jsonObject("id" to "timed".json(),"question" to "请给出后续答复".json(),"options" to JsonArray(listOf(jsonObject("label" to "回复".json()))))
                        else jsonObject("id" to "plan".json(),"question" to "是否继续这份计划？".json(),"detail" to "请核对夹具计划后作答。".json(),"options" to JsonArray(listOf(jsonObject("label" to "继续".json()),jsonObject("label" to "停止".json()))),"intent" to jsonObject("kind" to "plan-review".json(),"approve" to "继续".json()))
                    var item=jsonObject("question_id" to (if(timed) timedQuestionId else ordinaryQuestionId).json(),"expires_at" to (if(timed) JsonNull else questionExpiry.json()),"questions" to JsonArray(listOf(prompt)))
                    if(timed) item=item.with("state" to timedQuestionState!!.json())
                    return JsonArray(listOf(item))
                }
                private fun questions(socket: WebSocket) {
                    val request=subscribeRequest ?: return
                    if(!questionMode) return
                    questionRevision++
                    send(socket,"question.snapshot",request,jsonObject("revision" to questionRevision.json(),"items" to questionItems(false)))
                    send(socket,"question.timed.snapshot",request,jsonObject("revision" to questionRevision.json(),"items" to questionItems(true)))
                }
                private fun send(socket: WebSocket, type: String, request: String, payload: JsonObject) {
                    var frame = jsonObject("v" to 1L.json(), "type" to type.json(), "request_id" to request.json(), "runtime_id" to runtimeId.json(), "runtime_epoch" to epoch.json(),
                        "session_id" to currentSession.json(), "subscription_id" to subscription.json(), "payload" to payload)
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
                            "file.exports.list", "file.export.request" -> {
                                require(exportMode && "file.download" in subscribedScope.actions && frame.string("session_id") == sessionId && frame.string("runtime_epoch") == epoch)
                                val result = if (frame.string("type") == "file.exports.list") {
                                    jsonObject("items" to JsonArray(listOf(jsonObject("source_id" to exportSourceId.json(), "kind" to "file".json(), "origin" to "session_attachment".json(),
                                        "name" to "APK export.txt".json(), "size_bytes" to exportBytes.size.toLong().json(), "expires_at" to Contract.timestamp(System.currentTimeMillis() + 120_000).json()))), "directory_id" to JsonNull, "cursor" to JsonNull)
                                } else {
                                    require(payload.string("source_id") == exportSourceId)
                                    val id = frame.string("request_id")
                                    val owner = CommandOwner(accountId, organizationId, config.fingerprint, userId, deviceId)
                                    SqlCommandJournal.open(context, owner).use { database -> require(kotlinx.coroutines.runBlocking { database.exports(runtimeId, sessionId).any { it.intent.requestId == id } }) }
                                    exportRequests.putIfAbsent(id, exportStatus()); exportSelections.incrementAndGet()
                                    jsonObject("file" to exportRequests[id]!!)
                                }
                                webSocket.send(JsonDocument.of(frame.with("type" to (if (frame.string("type") == "file.exports.list") "file.exports.result" else "file.export.accepted").json(), "payload" to result)).canonicalText()); return
                            }
                            "file.export.cancel" -> return
                            "approval.subscribe" -> {
                                require(approvalMode && approvalRole == "owner" && "approval.decide" in subscribedScope.actions)
                                approvalWatch = frame.string("request_id")
                                publishApproval.set { approvalFrame(webSocket, "approval.reference", approvalWatch!!, jsonObject("status" to currentApprovalStatus())) }
                                val status = currentApprovalStatus()
                                val items = if (status.string("state") in setOf("pending", "decision_received")) listOf(status) else emptyList()
                                approvalFrame(webSocket, "approval.snapshot", approvalWatch!!, jsonObject("items" to JsonArray(items)), scoped = false)
                                return
                            }
                            "approval.status.get" -> {
                                require(approvalMode && payload.string("approval_id") == approvalBody.root.string("approval_id"))
                                approvalQueries.incrementAndGet()
                                approvalFrame(webSocket, "approval.reference", frame.string("request_id"), jsonObject("status" to currentApprovalStatus())); return
                            }
                            "approval.details.get" -> {
                                require(approvalMode && !runtimeOffline && approvalRole == "owner" && payload.string("approval_id") == approvalBody.root.string("approval_id"))
                                approvalDetails.incrementAndGet()
                                approvalFrame(webSocket, "approval.details", frame.string("request_id"), jsonObject("context" to approvalBody.root)); return
                            }
                            "ping" -> {
                                webSocket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "pong".json(), "payload" to jsonObject("connection_id" to connectionId.json(), "server_time" to java.time.Instant.now().toString().json()))).canonicalText())
                                return
                            }
                            "session.subscribe" -> {
                                currentSession=frame.string("session_id")
                                require(frame.string("runtime_id") == runtimeId && (currentSession==sessionId && sessionId in subscribedScope.sessions || currentSession in createdSessions && workspaceId in subscribedScope.workspaces))
                                val requestId = frame.string("request_id")
                                subscribeRequest=requestId;publishQuestions.set {questions(webSocket)}
                                if (runtimeOffline) {
                                    webSocket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "error".json(), "request_id" to requestId.json(), "runtime_id" to runtimeId.json(), "session_id" to currentSession.json(), "payload" to jsonObject("code" to "runtime.offline".json()))).canonicalText())
                                    return
                                }
                                send(webSocket, "session.subscribed", requestId, jsonObject())
                                if(currentSession in createdSessions) {
                                    send(webSocket,"session.snapshot",requestId,jsonObject("cursor" to (-1L).json(),"has_more" to JsonBoolean(false),"records" to JsonArray(emptyList()),"assistant" to JsonNull))
                                    send(webSocket,"session.checkpoint",requestId,jsonObject("state" to "persisted".json(),"through_seq" to (-1L).json()))
                                    subscriptions.incrementAndGet(); return
                                }
                                send(webSocket, "session.snapshot", requestId, jsonObject("cursor" to 2L.json(), "has_more" to JsonBoolean(true), "records" to JsonArray(listOf(user(2, "电脑当前消息"))), "assistant" to jsonObject("revision" to 0L.json())))
                                send(webSocket, "session.checkpoint", requestId, jsonObject("state" to "persisted".json(), "through_seq" to 2L.json()))
                                questions(webSocket)
                                subscriptions.incrementAndGet()
                                return
                            }
                            "session.page" -> {
                                require(frame.string("runtime_epoch") == epoch && frame.string("subscription_id") == subscription && payload.integer("through_seq", -1) == 2L && payload.integer("before_seq") == 2L)
                                send(webSocket, "session.page.result", frame.string("request_id"), jsonObject("records" to JsonArray(listOf(user(0, "最早的消息"), user(1, "更早的消息"))), "has_more" to JsonBoolean(false), "through_seq" to 2L.json()))
                                return
                            }
                            "session.create.options.get" -> {
                                require(creationMode && "session.create" in subscribedScope.actions && workspaceId in subscribedScope.workspaces)
                                if(runtimeOffline) webSocket.send(JsonDocument.of(jsonObject("v" to 1L.json(),"type" to "error".json(),"request_id" to frame.string("request_id").json(),"runtime_id" to runtimeId.json(),"payload" to jsonObject("code" to "runtime.offline".json()))).canonicalText())
                                else webSocket.send(JsonDocument.of(jsonObject("v" to 1L.json(),"type" to "session.create.options.result".json(),"request_id" to frame.string("request_id").json(),"runtime_id" to runtimeId.json(),"runtime_epoch" to epoch.json(),
                                    "payload" to jsonObject("workspaces" to JsonArray(listOf(jsonObject("workspace_id" to workspaceId.json(),"label" to "开发夹具".json()))),"presets" to JsonArray(listOf("fixture".json()))))).canonicalText())
                                return
                            }
                            "session.create" -> {
                                require(creationMode && "session.create" in subscribedScope.actions && workspaceId in subscribedScope.workspaces)
                                val intent=cn.edu.ustc.dsh.command.CommandIntent.parse(frame)
                                require(intent.epoch==epoch && intent.workspaceId==workspaceId && intent.payload.string("preset")=="fixture")
                                val existing=commandStatuses[intent.requestId]
                                val status=if(existing!=null) { require(existing.string("payload_sha256")==intent.digest); existing } else {
                                    val result=UUID.randomUUID().toString(); createdSessions.add(result); creationWrites.incrementAndGet()
                                    jsonObject("request_id" to intent.requestId.json(),"workspace_id" to workspaceId.json(),"session_id" to result.json(),"state" to "settled".json(),"payload_sha256" to intent.digest.json(),"updated_at" to java.time.Instant.now().toString().json()).also {commandStatuses[intent.requestId]=it}
                                }
                                if(dropNextCommandReply) {dropNextCommandReply=false;webSocket.close(1001,"fixture response lost");return}
                                webSocket.send(JsonDocument.of(jsonObject("v" to 1L.json(),"type" to "command.receipt".json(),"request_id" to intent.requestId.json(),"runtime_id" to runtimeId.json(),"runtime_epoch" to epoch.json(),"session_id" to status.string("session_id").json(),
                                    "payload" to JsonObject(status.fields.filterKeys {it in setOf("state","payload_sha256","updated_at","workspace_id")}))).canonicalText())
                                return
                            }
                            "question.claim"->{
                                require(questionMode && "question.answer" in subscribedScope.actions && payload.string("question_id")==timedQuestionId && timedQuestionState=="open")
                                activeClaim=frame.string("request_id");claimWrites.incrementAndGet()
                                send(webSocket,"question.claimed",activeClaim!!,jsonObject("question_id" to timedQuestionId.json(),"remaining_ms" to 2000L.json(),"expires_at" to java.time.Instant.now().plusMillis(2000).toString().json()))
                                return
                            }
                            "question.release"->{
                                require(questionMode && payload.string("claim_id")==activeClaim)
                                releaseWrites.incrementAndGet();send(webSocket,"question.released",frame.string("request_id"),jsonObject("claim_id" to activeClaim!!.json()))
                                timedQuestionState="continued";questions(webSocket);return
                            }
                            "question.answer","question.timed.answer"->{
                                require(questionMode && "question.answer" in subscribedScope.actions && frame.string("session_id")==sessionId)
                                val intent=cn.edu.ustc.dsh.command.CommandIntent.parse(frame)
                                val timed=intent.kind==cn.edu.ustc.dsh.command.CommandKind.TIMED_QUESTION
                                val answers=QuestionAnswers.parse(intent.payload);require(answers.questionId==(if(timed) timedQuestionId else ordinaryQuestionId))
                                val existing=commandStatuses[intent.requestId]
                                val state=if(timed && timedQuestionState=="continued") "agent_queued" else "settled"
                                val status=if(existing!=null) {require(existing.string("payload_sha256")==intent.digest);existing} else {
                                    require(if(timed) timedQuestionState in setOf("open","continued") else blockingPending)
                                    questionWrites.incrementAndGet()
                                    questionRequestIds.add(intent.requestId)
                                    if(timed) timedQuestionState=if(state=="agent_queued") "reply_queued" else null else blockingPending=false
                                    jsonObject("request_id" to intent.requestId.json(),"session_id" to sessionId.json(),"state" to state.json(),"payload_sha256" to intent.digest.json(),"updated_at" to java.time.Instant.now().toString().json()).also {commandStatuses[intent.requestId]=it}
                                }
                                questions(webSocket)
                                if(dropNextCommandReply) {dropNextCommandReply=false;webSocket.close(1001,"fixture response lost");return}
                                webSocket.send(JsonDocument.of(jsonObject("v" to 1L.json(),"type" to "command.receipt".json(),"request_id" to intent.requestId.json(),"runtime_id" to runtimeId.json(),"runtime_epoch" to epoch.json(),"session_id" to sessionId.json(),"payload" to JsonObject(status.fields.filterKeys {it in setOf("state","payload_sha256","updated_at")}))).canonicalText())
                                return
                            }
                            "message.submit", "session.cancel", "session.archive" -> {
                                val target=frame.string("session_id")
                                require((chatMode || creationMode) && frame.string("runtime_id") == runtimeId && (target==sessionId || target in createdSessions))
                                val intent = cn.edu.ustc.dsh.command.CommandIntent.parse(frame)
                                require(intent.kind.wire in subscribedScope.actions)
                                if (intent.fileIds().isNotEmpty()) {
                                    require(fileMode && fileReady && fileState == "clean")
                                    intent.fileIds().forEach { id ->
                                        val file = files[id]!!
                                        require(file.committed && (file.messageId == null || file.messageId == intent.requestId))
                                        file.messageId = intent.requestId
                                    }
                                    fileMessage.set(intent)
                                }
                                commandWrites.incrementAndGet()
                                if (intent.kind == cn.edu.ustc.dsh.command.CommandKind.ARCHIVE) {
                                    require(archiveMode && target == sessionId && intent.epoch == epoch)
                                    archived = (intent.payload["archived"] as JsonBoolean).value
                                    archiveWrites.incrementAndGet()
                                }
                                val state = if (intent.kind == cn.edu.ustc.dsh.command.CommandKind.MESSAGE) "agent_queued" else "settled"
                                val status = jsonObject("request_id" to intent.requestId.json(), "session_id" to target.json(), "state" to state.json(), "payload_sha256" to intent.digest.json(), "updated_at" to java.time.Instant.now().toString().json())
                                commandStatuses[intent.requestId] = status
                                if (dropNextCommandReply) { dropNextCommandReply = false; webSocket.close(1001, "fixture response lost"); return }
                                webSocket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "command.receipt".json(), "request_id" to intent.requestId.json(), "runtime_id" to runtimeId.json(), "runtime_epoch" to epoch.json(), "session_id" to target.json(),
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
                        require(capabilities.toSet().all { it in setOf("connection.heartbeat.v1", "session.read.v1", "question.blocking.v1","question.timed.v1","command.relay.v1", FILE_MESSAGE_CAPABILITY, FILE_EXPORT_CAPABILITY, "session.archive.v1", "session.cancel.v1", "session.create.v1", "session.create_options.v1", "approval.signed.v1") })
                        require(claims.string("hello_sha256") == DeviceHello(deviceId, capabilities).digest())
                        relayProofReceived = true
                        if ("approval.signed.v1" in capabilities) approvalEndpoint.set(ApprovalEndpoint(connectionId, subscribedScope))
                        webSocket.send(JsonDocument.of(jsonObject("v" to 1L.json(), "type" to "hello.ok".json(), "payload" to jsonObject(
                            "role" to "device".json(), "connection_id" to connectionId.json(), "device_id" to deviceId.json(), "runtime_id" to "55555555-5555-4555-8555-555555555555".json(),
                            "grant_version" to 7L.json(), "scope" to subscribedScope.json(), "protocols" to JsonArray(listOf(1L.json())),
                            "capabilities" to JsonArray(capabilities.map(String::json)), "heartbeat_seconds" to 20L.json(), "max_frame_bytes" to RELAY_FRAME_BYTES.toLong().json(),
                            "server_time" to java.time.Instant.now().toString().json(), "lease_expires_at" to java.time.Instant.ofEpochMilli(leaseExpires).toString().json()))).canonicalText())
                    } catch (_: Exception) { failure.set("native Relay proof validation failed"); webSocket.cancel() }
                }
                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) { relayClosures.incrementAndGet(); if (currentRelay.compareAndSet(webSocket, null)) approvalEndpoint.set(null) }
                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) { relayClosures.incrementAndGet(); if (currentRelay.compareAndSet(webSocket, null)) approvalEndpoint.set(null) }
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
            proofJkt = requestJkt; approvalJkt = approval.computeThumbprint().toString(); approvalPublic = body.obj("approval_public_jwk"); active = true
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
        if (appUpdateMode && path == "/v1/app/releases/latest") {
            require(request.method == "GET")
            val url = request.requestUrl!!
            require(url.queryParameterNames == setOf("organization_id", "version_code", "protocol_version", "android_api"))
            require(url.queryParameter("organization_id") == organizationId && url.queryParameter("protocol_version") == "1" && url.queryParameter("android_api")!!.toLong() in 26..100)
            val version = url.queryParameter("version_code")!!.toLong()
            appUpdateQueries.incrementAndGet()
            val reply = resourceResponse(data(jsonObject("v" to 1L.json(), "package_name" to context.packageName.json(), "protocol_version" to 1L.json(),
                "current_version_code" to version.json(), "current_supported" to JsonBoolean(version in 1..100),
                "supported_client_versions" to jsonObject("minimum" to 1L.json(), "maximum" to 100L.json()),
                "release" to (appUpdateRelease?.takeIf { it.versionCode > version }?.document?.root ?: JsonNull))))
            return if (holdAppUpdateMetadata) reply.setBodyDelay(2, java.util.concurrent.TimeUnit.SECONDS) else reply
        }
        if (pushMode && path == "/v1/push/capabilities") return resourceResponse(data(jsonObject("v" to 1L.json(), "providers" to JsonArray(listOf(jsonObject("provider" to "fcm".json(), "project_id" to "fixture-project".json(), "package_name" to "cn.edu.ustc.dsh.mobile".json(), "address_kind" to "fid".json()))), "sources" to JsonArray(listOf("approval".json(), "question".json(), "timed_question".json())), "verification" to "provider_challenge".json(), "lease_seconds" to 604800L.json())))
        if (pushMode && path == "/v1/push-bindings") {
            require(request.method == "POST")
            val input = JsonDocument.parse(request.body.readByteArray()).root; input.exactKeys("binding_id", "organization_id", "provider", "address", "revoke_secret_sha256")
            require(input.string("organization_id") == organizationId && input.string("provider") == "fcm")
            val id = Contract.uuid(input.string("binding_id"))
            val previous = pushIntents.putIfAbsent(id, input)
            if (previous == null) { pushStates[id] = "pending"; pushRegistrations.incrementAndGet() } else require(JsonDocument.of(previous).canonicalText() == JsonDocument.of(input).canonicalText())
            pushDeliver?.invoke(mapOf("v" to "1", "kind" to "registration_challenge", "binding_id" to id, "challenge" to pushNonce, "expires_at" to Contract.timestamp(System.currentTimeMillis() + 120_000)))
            return resourceResponse(data(jsonObject("binding" to pushBinding(id))), 201)
        }
        if (pushMode && path.startsWith("/v1/push-bindings/")) {
            val id = path.removePrefix("/v1/push-bindings/").substringBefore('/')
            require(pushIntents.containsKey(id))
            if (path.endsWith("/confirm")) {
                val input = JsonDocument.parse(request.body.readByteArray()).root; input.exactKeys("challenge"); require(input.string("challenge") == pushNonce)
                pushStates[id] = "active"; pushConfirmations.incrementAndGet()
            } else if (path.endsWith("/lease")) require(pushStates[id] == "active") else require(request.method == "GET")
            return resourceResponse(data(jsonObject("binding" to pushBinding(id))))
        }
        if (pushMode && path.startsWith("/v1/notifications/")) {
            if (path.endsWith("/receipts")) return resourceResponse(data(jsonObject("recorded" to JsonBoolean(true))))
            pushReads.incrementAndGet()
            require(path.substringAfterLast('/') == pushNotificationId)
            val reply = resourceResponse(data(jsonObject("reference" to pushReference())))
            return if (holdPushReference) reply.setHeadersDelay(2, java.util.concurrent.TimeUnit.SECONDS) else reply
        }
        if (pushMode && path == "/v1/notifications") return resourceResponse(data(jsonObject("items" to JsonArray(listOf(pushReference())), "cursor" to JsonNull)))
        if (exportMode && (path.startsWith("/v1/file-exports/") || path == "/v1/files/$exportFileId")) {
            require(request.method == "GET")
            if (path.startsWith("/v1/file-exports/") && !exportRequests.containsKey(path.substringAfterLast('/')))
                return resourceResponse(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "access.denied".json())), 403)
            return resourceResponse(data(jsonObject("file" to exportStatus())))
        }
        if (exportMode && path == "/v1/files/$exportFileId/content") {
            require(request.method == "GET" && request.getHeader("Range") == null && request.getHeader("Accept-Encoding") == "identity")
            exportDownloads.incrementAndGet()
            val reply = MockResponse().setHeader("Content-Type", "application/octet-stream").setHeader("Content-Encoding", "identity").setHeader("X-DSH-Content-SHA256", sha256(exportBytes)).setBody(okio.Buffer().write(exportBytes))
            return if (exportSlow) reply.throttleBody(1, 1, java.util.concurrent.TimeUnit.SECONDS) else reply
        }
        if (fileMode && path == "/v1/runtimes/$runtimeId/sessions/$sessionId/files") {
            require(request.method == "POST" && "file.upload" in directoryScope.actions)
            val body = JsonDocument.parse(request.body.readByteArray()).root
            body.exactKeys("request_id", "name", "size_bytes", "sha256")
            val id = Contract.uuid(body.string("request_id"))
            val manifest = FileManifest.parse(JsonObject(body.fields.filterKeys { it != "request_id" }))
            val file = files.values.firstOrNull { it.requestId == id }?.also { require(it.manifest.same(manifest)) }
                ?: FileEntry(UUID.randomUUID().toString(), id, manifest, System.currentTimeMillis()).also { files[it.id] = it; fileRegistrations.incrementAndGet() }
            var reply = jsonObject("file" to fileStatus(file))
            if (!file.committed) reply = reply.with("upload" to jsonObject("url" to "$origin/quarantine/${file.id}?fixture=public".json(), "method" to "PUT".json(),
                "headers" to jsonObject("Content-Type" to "application/octet-stream".json(), "Content-Length" to manifest.sizeBytes.toString().json()),
                "expires_at" to Contract.timestamp(System.currentTimeMillis() + 60_000).json()))
            return resourceResponse(data(reply), 201)
        }
        if (fileMode && path.startsWith("/v1/files/")) {
            val file = files[path.removePrefix("/v1/files/").substringBefore('/')]!!
            if (path.endsWith("/commit")) {
                require(request.method == "POST" && file.uploaded)
                file.committed = true
            } else require(request.method == "GET")
            return resourceResponse(data(jsonObject("file" to fileStatus(file))))
        }
        if (approvalMode && path == "/v1/approvals/${approvalBody.root.string("approval_id")}/decisions") {
            val body = JsonDocument.parse(request.body.readByteArray()).root; body.exactKeys("connection_id", "decision_jws")
            val endpoint = approvalEndpoint.get() ?: error("no current approval connection")
            require(!runtimeOffline && approvalRole == "owner" && body.string("connection_id") == endpoint.id && "approval.decide" in endpoint.scope.actions)
            if (claims.fields["acr"] != "fixture:2".json() || claims.array("amr") != listOf("otp".json()) || System.currentTimeMillis() / 1000 - claims.integer("auth_time", 0) > 60)
                return resourceResponse(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "approval.assurance_required".json())), 403)
            val registered = RegisteredApprovalKey.parse(jsonObject("user_id" to userId.json(), "device_id" to deviceId.json(), "key_version" to 1L.json(), "active" to JsonBoolean(true),
                "public_jwk" to approvalPublic!!, "approval_key_jkt" to approvalJkt!!.json()))
            val signed = ApprovalSignatures.verify(body.string("decision_jws"), registered, approvalBody, System.currentTimeMillis())
            val owner = CommandOwner(accountId, organizationId, config.fingerprint, userId, deviceId)
            SqlCommandJournal.open(context, owner).use { database -> database.approvalDecisions(registered).use { journal ->
                val original = kotlinx.coroutines.runBlocking { journal.list(runtimeId, sessionId).single() }
                require(original.attempts > 0 && original.delivery == ApprovalDecisionDelivery.RECONCILE && original.intent.signed.compact == signed.compact)
            } }
            require(approvalStatus.get() == null || currentApprovalStatus().string("decision_payload_sha256") == signed.payloadSha256)
            if (approvalStatus.get() == null) { approvalWrites.incrementAndGet(); lastApproval.set(signed) }
            var status = currentApprovalStatus().with("decision" to signed.decision.choice.wire.json(), "decision_payload_sha256" to signed.payloadSha256.json(),
                "state" to (if (approvalNativeResult) if (signed.decision.choice == ApprovalChoice.ALLOW_ONCE) "allowed" else "denied" else "decision_received").json())
            if (approvalNativeResult) {
                status = status.with("host_state" to (if (signed.decision.choice == ApprovalChoice.ALLOW_ONCE) "settled" else "denied").json())
                if (signed.decision.choice == ApprovalChoice.ALLOW_ONCE) status = status.with("execution_outcome" to "succeeded".json())
            }
            approvalStatus.set(status); publishApproval.get()?.invoke()
            val reply = resourceResponse(data(jsonObject("status" to status, "delivery" to "forwarded".json())))
            return if (dropApprovalReply) reply.setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST) else reply
        }
        if (path == "/v1/runtimes/$runtimeId/sessions/$sessionId") {
            targetRequests.incrementAndGet()
            if (!allowSessionRead) return resourceResponse(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "access.denied".json())), 403)
            val reply = resourceResponse(data(jsonObject("runtime" to runtimeRow(), "session" to sessionRow(sessionId))))
            return if (holdSessionTarget) reply.setHeadersDelay(2, java.util.concurrent.TimeUnit.SECONDS) else reply
        }
        if (path.startsWith("/v1/runtimes/$runtimeId/sessions/$sessionId/question-answers/")) {
            answerStatusRequests.incrementAndGet()
            val id = path.substringAfterLast('/')
            val status = commandStatuses[id]?.takeIf { questionMode && allowSessionRead && id in questionRequestIds }
            return if (status != null) resourceResponse(data(status)) else resourceResponse(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "access.denied".json())), 403)
        }
        if (path.startsWith("/v1/runtimes/$runtimeId/sessions/") && path.endsWith("/read-access")) {
            val selected=path.substringAfter("/sessions/").substringBefore('/')
            require(selected==sessionId || selected in createdSessions)
            if (!allowSessionRead) return resourceResponse(jsonObject("ok" to JsonBoolean(false), "error" to jsonObject("code" to "access.denied".json())), 403)
            val issued = System.currentTimeMillis()
            return resourceResponse(data(jsonObject("runtime_id" to runtimeId.json(), "session_id" to selected.json(), "workspace_id" to (if(selected in createdSessions) workspaceId.json() else JsonNull), "grant_version" to 7L.json(),
                "issued_at" to java.time.Instant.ofEpochMilli(issued).toString().json(), "expires_at" to java.time.Instant.ofEpochMilli(minOf(issued + 300_000, claims.integer("exp") * 1000)).toString().json())))
        }
        if (path.startsWith("/v1/commands/")) {
            require((chatMode || creationMode || questionMode) && request.requestUrl!!.queryParameter("device_id") == deviceId)
            require(allowCommandStatus)
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
            require(relayScope!!.actions.all { it in setOf("session.read", "message.submit", "session.archive", "session.cancel", "question.answer","command.status", "session.create", "approval.decide", "file.download") })
            if ("file.download" in relayScope!!.actions) require(exportMode)
            if ("approval.decide" in relayScope!!.actions) require(approvalMode && approvalRole == "owner")
            relayProofKey = JWSObject.parse(request.getHeader("DPoP")).header.jwk as ECKey
            relayAccessExpiresAt = claims.integer("exp") * 1000
            ticketScopes.add(relayScope!!)
            ticketRequests.incrementAndGet()
            return resourceResponse(data(jsonObject("ticket" to relayToken.json(), "runtime_id" to body.string("runtime_id").json(), "grant_version" to 7L.json(), "scope" to relayScope!!.json(),
                "expires_at" to java.time.Instant.ofEpochMilli(System.currentTimeMillis() + 30_000).toString().json())), 201)
        }
        if (path == "/v1/runtimes/$runtimeId/sessions") {
            sessionRequests.incrementAndGet()
            require(allowSessionList)
            val rows=listOf(sessionRow(sessionId)) + createdSessions.map(::sessionRow)
            val result = resourceResponse(data(jsonObject("items" to JsonArray(rows))))
            return if (holdSessions) result.setHeadersDelay(2, java.util.concurrent.TimeUnit.SECONDS) else result
        }
        if (path == "/v1/hosts") {
            hostRequests.incrementAndGet()
            if (!allowHostList && !allowSessionList) return resourceResponse(data(jsonObject("items" to JsonArray(emptyList()))))
            return resourceResponse(data(jsonObject("items" to JsonArray(listOf(jsonObject("id" to "44444444-4444-4444-8444-444444444444".json(), "alias" to "夹具电脑".json(), "state" to "active".json()))))))
        }
        require(path == "/v1/runtimes")
        if (!allowHostList && !allowSessionList) return resourceResponse(data(jsonObject("items" to JsonArray(emptyList()))))
        if (bindingMode && (!bindingApproved || bindingConfirmedElsewhere)) return resourceResponse(data(jsonObject("items" to JsonArray(emptyList()))))
        return resourceResponse(data(jsonObject("items" to JsonArray(listOf(runtimeRow())))))
    }
    private fun sessionRow(id: String) = jsonObject("session_id" to id.json(), "workspace_id" to (if (id in createdSessions) workspaceId.json() else JsonNull),
        "state" to (if (id == sessionId && archived) "archived" else "available").json(), "last_persisted_seq" to (if (id in createdSessions) -1L else 2L).json(), "updated_at" to java.time.Instant.now().toString().json())
    private fun runtimeRow() = jsonObject("id" to runtimeId.json(), "host_id" to "44444444-4444-4444-8444-444444444444".json(), "organization_id" to organizationId.json(), "protocol_version" to 1L.json(), "dsh_version" to "0.2.1-rc.2".json(),
        "access" to jsonObject("role" to (if (approvalMode) approvalRole else if (bindingMode) "owner" else if (chatMode || creationMode || questionMode) "operator" else "viewer").json(), "grant_version" to (if (allowSessionRead) 7L else 8L).json(), "scope" to directoryScope.json()))

    private fun pushBinding(id: String) = jsonObject("binding_id" to id.json(), "state" to pushStates[id]!!.json(), "challenge_expires_at" to Contract.timestamp(System.currentTimeMillis() + 120_000).json(), "expires_at" to Contract.timestamp(System.currentTimeMillis() + 3600_000).json())
    private fun pushReference() = jsonObject("notification_id" to pushNotificationId.json(), "binding_id" to pushStates.entries.single { it.value == "active" }.key.json(), "kind" to pushReferenceKind.json(),
        "reference_id" to (pushReferenceId ?: when (pushReferenceKind) { "question" -> ordinaryQuestionId; "timed_question" -> timedQuestionId; else -> approvalBody.root.string("approval_id") }).json(), "runtime_id" to runtimeId.json(), "runtime_epoch" to approvalBody.root["runtime_epoch"], "session_id" to sessionId.json(), "state" to pushReferenceState.json(),
        "availability" to pushReferenceAvailability.json(), "expires_at" to Contract.timestamp(System.currentTimeMillis() + 120_000).json())
    private fun exportStatus(): JsonObject {
        val now = System.currentTimeMillis()
        return ExportManifest("APK export.txt", exportBytes.size.toLong(), sha256(exportBytes)).json().with("file_id" to exportFileId.json(), "runtime_id" to runtimeId.json(), "session_id" to sessionId.json(), "direction" to "from_host".json(),
            "state" to "clean".json(), "created_at" to Contract.timestamp(now - 1000).json(), "upload_expires_at" to Contract.timestamp(now + 300_000).json(), "expires_at" to Contract.timestamp(now + 600_000).json())
    }
    private fun fileStatus(file: FileEntry): JsonObject {
        val state = if (file.committed) fileState else "uploading"
        var status = file.manifest.json().with("file_id" to file.id.json(), "runtime_id" to runtimeId.json(), "session_id" to sessionId.json(), "direction" to "to_host".json(),
            "state" to state.json(), "created_at" to Contract.timestamp(file.createdAt).json(), "upload_expires_at" to Contract.timestamp(file.createdAt + 300_000).json(),
            "expires_at" to Contract.timestamp(file.createdAt + 600_000).json())
        if (state == "clean") status = status.with("delivery" to when {
            file.messageId != null -> jsonObject("state" to "bound".json(), "request_id" to file.messageId!!.json(), "command_state" to "agent_queued".json())
            fileReady -> jsonObject("state" to "ready".json(), "expires_at" to Contract.timestamp(System.currentTimeMillis() + 4000).json())
            else -> jsonObject("state" to "waiting".json())
        })
        return status
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
    fun replaceQuestions() {publishQuestions.get()?.invoke()}

    fun seed(registering: Boolean = false, refreshing: Boolean = false, ttlSeconds: Long = 120) {
        val now = System.currentTimeMillis()
        val ledger = PendingKeyLedger(context, ledgerName); ledger.add(reference)
        DeviceKeyStore(context).use { owner ->
            val proof = owner.create(reference.scope(), DeviceKeyPurpose.PROOF, 1)
            val approval = owner.create(reference.scope(), DeviceKeyPurpose.APPROVAL, 1)
            proofJkt = proof.thumbprint; approvalJkt = approval.thumbprint; approvalPublic = approval.publicJwk; active = true
            val attempt = PendingLogin(OidcDiscovery.parse(JsonDocument.of(discovery()).canonicalBytes(), config), proof.thumbprint, now)
            val exchange = attempt.acceptCallback(LoginConfiguration.REDIRECT_URI + "?state=${attempt.state}&code=seed", now)
            val session = TokenVerifier.authorizationCodeResponse(JsonDocument.of(tokenReply(proof.thumbprint, subject, attempt.nonce, ttlSeconds)).canonicalBytes(), exchange, IssuerKeys.parse(JsonDocument.of(jsonObject("keys" to JsonArray(listOf(JsonDocument.parse(issuerKey.toPublicJWK().toJSONString()).root)))).canonicalBytes()), System.currentTimeMillis())
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
