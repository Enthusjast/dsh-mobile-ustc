package cn.edu.ustc.dsh.mobile

import android.content.Context
import android.net.Uri
import androidx.core.net.toUri
import androidx.biometric.BiometricPrompt
import androidx.lifecycle.ViewModel
import cn.edu.ustc.dsh.auth.*
import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.keystore.*
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.data.SqlCommandJournal
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.ResponseTypeValues
import java.io.FileNotFoundException
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

enum class HomePhase { LOADING, UNCONFIGURED, INVALID_CONFIGURATION, SIGNED_OUT, RECOVERING, RECOVERY_ERROR, REAUTHENTICATE, RENEWING, CLEARING, STARTING, BROWSER, EXCHANGING, ENROLL, PREPARING, AUTHENTICATING, REGISTERING, RECONCILING, REGISTRATION_UNKNOWN, READY }
class BrowserLaunch(val id: Long, val uri: Uri)
class BiometricLaunch(val id: Long, val operation: AuthenticatedKeyOperation<*>, val title: String = "确认登记此设备", val subtitle: String = "将这部手机的独立密钥登记到学校账号")
class DocumentPickLaunch(val id: String)
class ExportSaveLaunch(val id: String, val name: String) { override fun toString() = "ExportSaveLaunch" }
class MessageDraft(val text: String, val mode: String, val runtimeId: String, val sessionId: String) { override fun toString() = "MessageDraft" }
enum class ApprovalUiStage { IDLE, PREPARING, AUTHENTICATING, SENDING }
data class RuntimeRow(val id: String, val hostId: String, val version: String, val hostAlias: String, val access: RuntimeDirectoryEntry? = null)
data class HomeState(
    val phase: HomePhase = HomePhase.LOADING, val issuer: String = "", val error: String? = null,
    val subject: String = "", val deviceId: String = "", val runtimes: List<RuntimeRow> = emptyList(),
    val browser: BrowserLaunch? = null, val biometric: BiometricLaunch? = null, val authenticationId: Long? = null,
    val securitySetupRequired: Boolean = false, val refreshing: Boolean = false, val deviceName: String? = null,
    val selectedRuntimeId: String? = null, val selectedSessionId: String? = null,
    val sessions: List<SessionDirectoryEntry> = emptyList(), val loadingSessions: Boolean = false, val sessionError: String? = null,
    val reader: SessionReadState? = null,
    val exports: SessionExportState? = null, val exportSavePicker: ExportSaveLaunch? = null, val exportSaving: Boolean = false, val exportSaved: Boolean = false, val exportSaveError: String? = null, val exportBytes: Long = 0,
    val uploads: SessionUploadState? = null, val documentPicker: DocumentPickLaunch? = null, val composerRestore: MessageDraft? = null,
    val binding: HostBindingState? = null, val pendingBindingId: String? = null,
    val outbox: CommandOutboxState? = null, val commandError: String? = null, val submitting: Boolean = false, val composerRevision: Long = 0,
    val creation: SessionCreationState? = null,
    val approvals: ApprovalClientState? = null, val reviewingApprovalId: String? = null, val approvalStage: ApprovalUiStage = ApprovalUiStage.IDLE, val approvalError: String? = null,
)

internal class LoginEnvironment(
    val configuration: () -> ByteArray,
    val storageSlot: String = "active",
    val ledgerName: String = "pending_device_keys",
    val now: () -> Long = System::currentTimeMillis,
    val refreshLeadMillis: Long = 30_000,
    val minimumValidityMillis: Long = 60_000,
    val approvalPromptMillis: Long = MAX_DECISION_AGE_MS,
) { init { require(approvalPromptMillis in 1..MAX_DECISION_AGE_MS) } }

@Singleton
class LoginController internal constructor(private val context: Context, private val http: LoginHttp, private val environment: LoginEnvironment) : AutoCloseable {
    @Inject constructor(@ApplicationContext context: Context, http: LoginHttp) : this(context, http, LoginEnvironment({ context.assets.open("deployment.json").use { it.readBytes() } }))

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val mutable = MutableStateFlow(HomeState())
    val state: StateFlow<HomeState> = mutable.asStateFlow()
    @Volatile private var generation = 0L
    private val persistence = AccountPersistence(context, environment.storageSlot, environment.ledgerName) { it == generation && scope.isActive }
    private var configuration: LoginConfiguration? = null
    private var nextAuthenticationId = 0L
    private var job: Job? = null
    private var deadline: Job? = null
    private var reference: ScopeReference? = null
    private var owner: DeviceKeyStore? = null
    private var proof: DeviceKeyHandle? = null
    private var approval: DeviceKeyHandle? = null
    private var checkpoint: AccountCheckpoint? = null
    private var pending: PendingLogin? = null
    private var session: LoginSession? = null
    private var api: RemoteApi? = null
    private var registration: RemoteApi.RegistrationRequest? = null
    private var operation: AuthenticatedKeyOperation<DeviceRegistrationProof>? = null
    private var cleanupPending = false
    private var foreground = false
    private var navigationGeneration = 0L
    private var navigationJob: Job? = null
    private var readerJob: Job? = null
    private var reader: SessionReader? = null
    private var desired: Pair<String, String?>? = null
    private var creationDesired: String? = null
    private var creationReturnsToRuntime = false
    private var creationFlow: SessionCreationFlow? = null
    private var creationCollector: Job? = null
    private var commandJournal: SqlCommandJournal? = null
    private var commandCollector: Job? = null
    private var uploads: SessionUploads? = null
    private var uploadCollector: Job? = null
    private var exportCollector: Job? = null
    private var exportSaveJob: Job? = null
    private class PendingExportSave(val id: String, val generation: Long, val runtime: String, val session: String, val request: String, val file: RemoteExportStatus) { var result: Uri? = null }
    private var pendingExportSave: PendingExportSave? = null
    private val abandonedSavePickers = linkedSetOf<String>()
    private class PendingDocument(val id: String, val generation: Long, val runtime: String, val session: String, val resume: String?, val draft: MessageDraft) { var result: Uri? = null }
    private var pendingDocument: PendingDocument? = null
    private var commandJob: Job? = null
    private var questionScope: CoroutineScope?=null
    private var approvalCollector: Job? = null
    private var approvalActionJob: Job? = null
    private var approvalTimeout: Job? = null
    private var approvalJournal: ApprovalDecisionJournal? = null
    private var approvalPreparingHandle: ApprovalReviewHandle? = null
    private var approvalPrepared: PreparedApprovalSignature? = null
    private var approvalActionGeneration = 0L
    private class ApprovalAuthentication(val id: Long, val stamp: Long, val view: Long, val action: Long, val client: SessionApprovalClient, val handle: ApprovalReviewHandle,
        val prepared: PreparedApprovalSignature, val operation: ApprovalKeyOperation)
    private var approvalAuthentication: ApprovalAuthentication? = null
    private var binding: HostBindingFlow? = null
    private var bindingCollector: Job? = null
    private var bindingGeneration = 0L
    private var pendingBindingId: String? = null
    private var resumeBindingView = false
    private enum class Source { BROWSER, CACHE, REFRESH }

    init {
        work {
            try { configuration = withContext(Dispatchers.IO) { LoginConfiguration.parse(environment.configuration()) } }
            catch (_: FileNotFoundException) { mutable.value = HomeState(HomePhase.UNCONFIGURED); return@work }
            catch (_: Exception) { mutable.value = HomeState(HomePhase.INVALID_CONFIGURATION); return@work }
            restore(generation)
        }
    }

    private fun work(block: suspend CoroutineScope.() -> Unit) {
        // Assign before execution: an immediate failure can start cleanup as another task.
        val next = scope.launch(start = CoroutineStart.LAZY, block = block)
        job = next
        next.start()
    }

    private fun current(stamp: Long) { if (generation != stamp || !scope.isActive) throw CancellationException() }
    private fun now() = environment.now()

    /** Capture returned owners inside NonCancellable so cancellation cannot drop an unclosed key owner. */
    private suspend fun open(stamp: Long, action: suspend () -> OpenAccount?): Boolean {
        var opened: OpenAccount? = null
        try {
            withContext(NonCancellable) { opened = action() }
            current(stamp)
            val result = opened ?: return false
            owner?.close()
            reference = result.reference; owner = result.owner; proof = result.proof; approval = result.approval
            checkpoint = result.checkpoint
            opened = null
            return true
        } finally { opened?.close() }
    }

    private suspend fun persist(next: AccountCheckpoint, stamp: Long) {
        persistence.save(next, stamp)
        current(stamp)
        checkpoint = next
    }
    private suspend fun <T> beginKeyOperation(stamp: Long, begin: () -> AuthenticatedKeyOperation<T>): AuthenticatedKeyOperation<T> {
        var opened: AuthenticatedKeyOperation<T>? = null
        try {
            withContext(NonCancellable + Dispatchers.Default) { opened = begin() }
            current(stamp)
            return opened!!.also { opened = null }
        } finally { opened?.close() }
    }

    private suspend fun restore(stamp: Long) {
        val config = configuration ?: return
        mutable.value = HomeState(HomePhase.RECOVERING, config.issuer)
        try {
            if (!open(stamp) { persistence.load(config, stamp, now()) }) {
                mutable.value = HomeState(HomePhase.SIGNED_OUT, config.issuer)
                return
            }
            val saved = checkpoint!!
            if (saved.refresh != RefreshCheckpoint.READY) { showReauthentication("login.reauthentication"); return }
            val discovery = http.discovery(config)
            val verified = try { TokenVerifier.revalidateStored(saved.session, config, http.keys(discovery), now()) }
            catch (error: LoginException) {
                if (saved.session.hasRefreshToken()) {
                    if (renewCredential(stamp, discovery)) install(session!!, Source.REFRESH, stamp)
                    return
                }
                requireReauthentication(stamp, "login.reauthentication")
                return
            }
            install(verified, Source.CACHE, stamp)
        } catch (error: CancellationException) { throw error }
        catch (error: Exception) { handle(error, stamp) }
    }

    fun login() {
        val config = configuration ?: return
        if (mutable.value.phase == HomePhase.RECOVERY_ERROR) {
            if (cleanupPending) { clearAccount(null); return }
            val stamp = fence(closeKeys = true)
            checkpoint = null
            work { restore(stamp) }
            return
        }
        if (mutable.value.phase !in setOf(HomePhase.SIGNED_OUT, HomePhase.REAUTHENTICATE)) return
        val saved = checkpoint
        val forceAuthentication = mutable.value.error == "approval.assurance_required"
        val stamp = fence(closeKeys = false)
        mutable.value = HomeState(HomePhase.STARTING, config.issuer)
        work {
            try {
                if (saved != null) {
                    // A cancelled/restarted browser reauthentication must not resume an old rotating grant.
                    persist(saved.requireReauthentication(now()), stamp)
                    if (proof == null) open(stamp) { persistence.load(config, stamp, now()) }
                }
                val discovery = http.discovery(config)
                if (saved == null) {
                    val local = ScopeReference(UUID.randomUUID().toString(), config.organizationId)
                    open(stamp) { persistence.createProof(local, stamp) }
                }
                current(stamp)
                val attempt = PendingLogin(discovery, proof!!.thumbprint, now())
                pending = attempt
                val browserRequest = AuthorizationRequest.Builder(
                    AuthorizationServiceConfiguration(discovery.authorizationEndpoint.toUri(), discovery.tokenEndpoint.toUri()),
                    config.clientId, ResponseTypeValues.CODE, config.redirectUri.toUri(),
                ).setScopes(config.scopes).setState(attempt.state).setNonce(attempt.nonce)
                    .setCodeVerifier(attempt.verifierForAuthorizationRequest(), attempt.codeChallenge, "S256")
                    .setAdditionalParameters(mapOf("resource" to config.resource, "dpop_jkt" to proof!!.thumbprint))
                    .apply { if (forceAuthentication) setPrompt("login") }.build()
                mutable.value = HomeState(HomePhase.BROWSER, config.issuer, browser = BrowserLaunch(stamp, browserRequest.toUri()))
                deadline = scope.launch { delay(600_000); if (generation == stamp && pending != null) browserFailed("login.expired") }
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { if (generation == stamp) browserFailed(code(error)) }
        }
    }

    fun browserOpened(id: Long) { if (mutable.value.browser?.id == id) mutable.value = mutable.value.copy(browser = null) }
    fun browserUnavailable() { if (pending != null) browserFailed("login.browser_unavailable") }

    fun callback(uri: String) {
        val attempt = pending ?: return
        val stamp = generation
        val exchange = try { attempt.acceptCallback(uri, now()) }
        catch (error: LoginException) {
            if (error.failure in setOf(LoginFailure.INVALID_RESPONSE, LoginFailure.IDENTITY)) mutable.value = mutable.value.copy(error = "login.invalid_callback")
            else browserFailed(code(error))
            return
        }
        pending = null; deadline?.cancel()
        mutable.value = mutable.value.copy(phase = HomePhase.EXCHANGING, browser = null, error = null)
        work {
            try {
                val signer = proof!!.proofSigner()
                val raw = http.tokenEndpoint(attempt.discovery, signer).exchange(exchange)
                val verified = TokenVerifier.authorizationCodeResponse(raw, exchange, http.keys(attempt.discovery), now())
                current(stamp)
                val old = checkpoint
                if (old != null && verified.subject != old.session.subject) { browserFailed("login.account_mismatch"); return@work }
                install(verified, Source.BROWSER, stamp)
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) {
                if (generation == stamp) {
                    if (checkpoint != null && session != null) handle(error, stamp)
                    else if (authorityLost(error)) clearAccount(code(error)) else browserFailed(code(error))
                }
            }
        }
    }

    private suspend fun install(verified: LoginSession, source: Source, stamp: Long) {
        val config = configuration!!
        val resource = http.resource(config, verified, proof!!.proofSigner())
        val identity = resource.me()
        current(stamp)
        val saved = checkpoint
        if (saved != null && identity.userId != saved.userId) throw RemoteRequestException("auth.identity_mismatch")
        val next = when (source) {
            Source.BROWSER -> saved?.authorized(verified, identity.userId, now()) ?: AccountCheckpoint.create(reference!!.account, config, identity.userId, verified, now())
            Source.CACHE -> saved!!.revalidated(verified, identity.userId, now())
            Source.REFRESH -> saved!!
        }
        session = verified; api = resource
        try { persist(next, stamp) }
        catch (error: VaultException) {
            // A new phone may still need the user's secure-lock setup. Never POST enrollment until saved.
            if (saved == null && source == Source.BROWSER && error.failure == VaultFailure.LOCK_REQUIRED) {
                checkpoint = next
                showEnrollment(code(error), setup = true)
                scheduleRenewal(stamp, verified)
                return
            }
            throw error
        }
        reconcileAccount(stamp)
    }

    private suspend fun reconcileAccount(stamp: Long) {
        current(stamp)
        val saved = checkpoint!!
        val key = approval
        if (key != null) {
            val device = api!!.currentDevice(PublicProofKey(key.publicJwk))
            current(stamp)
            if (device != null) {
                persist(saved.deviceAccepted(device.deviceId, device.keyVersion, now()), stamp)
                mutable.value = HomeState(HomePhase.READY, session!!.issuer, subject = session!!.subject, deviceId = device.deviceId)
                scheduleRenewal(stamp, session!!)
                fetchDirectory(stamp)
                return
            }
        }
        persist(saved.enrollmentNotFound(now()), stamp)
        showEnrollment()
        scheduleRenewal(stamp, session!!)
    }

    private fun showEnrollment(error: String? = null, setup: Boolean = false) {
        mutable.value = HomeState(HomePhase.ENROLL, configuration!!.issuer, error, subject = checkpoint!!.session.subject,
            securitySetupRequired = setup, deviceName = checkpoint!!.deviceName)
    }

    fun register(name: String) {
        if (mutable.value.phase == HomePhase.REGISTRATION_UNKNOWN) {
            val stamp = generation
            mutable.value = mutable.value.copy(phase = HomePhase.RECONCILING, error = null)
            work { try { reconcileAccount(stamp) } catch (error: CancellationException) { throw error } catch (error: Exception) { registrationUnknown(error, stamp) } }
            return
        }
        if (mutable.value.phase != HomePhase.ENROLL) return
        if (session!!.accessExpiresAt - now() <= environment.minimumValidityMillis) { renew(); return }
        val stamp = generation
        mutable.value = mutable.value.copy(phase = HomePhase.PREPARING, error = null, securitySetupRequired = false)
        work {
            try {
                // The credential record exists before any enrollment effect. Reuse an interrupted local key creation.
                persist(checkpoint!!, stamp)
                val local = approval ?: persistence.approval(owner!!, reference!!, stamp)
                current(stamp); approval = local
                persist(checkpoint!!.withApprovalKey(local.thumbprint, now()), stamp)
                val existing = api!!.currentDevice(PublicProofKey(local.publicJwk))
                current(stamp)
                if (existing != null) { reconcileAccount(stamp); return@work }
                if (checkpoint!!.enrollment != EnrollmentCheckpoint.PENDING) persist(checkpoint!!.enrollmentNotFound(now()), stamp)
                val actualName = checkpoint!!.deviceName ?: name.trim()
                val request = api!!.prepareRegistration(PublicProofKey(local.publicJwk), actualName)
                current(stamp)
                registration = request
                operation = beginKeyOperation(stamp) { local.beginRegistration(request.signatureRequest) }
                current(stamp)
                val id = ++nextAuthenticationId
                mutable.value = mutable.value.copy(phase = HomePhase.AUTHENTICATING, authenticationId = id, biometric = BiometricLaunch(id, operation!!), deviceName = actualName)
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) {
                if (generation == stamp) {
                    discardRegistration()
                    if (authorityLost(error)) clearAccount(code(error))
                    else showEnrollment(code(error), setup = error is DeviceCryptoException && error.failure in setOf(DeviceCryptoFailure.LOCK_REQUIRED, DeviceCryptoFailure.BIOMETRIC_REQUIRED) || error is VaultException && error.failure == VaultFailure.LOCK_REQUIRED)
                }
            }
        }
    }

    fun promptOpened(id: Long) { if (mutable.value.biometric?.id == id) mutable.value = mutable.value.copy(biometric = null) }
    fun authenticated(id: Long, result: BiometricPrompt.AuthenticationResult) {
        approvalAuthentication?.takeIf { it.id == id }?.let { authenticatedApproval(it, result); return }
        if (mutable.value.authenticationId != id) return
        val active = operation ?: return
        val request = registration ?: return
        if (runCatching { result.cryptoObject?.signature === active.cryptoObject.signature }.getOrDefault(false).not()) return
        val stamp = generation
        operation = null; registration = null
        val name = mutable.value.deviceName!!
        mutable.value = mutable.value.copy(phase = HomePhase.REGISTERING, biometric = null, authenticationId = null)
        work {
            var posted = false
            try {
                val signed = withContext(Dispatchers.Default) { active.finish(result) }
                current(stamp)
                persist(checkpoint!!.beginEnrollment(name, now()), stamp)
                current(stamp); posted = true
                val device = request.submit(signed)
                current(stamp)
                persist(checkpoint!!.deviceAccepted(device.deviceId, device.keyVersion, now()), stamp)
                reconcileAccount(stamp)
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) {
                if (generation == stamp) {
                    if (authorityLost(error)) clearAccount(code(error))
                    else if (posted) {
                        mutable.value = mutable.value.copy(phase = HomePhase.RECONCILING)
                        try { reconcileAccount(stamp) } catch (cancelled: CancellationException) { throw cancelled } catch (failure: Exception) { registrationUnknown(failure, stamp) }
                    } else showEnrollment(code(error))
                }
            } finally { active.close(); request.cancel() }
        }
    }

    private fun registrationUnknown(error: Exception, stamp: Long) {
        if (generation != stamp) return
        if (authorityLost(error)) clearAccount(code(error))
        else mutable.value = HomeState(HomePhase.REGISTRATION_UNKNOWN, configuration!!.issuer, "device.registration_unknown", subject = checkpoint!!.session.subject, deviceName = checkpoint!!.deviceName)
    }

    fun authenticationCancelled(id: Long) {
        if (approvalAuthentication?.id == id) { abortApprovalAuthentication("approval.authentication_cancelled"); return }
        if (mutable.value.authenticationId != id) return
        discardRegistration()
        if (mutable.value.phase == HomePhase.AUTHENTICATING) showEnrollment("login.authentication_cancelled")
    }
    private fun discardRegistration() { operation?.close(); registration?.cancel(); operation = null; registration = null }

    private fun scheduleRenewal(stamp: Long, verified: LoginSession) {
        deadline?.cancel()
        deadline = scope.launch {
            delay((verified.accessExpiresAt - now() - environment.refreshLeadMillis).coerceAtLeast(1000))
            if (generation == stamp && session === verified) renew()
        }
    }
    private fun renew() {
        if (checkpoint == null || session == null) return
        val stamp = fence(closeKeys = false, preserveSelection = true)
        mutable.value = HomeState(HomePhase.RENEWING, configuration!!.issuer, subject = checkpoint!!.session.subject)
        work {
            try { if (renewCredential(stamp)) install(session!!, Source.REFRESH, stamp) }
            catch (error: CancellationException) { throw error }
            catch (error: Exception) { handle(error, stamp) }
        }
    }

    private suspend fun renewCredential(stamp: Long, known: OidcDiscovery? = null): Boolean {
        val config = configuration!!
        val saved = checkpoint!!
        if (saved.refresh != RefreshCheckpoint.READY || !saved.session.hasRefreshToken()) { requireReauthentication(stamp, "login.reauthentication"); return false }
        val discovery = known ?: http.discovery(config)
        persist(saved.beginRefresh(now()), stamp)
        val refreshing = checkpoint!!
        try {
            val requested = now()
            val raw = http.tokenEndpoint(discovery, proof!!.proofSigner()).refresh(refreshing.session)
            val verified = TokenVerifier.refreshResponse(raw, refreshing.session, config, http.keys(discovery), requested, now())
            current(stamp)
            persist(refreshing.refreshed(verified, now()), stamp)
            session = verified
            return true
        } catch (error: CancellationException) { throw error }
        catch (error: Exception) {
            current(stamp)
            // The durable marker already prevents replay if this follow-up write also fails.
            runCatching { persist(refreshing.requireReauthentication(now()), stamp) }
            showReauthentication("login.reauthentication")
            return false
        }
    }

    private suspend fun requireReauthentication(stamp: Long, error: String) {
        checkpoint?.let { persist(it.requireReauthentication(now()), stamp) }
        current(stamp); showReauthentication(error)
    }
    private fun showReauthentication(error: String?) {
        retireNavigation(false)
        retireBinding(false)
        deadline?.cancel(); pending?.cancel(); pending = null; discardRegistration()
        session = null; api = null
        mutable.value = HomeState(HomePhase.REAUTHENTICATE, configuration!!.issuer, error, subject = checkpoint?.session?.subject ?: "")
    }
    private fun browserFailed(error: String) {
        if (checkpoint == null) clearAccount(error)
        else { fence(closeKeys = false); showReauthentication(error) }
    }

    fun refresh() {
        if (mutable.value.phase != HomePhase.READY || mutable.value.refreshing) return
        if (session!!.accessExpiresAt - now() <= environment.minimumValidityMillis) { renew(); return }
        val stamp = generation
        work { try { fetchDirectory(stamp) } catch (error: CancellationException) { throw error } catch (error: Exception) { handle(error, stamp) } }
    }
    private suspend fun fetchDirectory(stamp: Long) {
        mutable.value = mutable.value.copy(refreshing = true)
        try {
            val resource = api!!
            val identity = resource.me()
            current(stamp)
            if (identity.userId != checkpoint!!.userId) throw RemoteRequestException("auth.identity_mismatch")
            val hosts = resource.hosts()
            current(stamp)
            if (hosts["ok"] != JsonBoolean(true)) throw RemoteRequestException("network.invalid_response")
            val names = hosts.obj("data").array("items").associate { item ->
                val host = item as? JsonObject ?: throw RemoteRequestException("network.invalid_response")
                val alias = Contract.boundedText(host.string("alias"), 640)
                if (alias.codePointCount(0, alias.length) > 160) throw RemoteRequestException("network.invalid_response")
                Contract.uuid(host.string("id")) to alias
            }
            val response = resource.runtimes()
            current(stamp)
            if (response["ok"] != JsonBoolean(true)) throw RemoteRequestException("network.invalid_response")
            val items = response.obj("data").array("items").mapNotNull { item ->
                val row = item as? JsonObject ?: throw RemoteRequestException("network.invalid_response")
                val access = RuntimeDirectoryEntry.parse(row)
                if (access.organizationId != null && access.organizationId != configuration!!.organizationId) return@mapNotNull null
                RuntimeRow(access.id, access.hostId, access.dshVersion, names[access.hostId] ?: "已授权的电脑", access)
            }
            val selectedContext = creationDesired ?: desired?.first
            val oldAccess = mutable.value.runtimes.firstOrNull { it.id == selectedContext }?.access
            val removedRead = mutable.value.runtimes.filter { old ->
                old.access?.scope?.actions?.contains("session.read") == true && items.firstOrNull { it.id == old.id }?.access?.scope?.actions?.contains("session.read") != true
            }.map { it.id }
            mutable.value = mutable.value.copy(runtimes = items, error = null)
            val activeAccess = items.firstOrNull { it.id == selectedContext }?.access
            if (oldAccess != null && activeAccess != null && (oldAccess.role != activeAccess.role || oldAccess.grantVersion != activeAccess.grantVersion || activeAccess.scope?.let { oldAccess.scope?.same(it) } != true)) retireNavigation(true)
            if (removedRead.isNotEmpty()) {
                val saved = checkpoint!!
                val owner = CommandOwner(saved.accountId, saved.organizationId, configuration!!.fingerprint, saved.userId, saved.deviceId!!)
                if (mutable.value.selectedRuntimeId in removedRead) {
                    retireNavigation(false)
                    mutable.value = mutable.value.copy(selectedRuntimeId = null, selectedSessionId = null, reader = null, outbox = null, commandError = null, submitting = false)
                }
                for (runtime in removedRead) persistence.revokeCommands(owner, runtime, stamp)
                current(stamp)
            }
            val dataOwner = checkpoint!!.let { CommandOwner(it.accountId, it.organizationId, configuration!!.fingerprint, it.userId, it.deviceId!!) }
            try {
                val scopes = items.mapNotNull { item -> item.access?.takeIf { it.protocolVersion==1L && it.expiresAt?.let { expiry -> expiry>now() }!=false }?.scope?.let { item.id to it } }.toMap()
                val approvalRuntimes = items.filter { it.access?.role == "owner" }.map { it.id }.toSet()
                persistence.retainHistory(dataOwner, scopes, stamp, approvalRuntimes)
                current(stamp)
            } catch (error: CancellationException) { throw error }
            catch (_: CommandDataException) { current(stamp) /* Online reading remains available if local data cannot open. */ }
            val pendingCreation=creationDesired
            val selection = desired
            if(pendingCreation!=null) {
                val entry=items.firstOrNull { it.id==pendingCreation }?.access
                if(entry?.creationScope()==null || entry.organizationId!=configuration!!.organizationId) {
                    retireNavigation(false)
                    mutable.value=mutable.value.copy(selectedRuntimeId=null,selectedSessionId=null,sessions=emptyList(),reader=null,creation=null)
                } else if(foreground && creationFlow==null) openCreationInternal(pendingCreation,true)
            } else if (selection != null) {
                val entry = items.firstOrNull { it.id == selection.first }?.access
                if (entry?.canList() != true || entry.organizationId != configuration!!.organizationId) {
                    retireNavigation(false)
                    mutable.value = mutable.value.copy(selectedRuntimeId = null, selectedSessionId = null, sessions = emptyList(), reader = null, loadingSessions = false, sessionError = "access.denied")
                } else if (foreground && (mutable.value.selectedRuntimeId == null || oldAccess?.grantVersion != entry.grantVersion || oldAccess?.scope?.same(entry.scope!!) != true)) navigateRuntime(selection.first, selection.second)
            }
            mutable.value = mutable.value.copy(pendingBindingId = pendingBindingId)
            if (foreground && resumeBindingView && binding == null) {
                resumeBindingView = false
                pendingBindingId?.let(::openBinding)
            }
        } finally { if (generation == stamp) mutable.value = mutable.value.copy(refreshing = false) }
    }

    private fun retireNavigation(keepDesired: Boolean) {
        navigationGeneration++; navigationJob?.cancel(); navigationJob = null; readerJob?.cancel(); readerJob = null
        commandJob?.cancel(); commandJob = null; commandCollector?.cancel(); commandCollector = null
        uploadCollector?.cancel(); uploadCollector = null; uploads?.close(); uploads = null
        exportCollector?.cancel(); exportCollector = null; exportSaveJob?.cancel(); exportSaveJob = null
        if (!keepDesired || pendingExportSave?.let { it.generation != generation || desired != (it.runtime to it.session) } == true) {
            pendingExportSave?.let { pending ->
                if (pending.result == null) { abandonedSavePickers += pending.id; while (abandonedSavePickers.size > 32) abandonedSavePickers.remove(abandonedSavePickers.first()) }
                else pending.result?.let { uri -> scope.launch(Dispatchers.IO) { discardExportDocument(context, uri) } }
            }
            pendingExportSave = null
        }
        if (!keepDesired || pendingDocument?.let { it.runtime != desired?.first || it.session != desired?.second } == true) { pendingDocument = null }
        if (!keepDesired || mutable.value.composerRestore?.let { desired != (it.runtimeId to it.sessionId) } == true) mutable.value = mutable.value.copy(composerRestore = null)
        abortApprovalAuthentication(null)
        approvalCollector?.cancel(); approvalCollector = null; approvalActionJob?.cancel(); approvalActionJob = null
        questionScope?.cancel();questionScope=null
        reader?.close(); reader = null
        approvalJournal?.close(); approvalJournal = null
        creationCollector?.cancel(); creationCollector=null; creationFlow?.close(); creationFlow=null
        commandJournal?.close(); commandJournal = null
        mutable.value = mutable.value.copy(outbox = null, uploads = null, exports = null, exportSaving = false, exportSaved = false, exportSaveError = null, exportBytes = 0, exportSavePicker = mutable.value.exportSavePicker.takeIf { pendingExportSave != null }, documentPicker = if (pendingDocument == null) null else mutable.value.documentPicker, commandError = null, submitting = false, creation=null, approvals=null, reviewingApprovalId=null, approvalError=null, approvalStage=ApprovalUiStage.IDLE)
        if (!keepDesired) { desired = null; creationDesired=null }
    }
    fun foreground(active: Boolean) {
        if (foreground == active) return
        foreground = active
        binding?.foreground(active)
        if (!active) {
            retireNavigation(true)
            mutable.value = mutable.value.copy(reader = mutable.value.reader?.copy(phase = SessionReadPhase.CLOSED, window = null, questions = SessionQuestionState()), loadingSessions = false, binding = binding?.state?.value,
                outbox = null, commandError = null, submitting = false, composerRevision = mutable.value.composerRevision + 1, composerRestore = pendingDocument?.draft)
        } else if (mutable.value.phase == HomePhase.READY && binding == null) {
            if (resumeBindingView) { resumeBindingView = false; pendingBindingId?.let(::openBinding) }
            else if(creationDesired!=null) openCreationInternal(creationDesired!!,true)
            else desired?.let { navigateRuntime(it.first, it.second) }
        }
    }
    private fun navigation(block: suspend CoroutineScope.() -> Unit) {
        val task = scope.launch(start = CoroutineStart.LAZY, block = block); navigationJob = task; task.start()
    }
    fun openRuntime(id: String) { creationDesired=null; navigateRuntime(id, null) }
    fun openCreation(id: String) = openCreationInternal(id,false)
    private fun openCreationInternal(id: String, restoring: Boolean) {
        if(!foreground || mutable.value.phase!=HomePhase.READY || binding!=null) return
        val row=mutable.value.runtimes.firstOrNull { it.id==id }?.access ?: return
        val allowed=row.creationScope() ?: return
        if(row.organizationId!=configuration!!.organizationId) return
        if(!restoring) creationReturnsToRuntime=mutable.value.selectedRuntimeId==id && mutable.value.selectedSessionId==null
        creationDesired=id; desired=null
        if(session!!.accessExpiresAt-now()<=environment.minimumValidityMillis) { renew(); return }
        retireNavigation(true)
        val stamp=generation; val view=navigationGeneration; val resource=api!!; val saved=checkpoint!!
        val dataOwner=CommandOwner(saved.accountId,saved.organizationId,configuration!!.fingerprint,saved.userId,saved.deviceId!!)
        mutable.value=mutable.value.copy(selectedRuntimeId=id,selectedSessionId=null,sessions=emptyList(),loadingSessions=false,sessionError=null,reader=null,creation=SessionCreationState())
        navigation {
            var database: SqlCommandJournal?=null
            try {
                withContext(NonCancellable) { database=persistence.commands(dataOwner,stamp) }
                current(stamp); if(view!=navigationGeneration) return@navigation
                val opened=resource.sessionCreator(saved.deviceId!!,id,allowed,database!!,scope)
                commandJournal=database; database=null; creationFlow=opened
                creationCollector=scope.launch {
                    opened.state.collect { next ->
                        if(generation!=stamp || navigationGeneration!=view || creationFlow!==opened || !foreground) return@collect
                        mutable.value=mutable.value.copy(creation=next)
                        if(next.phase==SessionCreationPhase.AUTH_REQUIRED && mutable.value.phase==HomePhase.READY) renew()
                        else if(next.phase==SessionCreationPhase.REVOKED && mutable.value.phase==HomePhase.READY) refresh()
                    }
                }
            } catch(error: CancellationException) { throw error }
            catch(error: Exception) { if(generation==stamp && view==navigationGeneration) mutable.value=mutable.value.copy(creation=SessionCreationState(SessionCreationPhase.ERROR,error=code(error))) }
            finally { database?.close() }
        }
    }
    fun createSession(workspace: String,preset: String,epoch: String) {
        if(!foreground || mutable.value.phase!=HomePhase.READY || mutable.value.submitting) return
        val opened=creationFlow ?: return
        val stamp=generation; val view=navigationGeneration
        mutable.value=mutable.value.copy(submitting=true,commandError=null)
        commandJob=scope.launch {
            try { opened.create(workspace,preset,epoch); current(stamp); if(view==navigationGeneration) mutable.value=mutable.value.copy(creation=opened.state.value) }
            catch(error: CancellationException) { throw error }
            catch(error: Exception) { if(generation==stamp && view==navigationGeneration) mutable.value=mutable.value.copy(commandError=code(error)) }
            finally { if(generation==stamp && view==navigationGeneration) mutable.value=mutable.value.copy(submitting=false) }
        }
    }
    fun refreshCreationOptions() = creationFlow?.refreshOptions()
    fun queryCreation() = creationFlow?.query()
    fun sendPendingCreation(id: String) = creationFlow?.sendPending(id)
    fun openCreatedSession(request: String) {
        val runtime=mutable.value.selectedRuntimeId ?: return
        val record=mutable.value.creation?.outbox?.records?.firstOrNull { it.intent.requestId==request && it.remote==RemoteCommandState.SETTLED } ?: return
        val result=record.createdSessionId ?: return
        if(mutable.value.runtimes.firstOrNull { it.id==runtime }?.access?.canList()!=true) return
        retireNavigation(false); navigateRuntime(runtime,result)
    }
    private fun navigateRuntime(id: String, resumeSession: String?) {
        if (!foreground || mutable.value.phase != HomePhase.READY || binding != null) return
        val row = mutable.value.runtimes.firstOrNull { it.id == id } ?: return
        if (row.access?.organizationId != configuration!!.organizationId || !row.access.canList()) return
        desired = id to resumeSession
        if (session!!.accessExpiresAt - now() <= environment.minimumValidityMillis) { renew(); return }
        retireNavigation(true)
        val stamp = generation; val view = navigationGeneration; val resource = api!!
        mutable.value = mutable.value.copy(selectedRuntimeId = id, selectedSessionId = null, sessions = emptyList(), loadingSessions = true, sessionError = null, reader = null)
        navigation {
            try {
                val response = resource.sessions(id)
                current(stamp); if (view != navigationGeneration) return@navigation
                if (response["ok"] != JsonBoolean(true)) throw RemoteRequestException("network.invalid_response")
                val entries = response.obj("data").array("items").map { SessionDirectoryEntry.parse(it as? JsonObject ?: throw RemoteRequestException("network.invalid_response")) }
                if (entries.map { it.id }.toSet().size != entries.size) throw RemoteRequestException("network.invalid_response")
                mutable.value = mutable.value.copy(sessions = entries, loadingSessions = false)
                if (resumeSession != null && entries.any { it.id == resumeSession }) { navigationJob = null; openSession(resumeSession) }
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) {
                if (generation == stamp && view == navigationGeneration) {
                    mutable.value = mutable.value.copy(loadingSessions = false, sessionError = code(error))
                    if (authorityLost(error)) refresh()
                }
            }
        }
    }
    fun openSession(id: String) {
        if (!foreground || mutable.value.phase != HomePhase.READY) return
        val runtimeId = mutable.value.selectedRuntimeId ?: return
        val runtime = mutable.value.runtimes.firstOrNull { it.id == runtimeId }?.access ?: return
        val selected = mutable.value.sessions.firstOrNull { it.id == id } ?: return
        val allowed = selected.viewScope(runtime, includeApprovals = approval != null) ?: return
        desired = runtimeId to id
        if (session!!.accessExpiresAt - now() <= environment.minimumValidityMillis) { renew(); return }
        retireNavigation(true)
        val stamp = generation; val view = navigationGeneration
        val resource = api!!
        val saved = checkpoint!!
        val owner = CommandOwner(saved.accountId, saved.organizationId, configuration!!.fingerprint, saved.userId, saved.deviceId!!)
        mutable.value = mutable.value.copy(selectedSessionId = id, reader = SessionReadState(SessionReadPhase.CONNECTING), sessionError = null, outbox = null, commandError = null, submitting = false)
        navigation {
            var database: SqlCommandJournal? = null
            try {
                try { withContext(NonCancellable) { database = persistence.commands(owner, stamp) } }
                catch (error: Exception) {
                    current(stamp); if (view != navigationGeneration) return@navigation
                    mutable.value = mutable.value.copy(commandError = if (error is CommandDataException) error.code else "data.unavailable")
                }
                current(stamp); if (view != navigationGeneration) return@navigation
                val approvalAccount = if (database != null && "approval.decide" in allowed.actions) {
                    val local = approval ?: throw DeviceCryptoException(DeviceCryptoFailure.KEY_MISSING)
                    if (local.thumbprint != saved.approvalKeyJkt) throw DeviceCryptoException(DeviceCryptoFailure.WRONG_KEY)
                    val key = RegisteredApprovalKey.parse(jsonObject("user_id" to saved.userId.json(), "device_id" to saved.deviceId!!.json(), "key_version" to 1L.json(),
                        "active" to JsonBoolean(true), "public_jwk" to local.publicJwk, "approval_key_jkt" to local.thumbprint.json()))
                    val decisions = database!!.approvalDecisions(key)
                    approvalJournal = decisions
                    SessionApprovalAccount(runtime.hostId, key, decisions)
                } else null
                val opened = if (database != null) resource.chatReader(saved.deviceId!!, runtimeId, id, allowed, database!!, scope, transcripts = database, workspaceId = selected.workspaceId, approvalAccount = approvalAccount, exportJournal = database.takeIf { "file.download" in allowed.actions })
                    else resource.reader(saved.deviceId!!, runtimeId, id, runtime.scope!!.readSession(id, selected.workspaceId), scope)
                commandJournal = database; database = null; reader = opened
                if (commandJournal != null && selected.state != "archived" && runtime.role in setOf("operator", "owner") && runtime.scope?.actions?.contains("file.upload") == true) {
                    val files = resource.fileUploads(runtimeId, id, selected.workspaceId, runtime.scope!!, commandJournal!!, scope)
                    uploads = files
                    uploadCollector = scope.launch { files.state.collect { value -> if (generation == stamp && navigationGeneration == view && foreground) mutable.value = mutable.value.copy(uploads = value) } }
                    drainDocument()
                } else { pendingDocument = null; mutable.value = mutable.value.copy(uploads = null, documentPicker = null) }
                drainExportSave()
                opened.exports?.let { exports -> exportCollector = scope.launch {
                    exports.state.collect { value -> if (generation == stamp && navigationGeneration == view && foreground) mutable.value = mutable.value.copy(exports = value) }
                } }
                questionScope=CoroutineScope(SupervisorJob(scope.coroutineContext[Job])+Dispatchers.Main.immediate)
                opened.approvals?.let { client -> approvalCollector = scope.launch {
                    client.state.collect {
                        if (generation != stamp || navigationGeneration != view || !foreground) return@collect
                        val next = client.state.value
                        mutable.value = mutable.value.copy(approvals = next)
                        val handle = approvalPreparingHandle ?: approvalAuthentication?.handle
                        if (handle != null && (!next.connected || !next.contentReady || next.view.items.none { it.handle == handle } ||
                                approvalAuthentication != null && !next.signing)) abortApprovalAuthentication("approval.stale")
                    }
                } }
                opened.commands?.let { commands -> commandCollector = scope.launch {
                    commands.state.collect { outbox ->
                        if (generation == stamp && navigationGeneration == view && foreground) mutable.value = mutable.value.copy(outbox = outbox)
                    }
                } }
                readerJob = scope.launch {
            opened.state.collect { state ->
                if (generation != stamp || view != navigationGeneration || !foreground) return@collect
                mutable.value = mutable.value.copy(reader = state)
                if (state.phase == SessionReadPhase.AUTH_REQUIRED && mutable.value.phase == HomePhase.READY) renew()
                else if (state.phase == SessionReadPhase.REVOKED && mutable.value.phase == HomePhase.READY) refresh()
            }
                }
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) {
                if (generation == stamp && navigationGeneration == view) mutable.value = mutable.value.copy(reader = SessionReadState(SessionReadPhase.ERROR, error = code(error)))
            } finally { database?.close() }
        }
    }
    fun submitMessage(mode: String, text: String, sendNow: Boolean = true) {
        if (!foreground || mutable.value.phase != HomePhase.READY || mutable.value.submitting) return
        if (mutable.value.sessions.firstOrNull { it.id == mutable.value.selectedSessionId }?.state == "archived") return
        val opened = reader ?: return
        if (opened.state.value.phase in setOf(SessionReadPhase.AUTH_REQUIRED, SessionReadPhase.REVOKED, SessionReadPhase.CLOSED)) return
        val commands = opened.commands ?: return
        val stamp = generation; val view = navigationGeneration
        mutable.value = mutable.value.copy(submitting = true, commandError = null)
        commandJob = scope.launch {
            try {
                val attachments = uploads?.selectedFiles() ?: emptyList()
                commands.submit(mode, text, sendNow, attachments)
                current(stamp); if (view != navigationGeneration) return@launch
                uploads?.messageSaved()
                mutable.value = mutable.value.copy(composerRevision = mutable.value.composerRevision + 1, composerRestore = null)
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { if (generation == stamp && view == navigationGeneration) mutable.value = mutable.value.copy(commandError = if (error is CommandDataException) error.code else "command.invalid") }
            finally { if (generation == stamp && view == navigationGeneration) mutable.value = mutable.value.copy(submitting = false) }
        }
    }
    fun sendPending(id: String) { reader?.commands?.sendPending(id) }
    fun pickDocument(resume: String?, text: String, mode: String) {
        val state = mutable.value
        if (!foreground || state.phase != HomePhase.READY || uploads == null || state.uploads?.busy == true) return
        val runtime = state.selectedRuntimeId ?: return; val selected = state.selectedSessionId ?: return
        val token = UUID.randomUUID().toString()
        pendingDocument = PendingDocument(token, generation, runtime, selected, resume, MessageDraft(text, mode, runtime, selected))
        mutable.value = state.copy(documentPicker = DocumentPickLaunch(token))
    }
    fun documentPicked(token: String, uri: Uri?) {
        val pending = pendingDocument ?: return
        if (pending.id != token || pending.generation != generation || desired != (pending.runtime to pending.session)) return
        mutable.value = mutable.value.copy(documentPicker = null, composerRestore = pending.draft, composerRevision = mutable.value.composerRevision + 1)
        if (uri == null) { pendingDocument = null; return }
        pending.result = uri
        drainDocument()
    }
    private fun drainDocument() {
        val pending = pendingDocument ?: return
        val source = pending.result ?: return
        val files = uploads ?: return
        if (!foreground || pending.generation != generation || desired != (pending.runtime to pending.session)) return
        pendingDocument = null
        try { files.select(DocumentFileSource(context, source), pending.resume) }
        catch (error: Exception) { mutable.value = mutable.value.copy(commandError = code(error)) }
    }
    fun toggleUpload(id: String) = uploads?.toggle(id)
    fun queryUpload(id: String) = uploads?.query(id)
    fun removeUpload(id: String) = uploads?.remove(id)
    fun cancelUpload() = uploads?.cancelTransfer()
    fun chooseExportDestination(id: String) {
        if (!foreground || mutable.value.phase != HomePhase.READY || mutable.value.exportSaving || pendingExportSave != null) return
        val row = reader?.exports?.state?.value?.rows?.firstOrNull { it.stored.intent.requestId == id } ?: return
        val file = row.status?.takeIf { it.downloadable() && row.stored.manifest?.same(it.manifest) == true } ?: return
        val token = UUID.randomUUID().toString()
        pendingExportSave = PendingExportSave(token, generation, file.runtimeId, file.sessionId, id, file)
        mutable.value = mutable.value.copy(exportSavePicker = ExportSaveLaunch(token, file.manifest.name), exportSaved = false, exportSaveError = null)
    }
    fun exportDestinationPicked(token: String, uri: Uri?) {
        val pending = pendingExportSave
        if (pending == null || pending.id != token || pending.generation != generation || desired != (pending.runtime to pending.session)) {
            if (abandonedSavePickers.remove(token)) uri?.let { scope.launch(Dispatchers.IO) { discardExportDocument(context, it) } }; return
        }
        mutable.value = mutable.value.copy(exportSavePicker = null)
        if (uri == null) { pendingExportSave = null; return }
        pending.result = uri; drainExportSave()
    }
    private fun drainExportSave() {
        val pending = pendingExportSave ?: return
        val uri = pending.result ?: return
        val journal = commandJournal ?: return
        val resource = api ?: return
        if (!foreground || pending.generation != generation || desired != (pending.runtime to pending.session)) return
        pendingExportSave = null
        val stamp = generation; val view = navigationGeneration
        mutable.value = mutable.value.copy(exportSaving = true, exportSaved = false, exportSaveError = null, exportBytes = 0)
        exportSaveJob = scope.launch {
            var savedSuccessfully = false
            try {
                val original = journal.exports(pending.runtime, pending.session).firstOrNull { it.intent.requestId == pending.request } ?: throw RemoteRequestException("file.export_reconcile")
                if (original.fileId != pending.file.id || original.manifest?.same(pending.file.manifest) != true) throw RemoteRequestException("file.request_conflict")
                val lifetime = currentCoroutineContext()
                val lastProgress = java.util.concurrent.atomic.AtomicLong()
                saveExportDocument(context, uri, resource, pending.file, {
                    lifetime.ensureActive(); session?.accessTokenForRequest(System.currentTimeMillis()) ?: throw RemoteRequestException("auth.expired")
                    if (!foreground || generation != stamp || navigationGeneration != view || desired != (pending.runtime to pending.session) ||
                        mutable.value.phase != HomePhase.READY || mutable.value.reader?.phase in setOf(SessionReadPhase.REVOKED, SessionReadPhase.AUTH_REQUIRED)) throw RemoteRequestException("file.export_stale")
                    if (!pending.file.downloadable()) throw RemoteRequestException("file.expired")
                }) { bytes ->
                    val tick = System.nanoTime(); val previous = lastProgress.get()
                    if ((tick - previous >= 250_000_000 || bytes == pending.file.manifest.sizeBytes) && lastProgress.compareAndSet(previous, tick))
                        scope.launch { if (generation == stamp && navigationGeneration == view) mutable.value = mutable.value.copy(exportBytes = bytes) }
                }
                current(stamp)
                savedSuccessfully = true
                if (view == navigationGeneration) mutable.value = mutable.value.copy(exportSaved = true)
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) {
                if (generation == stamp && navigationGeneration == view) mutable.value = mutable.value.copy(exportSaveError = code(error))
            } finally {
                withContext(NonCancellable + Dispatchers.IO) { if (!savedSuccessfully) discardExportDocument(context, uri) }
                if (generation == stamp && navigationGeneration == view) mutable.value = mutable.value.copy(exportSaving = false)
            }
        }
    }
    fun cancelExportSave() { mutable.value = mutable.value.copy(exportSaveError = "file.save_cancelled"); exportSaveJob?.cancel() }
    fun browseExports(source: ExportSource? = null, more: Boolean = false) = reader?.exports?.browse(source, more)
    fun requestExport(source: ExportSource) = reader?.exports?.request(source)
    fun queryExports() = reader?.exports?.query()
    fun cancelExport(id: String) = reader?.exports?.cancel(id)
    fun removeExport(id: String) = reader?.exports?.remove(id)
    fun queryCommands() { reader?.commands?.query() }
    fun refreshQuestions() {reader?.refreshQuestions()}
    fun reviewApproval(id: String) {
        if (!foreground || mutable.value.phase != HomePhase.READY || mutable.value.approvalStage != ApprovalUiStage.IDLE) return
        val client = reader?.approvals ?: return
        Contract.uuid(id)
        mutable.value = mutable.value.copy(reviewingApprovalId = id, approvalError = null)
        approvalWork { client.requestDetails(id) }
    }
    fun closeApprovalReview() {
        abortApprovalAuthentication(null)
        mutable.value = mutable.value.copy(reviewingApprovalId = null, approvalError = null)
        approvalWork { it.dismissReview() }
    }
    fun queryApprovals() { reader?.approvals?.query() }
    fun refreshApprovals() { closeApprovalReview(); reader?.refreshQuestions() }
    fun discardUnsentApproval(id: String) = approvalWork { it.discardUnsent(id) }
    private fun approvalWork(action: suspend (SessionApprovalClient) -> Unit) {
        if (!foreground || mutable.value.phase != HomePhase.READY) return
        val client = reader?.approvals ?: return; val work = questionScope ?: return
        val stamp = generation; val view = navigationGeneration; val selection = mutable.value.reviewingApprovalId
        work.launch {
            try { action(client) }
            catch (error: CancellationException) { throw error }
            catch (error: Exception) { if (generation == stamp && view == navigationGeneration && mutable.value.reviewingApprovalId == selection && reader?.approvals === client) mutable.value = mutable.value.copy(approvalError = code(error)) }
        }
    }
    private fun approvalCurrent(stamp: Long, view: Long, client: SessionApprovalClient, handle: ApprovalReviewHandle) {
        current(stamp)
        val authority = mutable.value.runtimes.firstOrNull { it.id == handle.runtimeId }?.access
        if (!foreground || navigationGeneration != view || mutable.value.phase != HomePhase.READY || reader?.approvals !== client ||
            authority?.role != "owner" || authority.scope?.actions?.containsAll(setOf("session.read", "approval.decide")) != true || authority.expiresAt?.let { it <= now() } == true ||
            mutable.value.selectedRuntimeId != handle.runtimeId || mutable.value.selectedSessionId != handle.sessionId ||
            mutable.value.reviewingApprovalId != handle.approvalId || !client.state.value.connected || !client.state.value.contentReady ||
            client.state.value.view.items.none { it.handle == handle && it.context?.current(System.currentTimeMillis()) == true }) throw ApprovalStateException("approval.stale")
    }
    fun decideApproval(handle: ApprovalReviewHandle, choice: ApprovalChoice) {
        if (!foreground || mutable.value.phase != HomePhase.READY || mutable.value.approvalStage != ApprovalUiStage.IDLE || mutable.value.reviewingApprovalId != handle.approvalId) return
        val client = reader?.approvals ?: return; val work = questionScope ?: return
        val local = approval ?: return
        val stamp = generation; val view = navigationGeneration; val began = System.nanoTime(); val action = ++approvalActionGeneration
        approvalPreparingHandle = handle
        mutable.value = mutable.value.copy(approvalStage = ApprovalUiStage.PREPARING, approvalError = null)
        approvalActionJob = work.launch {
            var opened: ApprovalKeyOperation? = null
            try {
                approvalCurrent(stamp, view, client, handle)
                val prepared = client.prepareSignature(handle, choice)
                approvalPrepared = prepared
                opened = beginKeyOperation(stamp) { local.beginApproval(prepared) }
                approvalCurrent(stamp, view, client, handle)
                if (!client.state.value.signing) throw ApprovalStateException("approval.stale")
                if ((System.nanoTime() - began) / 1_000_000 >= environment.approvalPromptMillis) throw ApprovalStateException("approval.authentication_expired")
                val id = ++nextAuthenticationId
                val active = ApprovalAuthentication(id, stamp, view, action, client, handle, prepared, opened!!)
                approvalAuthentication = active; opened = null; approvalPreparingHandle = null; approvalPrepared = null
                mutable.value = mutable.value.copy(approvalStage = ApprovalUiStage.AUTHENTICATING, authenticationId = id,
                    biometric = BiometricLaunch(id, active.operation, if (choice == ApprovalChoice.ALLOW_ONCE) "仅本次允许此工具" else "确认拒绝此工具", "签署当前电脑会话中的这一次决定"))
                approvalTimeout = work.launch {
                    delay((environment.approvalPromptMillis - (System.nanoTime() - began) / 1_000_000).coerceAtLeast(1))
                    if (approvalAuthentication === active) abortApprovalAuthentication("approval.authentication_expired")
                }
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) {
                if (generation == stamp && navigationGeneration == view && approvalActionGeneration == action) abortApprovalAuthentication(code(error))
            } finally { opened?.close() }
        }
    }
    private fun abortApprovalAuthentication(error: String?) {
        val active = approvalAuthentication
        val prepared = active?.prepared ?: approvalPrepared
        approvalActionGeneration++
        approvalAuthentication = null; approvalPreparingHandle = null; approvalPrepared = null
        approvalTimeout?.cancel(); approvalTimeout = null
        approvalActionJob?.cancel(); approvalActionJob = null
        active?.operation?.close()
        val ownsPrompt = active != null && mutable.value.authenticationId == active.id
        mutable.value = mutable.value.copy(approvalStage = ApprovalUiStage.IDLE, approvalError = error,
            authenticationId = if (ownsPrompt) null else mutable.value.authenticationId,
            biometric = if (ownsPrompt) null else mutable.value.biometric)
        val client = active?.client ?: reader?.approvals
        if (prepared != null) questionScope?.launch { client?.cancelSignature(prepared) }
    }
    private fun authenticatedApproval(active: ApprovalAuthentication, result: BiometricPrompt.AuthenticationResult) {
        if (runCatching { result.cryptoObject?.signature === active.operation.cryptoObject.signature }.getOrDefault(false).not()) return
        val work = questionScope ?: return
        try { approvalCurrent(active.stamp, active.view, active.client, active.handle) }
        catch (_: Exception) { abortApprovalAuthentication("approval.stale"); return }
        approvalAuthentication = null; approvalTimeout?.cancel(); approvalTimeout = null
        mutable.value = mutable.value.copy(approvalStage = ApprovalUiStage.SENDING, authenticationId = null, biometric = null, approvalError = null)
        approvalActionJob = work.launch {
            try {
                val signed = withContext(Dispatchers.Default) { active.operation.finish(result) }
                approvalCurrent(active.stamp, active.view, active.client, active.handle)
                active.client.submit(active.handle, signed)
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { if (generation == active.stamp && navigationGeneration == active.view && approvalActionGeneration == active.action) mutable.value = mutable.value.copy(approvalError = code(error)) }
            finally {
                active.operation.close()
                withContext(NonCancellable) { active.client.cancelSignature(active.prepared) }
                if (generation == active.stamp && navigationGeneration == active.view && approvalActionGeneration == active.action) mutable.value = mutable.value.copy(approvalStage = ApprovalUiStage.IDLE)
            }
        }
    }
    fun sendOriginalApproval(handle: ApprovalReviewHandle, id: String) {
        if (!foreground || mutable.value.phase != HomePhase.READY || mutable.value.approvalStage != ApprovalUiStage.IDLE) return
        val client = reader?.approvals ?: return; val work = questionScope ?: return
        val stamp = generation; val view = navigationGeneration; val action = ++approvalActionGeneration
        mutable.value = mutable.value.copy(approvalStage = ApprovalUiStage.SENDING, approvalError = null)
        approvalActionJob = work.launch {
            try { approvalCurrent(stamp, view, client, handle); client.sendPending(handle, id) }
            catch (error: CancellationException) { throw error }
            catch (error: Exception) { if (generation == stamp && navigationGeneration == view && approvalActionGeneration == action) mutable.value = mutable.value.copy(approvalError = code(error)) }
            finally { if (generation == stamp && navigationGeneration == view && approvalActionGeneration == action) mutable.value = mutable.value.copy(approvalStage = ApprovalUiStage.IDLE) }
        }
    }
    fun reauthenticateApproval() {
        if (mutable.value.phase != HomePhase.READY || mutable.value.approvalError != "approval.assurance_required" && mutable.value.approvals?.error != "approval.assurance_required") return
        val stamp = fence(closeKeys = false)
        mutable.value = HomeState(HomePhase.RENEWING, configuration!!.issuer)
        work { try { requireReauthentication(stamp, "approval.assurance_required") } catch (error: CancellationException) { throw error } catch (error: Exception) { handle(error, stamp) } }
    }
    fun answerQuestion(handle: QuestionHandle,answers: QuestionAnswers) {
        if(!foreground || mutable.value.phase!=HomePhase.READY || mutable.value.submitting) return
        val opened=reader ?: return
        val work=questionScope ?: return
        val stamp=generation;val view=navigationGeneration
        mutable.value=mutable.value.copy(submitting=true,commandError=null)
        commandJob=work.launch {
            try {
                opened.answerQuestion(handle,answers);current(stamp)
                if(view==navigationGeneration) mutable.value=mutable.value.copy(outbox=opened.commands?.state?.value)
            } catch(error: CancellationException) {throw error}
            catch(error: Exception) {if(generation==stamp && view==navigationGeneration) mutable.value=mutable.value.copy(commandError=code(error))}
            finally {if(generation==stamp && view==navigationGeneration) mutable.value=mutable.value.copy(submitting=false)}
        }
    }
    fun claimQuestion(handle: QuestionHandle) = questionWork(handle,true)
    fun releaseQuestion(handle: QuestionHandle) = questionWork(handle,false)
    private fun questionWork(handle: QuestionHandle,claim: Boolean) {
        if(!foreground || mutable.value.phase!=HomePhase.READY) return
        val opened=reader ?: return;val work=questionScope ?: return
        val stamp=generation;val view=navigationGeneration
        work.launch {
            try {if(claim) opened.claimQuestion(handle) else opened.releaseQuestion(handle)}
            catch(error: CancellationException) {throw error}
            catch(error: Exception) {if(generation==stamp && view==navigationGeneration) mutable.value=mutable.value.copy(commandError=code(error))}
        }
    }
    fun cancelSession(expectedEpoch: String) {
        if (!foreground || mutable.value.phase != HomePhase.READY) return
        val commands = reader?.commands ?: return
        if (reader?.state?.value?.runtimeEpoch != expectedEpoch) return
        val stamp = generation; val view = navigationGeneration
        commandJob = scope.launch { try { commands.cancel(expectedEpoch) } catch (error: Exception) {
            if (error is CancellationException) throw error
            if (generation == stamp && view == navigationGeneration) mutable.value = mutable.value.copy(commandError = "command.cancel_unconfirmed")
        } }
    }
    fun archiveSession(expectedEpoch: String, archived: Boolean, stopActivity: Boolean) {
        if (!foreground || mutable.value.phase != HomePhase.READY || mutable.value.submitting) return
        val opened = reader ?: return
        val commands = opened.commands ?: return
        val runtimeId = mutable.value.selectedRuntimeId ?: return
        val sessionId = mutable.value.selectedSessionId ?: return
        if (opened.state.value.phase != SessionReadPhase.READY || opened.state.value.runtimeEpoch != expectedEpoch) return
        val stamp = generation; val view = navigationGeneration
        val resource = api ?: return
        mutable.value = mutable.value.copy(submitting = true, commandError = null)
        commandJob = scope.launch {
            try {
                val id = commands.archive(archived, stopActivity, expectedEpoch)
                val result = withTimeoutOrNull(15_000) { commands.state.first { outbox -> outbox.records.any { row -> row.intent.requestId == id &&
                    row.remote in setOf(RemoteCommandState.SETTLED, RemoteCommandState.REJECTED, RemoteCommandState.OUTCOME_UNKNOWN) } } }
                current(stamp); if (view != navigationGeneration) return@launch
                if (result?.records?.firstOrNull { it.intent.requestId == id }?.remote == RemoteCommandState.SETTLED) {
                    // Receipts prove the historical command. Only a fresh Host
                    // catalog determines current state; desktop actions can race.
                    var pollsRemaining = 20
                    do {
                        val response = resource.sessions(runtimeId)
                        current(stamp); if (view != navigationGeneration) return@launch
                        if (response["ok"] != JsonBoolean(true)) throw RemoteRequestException("network.invalid_response")
                        val rows = response.obj("data").array("items").map { SessionDirectoryEntry.parse(it as? JsonObject ?: throw RemoteRequestException("network.invalid_response")) }
                        if (rows.map { it.id }.toSet().size != rows.size) throw RemoteRequestException("network.invalid_response")
                        mutable.value = mutable.value.copy(sessions = rows)
                        if (rows.firstOrNull { it.id == sessionId }?.state.let { if (archived) it == "archived" else it in setOf("available", "running") } || --pollsRemaining <= 0) break
                        delay(250)
                    } while (true)
                    if (mutable.value.sessions.any { it.id == sessionId }) openSession(sessionId)
                    else navigateRuntime(runtimeId, null)
                }
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { if (generation == stamp && view == navigationGeneration) mutable.value = mutable.value.copy(commandError = code(error)) }
            finally { if (generation == stamp && view == navigationGeneration) mutable.value = mutable.value.copy(submitting = false) }
        }
    }
    fun loadOlder() = reader?.loadOlder()
    fun retryRead() = reader?.retry()
    fun refreshSessions() { mutable.value.selectedRuntimeId?.let { navigateRuntime(it, mutable.value.selectedSessionId) } }
    fun back() {
        if (binding != null) { closeBinding(); return }
        if(creationDesired!=null || mutable.value.creation!=null) {
            val target=creationDesired ?: mutable.value.selectedRuntimeId
            val directory=creationReturnsToRuntime
            retireNavigation(false)
            mutable.value=mutable.value.copy(selectedRuntimeId=null,selectedSessionId=null,creation=null)
            if(directory && target!=null) navigateRuntime(target,null)
            return
        }
        val runtime = mutable.value.selectedRuntimeId ?: return
        if (mutable.value.selectedSessionId != null) {
            retireNavigation(false); desired = runtime to null
            mutable.value = mutable.value.copy(selectedSessionId = null, reader = null, outbox = null, commandError = null, submitting = false)
        } else {
            retireNavigation(false)
            mutable.value = mutable.value.copy(selectedRuntimeId = null, selectedSessionId = null, sessions = emptyList(), reader = null, loadingSessions = false, sessionError = null)
        }
    }
    private fun fence(closeKeys: Boolean, preserveSelection: Boolean = false): Long {
        pendingDocument = null
        mutable.value = mutable.value.copy(documentPicker = null, composerRestore = null)
        retireNavigation(preserveSelection)
        retireBinding(preserveSelection)
        generation++; job?.cancel(); deadline?.cancel(); pending?.cancel(); pending = null; discardRegistration()
        if (closeKeys) { owner?.close(); owner = null; proof = null; approval = null; api = null; session = null }
        return generation
    }
    fun cancel() { clearAccount(null) }
    private fun clearAccount(error: String?) {
        val old = reference
        val stamp = fence(closeKeys = true)
        cleanupPending = true
        mutable.value = HomeState(HomePhase.CLEARING, configuration?.issuer ?: "")
        work {
            try {
                persistence.clear(stamp, old)
                current(stamp)
                cleanupPending = false; checkpoint = null; reference = null
                mutable.value = HomeState(HomePhase.SIGNED_OUT, configuration?.issuer ?: "", error)
            } catch (error: CancellationException) { throw error }
            catch (_: Exception) { if (generation == stamp) mutable.value = HomeState(HomePhase.RECOVERY_ERROR, configuration?.issuer ?: "", "account.cleanup_failed") }
        }
    }
    private fun handle(error: Exception, stamp: Long) {
        if (generation != stamp) return
        deadline?.cancel()
        retireNavigation(false)
        retireBinding(false)
        if (authorityLost(error)) clearAccount(code(error))
        else { session = null; api = null; discardRegistration(); mutable.value = HomeState(HomePhase.RECOVERY_ERROR, configuration?.issuer ?: "", code(error)) }
    }
    private fun authorityLost(error: Exception): Boolean =
        error is LoginException && error.failure == LoginFailure.IDENTITY ||
            error is RemoteRequestException && error.code in setOf("auth.identity_mismatch", "access.organization_missing", "access.denied", "access.revoked", "device.invalid")
    private fun retireBinding(keepResume: Boolean) {
        bindingGeneration++; bindingCollector?.cancel(); bindingCollector = null
        resumeBindingView = keepResume && binding != null && binding?.resumeId != null
        if (keepResume) binding?.resumeId?.let { pendingBindingId = it } else pendingBindingId = null
        binding?.close(); binding = null
    }
    fun openBinding(resumeId: String? = pendingBindingId) {
        if (!foreground || mutable.value.phase != HomePhase.READY) return
        if (session!!.accessExpiresAt - now() <= environment.minimumValidityMillis) {
            pendingBindingId = resumeId; renew(); resumeBindingView = resumeId != null; return
        }
        retireNavigation(false); retireBinding(false)
        val stamp = generation; val view = bindingGeneration
        pendingBindingId = resumeId
        val opened = api!!.hostBinding(scope, resumeId, onAuthorityFailure = { code ->
            if (generation == stamp && bindingGeneration == view && mutable.value.phase == HomePhase.READY) {
                if (code in setOf("auth.expired", "auth.proof_invalid")) renew() else refresh()
            }
        }, onReady = {
            if (generation == stamp && bindingGeneration == view && mutable.value.phase == HomePhase.READY) refresh()
        })
        binding = opened
        mutable.value = mutable.value.copy(binding = opened.state.value, pendingBindingId = pendingBindingId,
            selectedRuntimeId = null, selectedSessionId = null, sessions = emptyList(), reader = null, loadingSessions = false, sessionError = null)
        bindingCollector = scope.launch {
            opened.state.collect { next ->
                if (generation != stamp || bindingGeneration != view || binding !== opened || mutable.value.phase != HomePhase.READY) return@collect
                pendingBindingId = if (next.phase in setOf(HostBindingPhase.READY, HostBindingPhase.UNAVAILABLE) || next.phase == HostBindingPhase.ENTER && next.id.isEmpty()) null else opened.resumeId
                mutable.value = mutable.value.copy(binding = next, pendingBindingId = pendingBindingId)
            }
        }
        opened.foreground(true)
    }
    fun previewBinding(id: String, code: String) = binding?.preview(id, code)
    fun confirmBinding() = binding?.confirm()
    fun queryBinding(id: String) = binding?.lookup(id)
    fun refreshBinding() = binding?.lookup()
    fun enterAnotherBinding() = binding?.enterAnother()
    fun closeBinding() {
        val opened = binding ?: return
        val resume = opened.resumeId.takeIf { opened.state.value.phase !in setOf(HostBindingPhase.READY, HostBindingPhase.UNAVAILABLE) }
        retireBinding(false); pendingBindingId = resume
        mutable.value = mutable.value.copy(binding = null, pendingBindingId = resume)
    }
    private fun code(error: Exception): String = when (error) {
        is CommandDataException -> error.code
        is QuestionStateException -> error.code
        is ApprovalStateException -> error.code
        is ApprovalSignatureException -> "approval.signature_unavailable"
        is LoginException -> "login.${error.failure.name.lowercase()}"
        is RemoteRequestException -> error.code
        is DeviceCryptoException -> "device.${error.failure.name.lowercase()}"
        is DeviceProofException -> "auth.proof_invalid"
        is VaultException -> "vault.${error.failure.name.lowercase()}"
        else -> "network.unavailable"
    }
    /** Process/owner disposal preserves durable credentials; explicit local exit uses cancel(). */
    override fun close() { fence(closeKeys = true); scope.cancel() }
}

@HiltViewModel
class HomeViewModel @Inject constructor(private val login: LoginController) : ViewModel() {
    val state = login.state
    fun login() = login.login()
    fun register(name: String) = login.register(name)
    fun cancel() = login.cancel()
    fun refresh() = login.refresh()
    fun foreground(active: Boolean) = login.foreground(active)
    fun openRuntime(id: String) = login.openRuntime(id)
    fun openSession(id: String) = login.openSession(id)
    fun openCreation(id: String) = login.openCreation(id)
    fun createSession(workspace: String,preset: String,epoch: String) = login.createSession(workspace,preset,epoch)
    fun refreshCreationOptions() = login.refreshCreationOptions()
    fun queryCreation() = login.queryCreation()
    fun sendPendingCreation(id: String) = login.sendPendingCreation(id)
    fun openCreatedSession(id: String) = login.openCreatedSession(id)
    fun loadOlder() = login.loadOlder()
    fun retryRead() = login.retryRead()
    fun refreshSessions() = login.refreshSessions()
    fun back() = login.back()
    fun submitMessage(mode: String, text: String, sendNow: Boolean = true) = login.submitMessage(mode, text, sendNow)
    fun sendPending(id: String) = login.sendPending(id)
    fun pickDocument(resume: String?, text: String, mode: String) = login.pickDocument(resume, text, mode)
    fun documentPicked(token: String, uri: Uri?) = login.documentPicked(token, uri)
    fun toggleUpload(id: String) = login.toggleUpload(id)
    fun queryUpload(id: String) = login.queryUpload(id)
    fun removeUpload(id: String) = login.removeUpload(id)
    fun cancelUpload() = login.cancelUpload()
    fun chooseExportDestination(id: String) = login.chooseExportDestination(id)
    fun exportDestinationPicked(token: String, uri: Uri?) = login.exportDestinationPicked(token, uri)
    fun cancelExportSave() = login.cancelExportSave()
    fun browseExports(source: ExportSource?, more: Boolean) = login.browseExports(source, more)
    fun requestExport(source: ExportSource) = login.requestExport(source)
    fun queryExports() = login.queryExports()
    fun cancelExport(id: String) = login.cancelExport(id)
    fun removeExport(id: String) = login.removeExport(id)
    fun queryCommands() = login.queryCommands()
    fun answerQuestion(handle: QuestionHandle,answers: QuestionAnswers) = login.answerQuestion(handle,answers)
    fun claimQuestion(handle: QuestionHandle) = login.claimQuestion(handle)
    fun releaseQuestion(handle: QuestionHandle) = login.releaseQuestion(handle)
    fun refreshQuestions() = login.refreshQuestions()
    fun reviewApproval(id: String) = login.reviewApproval(id)
    fun closeApprovalReview() = login.closeApprovalReview()
    fun decideApproval(handle: ApprovalReviewHandle, choice: ApprovalChoice) = login.decideApproval(handle, choice)
    fun sendOriginalApproval(handle: ApprovalReviewHandle, id: String) = login.sendOriginalApproval(handle, id)
    fun queryApprovals() = login.queryApprovals()
    fun refreshApprovals() = login.refreshApprovals()
    fun discardUnsentApproval(id: String) = login.discardUnsentApproval(id)
    fun reauthenticateApproval() = login.reauthenticateApproval()
    fun cancelSession(epoch: String) = login.cancelSession(epoch)
    fun archiveSession(epoch: String, archived: Boolean, stopActivity: Boolean) = login.archiveSession(epoch, archived, stopActivity)
    fun openBinding() = login.openBinding()
    fun previewBinding(id: String, code: String) = login.previewBinding(id, code)
    fun confirmBinding() = login.confirmBinding()
    fun queryBinding(id: String) = login.queryBinding(id)
    fun refreshBinding() = login.refreshBinding()
    fun enterAnotherBinding() = login.enterAnotherBinding()
    fun closeBinding() = login.closeBinding()
    fun browserOpened(id: Long) = login.browserOpened(id)
    fun browserUnavailable() = login.browserUnavailable()
    fun promptOpened(id: Long) = login.promptOpened(id)
    fun authenticated(id: Long, result: BiometricPrompt.AuthenticationResult) = login.authenticated(id, result)
    fun authenticationCancelled(id: Long) = login.authenticationCancelled(id)
}
