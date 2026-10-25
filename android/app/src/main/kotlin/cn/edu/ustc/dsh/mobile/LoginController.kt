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
class BiometricLaunch(val id: Long, val operation: AuthenticatedKeyOperation<DeviceRegistrationProof>)
data class RuntimeRow(val id: String, val hostId: String, val version: String, val hostAlias: String, val access: RuntimeDirectoryEntry? = null)
data class HomeState(
    val phase: HomePhase = HomePhase.LOADING, val issuer: String = "", val error: String? = null,
    val subject: String = "", val deviceId: String = "", val runtimes: List<RuntimeRow> = emptyList(),
    val browser: BrowserLaunch? = null, val biometric: BiometricLaunch? = null, val authenticationId: Long? = null,
    val securitySetupRequired: Boolean = false, val refreshing: Boolean = false, val deviceName: String? = null,
    val selectedRuntimeId: String? = null, val selectedSessionId: String? = null,
    val sessions: List<SessionDirectoryEntry> = emptyList(), val loadingSessions: Boolean = false, val sessionError: String? = null,
    val reader: SessionReadState? = null,
    val binding: HostBindingState? = null, val pendingBindingId: String? = null,
    val outbox: CommandOutboxState? = null, val commandError: String? = null, val submitting: Boolean = false, val composerRevision: Long = 0,
)

internal class LoginEnvironment(
    val configuration: () -> ByteArray,
    val storageSlot: String = "active",
    val ledgerName: String = "pending_device_keys",
    val now: () -> Long = System::currentTimeMillis,
    val refreshLeadMillis: Long = 30_000,
    val minimumValidityMillis: Long = 60_000,
)

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
    private var commandJournal: SqlCommandJournal? = null
    private var commandCollector: Job? = null
    private var commandJob: Job? = null
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
                    .setAdditionalParameters(mapOf("resource" to config.resource, "dpop_jkt" to proof!!.thumbprint)).build()
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
                operation = withContext(Dispatchers.Default) { local.beginRegistration(request.signatureRequest) }
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
            val oldAccess = mutable.value.runtimes.firstOrNull { it.id == desired?.first }?.access
            val removedRead = mutable.value.runtimes.filter { old ->
                old.access?.scope?.actions?.contains("session.read") == true && items.firstOrNull { it.id == old.id }?.access?.scope?.actions?.contains("session.read") != true
            }.map { it.id }
            mutable.value = mutable.value.copy(runtimes = items, error = null)
            val activeAccess = items.firstOrNull { it.id == desired?.first }?.access
            if (oldAccess != null && activeAccess != null && (oldAccess.grantVersion != activeAccess.grantVersion || activeAccess.scope?.let { oldAccess.scope?.same(it) } != true)) retireNavigation(true)
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
                persistence.retainHistory(dataOwner, items.mapNotNull { item -> item.access?.takeIf { it.canList() }?.scope?.let { item.id to it } }.toMap(), stamp)
                current(stamp)
            } catch (error: CancellationException) { throw error }
            catch (_: CommandDataException) { current(stamp) /* Online reading remains available if local data cannot open. */ }
            val selection = desired
            if (selection != null) {
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
        reader?.close(); reader = null
        commandJournal?.close(); commandJournal = null
        mutable.value = mutable.value.copy(outbox = null, commandError = null, submitting = false)
        if (!keepDesired) desired = null
    }
    fun foreground(active: Boolean) {
        if (foreground == active) return
        foreground = active
        binding?.foreground(active)
        if (!active) {
            retireNavigation(true)
            mutable.value = mutable.value.copy(reader = mutable.value.reader?.copy(phase = SessionReadPhase.CLOSED, window = null), loadingSessions = false, binding = binding?.state?.value,
                outbox = null, commandError = null, submitting = false, composerRevision = mutable.value.composerRevision + 1)
        } else if (mutable.value.phase == HomePhase.READY && binding == null) {
            if (resumeBindingView) { resumeBindingView = false; pendingBindingId?.let(::openBinding) }
            else desired?.let { navigateRuntime(it.first, it.second) }
        }
    }
    private fun navigation(block: suspend CoroutineScope.() -> Unit) {
        val task = scope.launch(start = CoroutineStart.LAZY, block = block); navigationJob = task; task.start()
    }
    fun openRuntime(id: String) = navigateRuntime(id, null)
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
        val allowed = selected.viewScope(runtime) ?: return
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
                val opened = if (database != null) resource.chatReader(saved.deviceId!!, runtimeId, id, allowed, database!!, scope, transcripts = database, workspaceId = selected.workspaceId)
                    else resource.reader(saved.deviceId!!, runtimeId, id, runtime.scope!!.readSession(id, selected.workspaceId), scope)
                commandJournal = database; database = null; reader = opened
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
        val opened = reader ?: return
        if (opened.state.value.phase in setOf(SessionReadPhase.AUTH_REQUIRED, SessionReadPhase.REVOKED, SessionReadPhase.CLOSED)) return
        val commands = opened.commands ?: return
        val stamp = generation; val view = navigationGeneration
        mutable.value = mutable.value.copy(submitting = true, commandError = null)
        commandJob = scope.launch {
            try {
                commands.submit(mode, text, sendNow)
                current(stamp); if (view != navigationGeneration) return@launch
                mutable.value = mutable.value.copy(composerRevision = mutable.value.composerRevision + 1)
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { if (generation == stamp && view == navigationGeneration) mutable.value = mutable.value.copy(commandError = if (error is CommandDataException) error.code else "command.invalid") }
            finally { if (generation == stamp && view == navigationGeneration) mutable.value = mutable.value.copy(submitting = false) }
        }
    }
    fun sendPending(id: String) { reader?.commands?.sendPending(id) }
    fun queryCommands() { reader?.commands?.query() }
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
    fun loadOlder() = reader?.loadOlder()
    fun retryRead() = reader?.retry()
    fun refreshSessions() { mutable.value.selectedRuntimeId?.let { navigateRuntime(it, null) } }
    fun back() {
        if (binding != null) { closeBinding(); return }
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
    fun loadOlder() = login.loadOlder()
    fun retryRead() = login.retryRead()
    fun refreshSessions() = login.refreshSessions()
    fun back() = login.back()
    fun submitMessage(mode: String, text: String, sendNow: Boolean = true) = login.submitMessage(mode, text, sendNow)
    fun sendPending(id: String) = login.sendPending(id)
    fun queryCommands() = login.queryCommands()
    fun cancelSession(epoch: String) = login.cancelSession(epoch)
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
