package cn.edu.ustc.dsh.mobile

import android.content.Context
import android.net.Uri
import android.annotation.SuppressLint
import androidx.core.net.toUri
import androidx.biometric.BiometricPrompt
import androidx.lifecycle.ViewModel
import cn.edu.ustc.dsh.auth.*
import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.keystore.*
import cn.edu.ustc.dsh.network.*
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

enum class HomePhase { LOADING, UNCONFIGURED, INVALID_CONFIGURATION, SIGNED_OUT, STARTING, BROWSER, EXCHANGING, ENROLL, PREPARING, AUTHENTICATING, REGISTERING, READY }
class BrowserLaunch(val id: Long, val uri: Uri)
class BiometricLaunch(val id: Long, val operation: AuthenticatedKeyOperation<DeviceRegistrationProof>)
data class RuntimeRow(val id: String, val hostId: String, val version: String, val hostAlias: String)
data class HomeState(
    val phase: HomePhase = HomePhase.LOADING, val issuer: String = "", val error: String? = null,
    val subject: String = "", val deviceId: String = "", val runtimes: List<RuntimeRow> = emptyList(),
    val browser: BrowserLaunch? = null, val biometric: BiometricLaunch? = null, val authenticationId: Long? = null,
    val securitySetupRequired: Boolean = false,
    val refreshing: Boolean = false,
)

private class ScopeReference(val account: String, val organization: String) {
    val encoded: String get() = "$account|$organization"
    fun scope() = DeviceKeyScope(account, organization)
}

/** Public cleanup metadata only. No verifier, state, nonce, code, JWT or user subject is persisted. */
private class PendingKeyLedger(private val context: Context) {
    private val lock = Any()
    private fun preferences() = context.getSharedPreferences("pending_device_keys", Context.MODE_PRIVATE)
    @SuppressLint("UseKtx") // The checked commit result is required before key creation.
    fun add(reference: ScopeReference) = synchronized(lock) {
        val entries = preferences().getStringSet("scopes", emptySet())!!.toMutableSet()
        check(entries.size < 16)
        entries += reference.encoded
        check(preferences().edit().putStringSet("scopes", entries).commit())
    }
    @SuppressLint("UseKtx") // Keep the durable commit result visible to recovery.
    fun remove(reference: ScopeReference) = synchronized(lock) {
        val entries = preferences().getStringSet("scopes", emptySet())!!.toMutableSet()
        entries -= reference.encoded
        check(preferences().edit().putStringSet("scopes", entries).commit())
    }
    fun recover() {
        val values = synchronized(lock) { preferences().getStringSet("scopes", emptySet())!!.toList() }
        check(values.size <= 16)
        values.forEach { value ->
            val ids = value.split('|'); check(ids.size == 2)
            val reference = ScopeReference(Contract.uuid(ids[0]), Contract.uuid(ids[1]))
            delete(reference)
        }
    }
    fun delete(reference: ScopeReference) {
        DeviceKeyStore(context).use { owner -> DeviceKeyPurpose.entries.forEach { owner.delete(reference.scope(), it, 1) } }
        remove(reference)
    }
}

@Singleton
class LoginController @Inject constructor(@param:ApplicationContext private val context: Context, private val http: LoginHttp) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val ledger = PendingKeyLedger(context)
    private val mutable = MutableStateFlow(HomeState())
    val state: StateFlow<HomeState> = mutable.asStateFlow()
    private var configuration: LoginConfiguration? = null
    private var generation = 0L
    private var nextAuthenticationId = 0L
    private var job: Job? = null
    private var deadline: Job? = null
    private var reference: ScopeReference? = null
    private var owner: DeviceKeyStore? = null
    private var proof: DeviceKeyHandle? = null
    private var approval: DeviceKeyHandle? = null
    private var pending: PendingLogin? = null
    private var session: LoginSession? = null
    private var account: ServiceAccountIdentity? = null
    private var api: RemoteApi? = null
    private var registration: RemoteApi.RegistrationRequest? = null
    private var operation: AuthenticatedKeyOperation<DeviceRegistrationProof>? = null

    init {
        scope.launch {
            try {
                configuration = withContext(Dispatchers.IO) {
                    ledger.recover()
                    val bytes = context.assets.open("deployment.json").use { it.readBytes() }
                    LoginConfiguration.parse(bytes)
                }
                mutable.value = HomeState(HomePhase.SIGNED_OUT, configuration!!.issuer)
            } catch (_: FileNotFoundException) { mutable.value = HomeState(HomePhase.UNCONFIGURED) }
            catch (_: Exception) { mutable.value = HomeState(HomePhase.INVALID_CONFIGURATION) }
        }
    }

    fun login() {
        val config = configuration ?: return
        if (mutable.value.phase != HomePhase.SIGNED_OUT) return
        val stamp = ++generation
        mutable.value = HomeState(HomePhase.STARTING, config.issuer)
        job = scope.launch {
            var createdOwner: DeviceKeyStore? = null
            val createdReference = ScopeReference(UUID.randomUUID().toString(), config.organizationId)
            var transferred = false
            try {
                val discovery = http.discovery(config)
                val key = withContext(NonCancellable + Dispatchers.IO) {
                    ledger.add(createdReference)
                    DeviceKeyStore(context).also { createdOwner = it }.create(createdReference.scope(), DeviceKeyPurpose.PROOF, 1)
                }
                if (generation != stamp) return@launch
                owner = createdOwner; reference = createdReference; proof = key; transferred = true
                val attempt = PendingLogin(discovery, key.thumbprint, System.currentTimeMillis())
                pending = attempt
                // AppAuth builds the browser request from validated discovery endpoints.
                // The verifier stays in this process; only the public request URI leaves it.
                val browserRequest = AuthorizationRequest.Builder(
                    AuthorizationServiceConfiguration(discovery.authorizationEndpoint.toUri(), discovery.tokenEndpoint.toUri()),
                    config.clientId, ResponseTypeValues.CODE, config.redirectUri.toUri(),
                ).setScopes(config.scopes).setState(attempt.state).setNonce(attempt.nonce)
                    .setCodeVerifier(attempt.verifierForAuthorizationRequest(), attempt.codeChallenge, "S256")
                    .setAdditionalParameters(mapOf("resource" to config.resource, "dpop_jkt" to key.thumbprint)).build()
                mutable.value = HomeState(HomePhase.BROWSER, config.issuer, browser = BrowserLaunch(stamp, browserRequest.toUri()))
                deadline = scope.launch { delay(600_000); if (generation == stamp && pending != null) fail("login.expired") }
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { if (generation == stamp) fail(code(error)) }
            finally {
                if (!transferred) withContext(NonCancellable + Dispatchers.IO) {
                    createdOwner?.close(); runCatching { ledger.delete(createdReference) }
                }
            }
        }
    }

    fun browserOpened(id: Long) { if (mutable.value.browser?.id == id) mutable.value = mutable.value.copy(browser = null) }
    fun browserUnavailable() { if (pending != null) fail("login.browser_unavailable") }

    fun callback(uri: String) {
        val attempt = pending ?: return
        val stamp = generation
        val exchange = try { attempt.acceptCallback(uri, System.currentTimeMillis()) }
        catch (error: LoginException) {
            if (error.failure in setOf(LoginFailure.INVALID_RESPONSE, LoginFailure.IDENTITY)) mutable.value = mutable.value.copy(error = "login.invalid_callback")
            else fail(code(error))
            return
        }
        pending = null; deadline?.cancel()
        mutable.value = mutable.value.copy(phase = HomePhase.EXCHANGING, browser = null, error = null)
        job = scope.launch {
            try {
                val signer = proof!!.proofSigner()
                val verified = withContext(Dispatchers.IO) {
                    val response = http.tokenEndpoint(attempt.discovery, signer).exchange(exchange)
                    TokenVerifier.authorizationCodeResponse(response, exchange, http.keys(attempt.discovery), System.currentTimeMillis())
                }
                val resource = http.resource(configuration!!, verified, signer)
                val mappedAccount = resource.me()
                if (generation != stamp) return@launch
                session = verified; account = mappedAccount; api = resource
                mutable.value = HomeState(HomePhase.ENROLL, verified.issuer, subject = verified.subject)
                deadline = scope.launch {
                    delay((verified.accessExpiresAt - System.currentTimeMillis()).coerceAtLeast(1))
                    if (generation == stamp && session === verified) fail("login.expired")
                }
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { if (generation == stamp) fail(code(error)) }
        }
    }

    fun register(name: String) {
        if (mutable.value.phase != HomePhase.ENROLL) return
        val stamp = generation
        mutable.value = mutable.value.copy(phase = HomePhase.PREPARING, error = null, securitySetupRequired = false)
        job = scope.launch {
            try {
                val localKey = withContext(Dispatchers.IO) {
                    approval ?: owner!!.create(reference!!.scope(), DeviceKeyPurpose.APPROVAL, 1)
                }
                if (generation != stamp) { localKey.close(); return@launch }
                approval = localKey
                val request = api!!.prepareRegistration(PublicProofKey(localKey.publicJwk), name.trim())
                if (generation != stamp) { request.cancel(); return@launch }
                registration = request
                operation = withContext(Dispatchers.Default) { localKey.beginRegistration(request.signatureRequest) }
                val authenticationId = ++nextAuthenticationId
                mutable.value = mutable.value.copy(phase = HomePhase.AUTHENTICATING, authenticationId = authenticationId, biometric = BiometricLaunch(authenticationId, operation!!))
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) {
                if (generation == stamp) {
                    if (authorityLost(error)) fail(code(error))
                    else mutable.value = mutable.value.copy(phase = HomePhase.ENROLL, error = code(error),
                        securitySetupRequired = error is DeviceCryptoException && error.failure in setOf(DeviceCryptoFailure.LOCK_REQUIRED, DeviceCryptoFailure.BIOMETRIC_REQUIRED))
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
        mutable.value = mutable.value.copy(phase = HomePhase.REGISTERING, biometric = null, authenticationId = null)
        job = scope.launch {
            try {
                val signed = withContext(Dispatchers.Default) { active.finish(result) }
                if (generation != stamp) return@launch
                val device = request.submit(signed)
                if (generation != stamp) return@launch
                mutable.value = mutable.value.copy(phase = HomePhase.READY, deviceId = device.deviceId)
                refresh()
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) {
                if (generation == stamp) {
                    if (authorityLost(error)) fail(code(error)) else mutable.value = mutable.value.copy(phase = HomePhase.ENROLL, error = code(error))
                }
            }
            finally { active.close(); request.cancel() }
        }
    }

    fun authenticationCancelled(id: Long) {
        if (mutable.value.authenticationId != id) return
        discardRegistration()
        if (mutable.value.phase == HomePhase.AUTHENTICATING) mutable.value = mutable.value.copy(phase = HomePhase.ENROLL, biometric = null, authenticationId = null, error = "login.authentication_cancelled")
    }

    private fun discardRegistration() {
        operation?.close(); registration?.cancel(); operation = null; registration = null
    }

    fun refresh() {
        if (mutable.value.phase != HomePhase.READY || mutable.value.refreshing) return
        val stamp = generation
        mutable.value = mutable.value.copy(refreshing = true)
        job = scope.launch {
            try {
                val mappedAccount = api!!.me()
                if (generation != stamp) return@launch
                account = mappedAccount
                val hosts = api!!.hosts()
                if (hosts["ok"] != JsonBoolean(true)) throw RemoteRequestException("network.invalid_response")
                val names = hosts.obj("data").array("items").associate { item ->
                    val host = item as? JsonObject ?: throw RemoteRequestException("network.invalid_response")
                    Contract.uuid(host.string("id")) to Contract.boundedText(host.string("alias"), 160)
                }
                val response = api!!.runtimes()
                if (generation != stamp) return@launch
                if (response["ok"] != JsonBoolean(true)) throw RemoteRequestException("network.invalid_response")
                val items = response.obj("data").array("items").map { item ->
                    val row = item as? JsonObject ?: throw RemoteRequestException("network.invalid_response")
                    val hostId = Contract.uuid(row.string("host_id"))
                    val version = (row.fields["dsh_version"] as? JsonString)?.value ?: ""
                    if (version.isNotEmpty()) Contract.boundedText(version, 128)
                    RuntimeRow(Contract.uuid(row.string("id")), hostId, version, names[hostId] ?: "已授权的电脑")
                }
                mutable.value = mutable.value.copy(runtimes = items, error = null)
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) {
                if (generation == stamp) {
                    if (authorityLost(error)) fail(code(error))
                    else mutable.value = mutable.value.copy(error = code(error), runtimes = if (code(error) == "access.denied") emptyList() else mutable.value.runtimes)
                }
            }
            finally { if (generation == stamp) mutable.value = mutable.value.copy(refreshing = false) }
        }
    }

    fun cancel() { fail(null) }
    private fun fail(error: String?) {
        generation++; job?.cancel(); deadline?.cancel(); pending?.cancel(); discardRegistration()
        owner?.close()
        val old = reference
        owner = null; reference = null; proof = null; approval = null; pending = null; session = null; account = null; api = null
        mutable.value = HomeState(HomePhase.SIGNED_OUT, configuration?.issuer ?: "", error)
        if (old != null) scope.launch(Dispatchers.IO) { runCatching { ledger.delete(old) } }
    }
    private fun authorityLost(error: Exception): Boolean =
        (error is LoginException && error.failure in setOf(LoginFailure.EXPIRED, LoginFailure.IDENTITY)) ||
            (error is RemoteRequestException && error.code in setOf("auth.expired", "auth.identity_mismatch", "access.organization_missing", "access.denied", "access.revoked", "device.invalid"))
    private fun code(error: Exception): String = when (error) {
        is LoginException -> "login.${error.failure.name.lowercase()}"
        is RemoteRequestException -> error.code
        is DeviceCryptoException -> "device.${error.failure.name.lowercase()}"
        is DeviceProofException -> "auth.proof_invalid"
        else -> "network.unavailable"
    }
}

@HiltViewModel
class HomeViewModel @Inject constructor(private val login: LoginController) : ViewModel() {
    val state = login.state
    fun login() = login.login()
    fun register(name: String) = login.register(name)
    fun cancel() = login.cancel()
    fun refresh() = login.refresh()
    fun browserOpened(id: Long) = login.browserOpened(id)
    fun browserUnavailable() = login.browserUnavailable()
    fun promptOpened(id: Long) = login.promptOpened(id)
    fun authenticated(id: Long, result: BiometricPrompt.AuthenticationResult) = login.authenticated(id, result)
    fun authenticationCancelled(id: Long) = login.authenticationCancelled(id)
}
