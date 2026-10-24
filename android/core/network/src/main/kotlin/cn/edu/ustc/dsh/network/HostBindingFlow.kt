package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.auth.*
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*

enum class HostBindingPhase { ENTER, LOADING, REVIEW, CONFIRMING, CHECKING, UNKNOWN, WAITING_HOST, WAITING_ACCESS, READY, UNAVAILABLE, ERROR, PAUSED, CLOSED }
data class HostBindingState(val phase: HostBindingPhase = HostBindingPhase.ENTER, val id: String = "", val details: HostBindingDetails? = null, val error: String? = null, val formRevision: Long = 0)
internal class HostBindingOptions(val pollMillis: Long = 3000, val pollingMillis: Long = 60_000)

/** One foreground binding intent. Reads may resume; confirmation is always an explicit action. */
class HostBindingFlow internal constructor(
    private val api: RemoteApi, owner: CoroutineScope, private val initialId: String?,
    private val onAuthorityFailure: (String) -> Unit, private val onReady: () -> Unit,
    private val options: HostBindingOptions = HostBindingOptions(),
) : AutoCloseable {
    private val scope = CoroutineScope(owner.coroutineContext + SupervisorJob(owner.coroutineContext[Job]))
    private val mutable = MutableStateFlow(HostBindingState(id = initialId ?: ""))
    val state: StateFlow<HostBindingState> = mutable.asStateFlow()
    private var job: Job? = null
    private var intent: HostBindingRequest? = null
    private var generation = 0L
    private var active = false
    private var closed = false
    private var publicResumeId: String? = initialId
    val resumeId: String? @Synchronized get() = publicResumeId
    init {
        initialId?.let(Contract::uuid)
        scope.coroutineContext[Job]!!.invokeOnCompletion { close() }
    }
    @Synchronized private fun current(stamp: Long) {
        if (closed || !active || generation != stamp || !scope.isActive) throw CancellationException("Binding view was retired")
    }
    @Synchronized private fun publish(stamp: Long, state: HostBindingState) { current(stamp); mutable.value = state }
    @Synchronized private fun retire(): Long {
        generation++; job?.cancel(); job = null; intent?.close(); intent = null
        return generation
    }
    private fun start(stamp: Long, block: suspend () -> Unit) {
        val task = scope.launch(start = CoroutineStart.LAZY) { block() }
        synchronized(this) { current(stamp); job = task; task.start() }
    }
    @Synchronized fun foreground(value: Boolean) {
        if (closed || active == value) return
        active = value
        if (!value) {
            retire()
            mutable.value = HostBindingState(if (publicResumeId == null) HostBindingPhase.ENTER else HostBindingPhase.PAUSED,
                mutable.value.id, error = if (publicResumeId == null) "binding.review_cleared" else null, formRevision = mutable.value.formRevision + 1)
        } else publicResumeId?.let(::lookup)
    }
    @Synchronized fun preview(id: String, code: String) {
        if (closed || !active) return
        val stamp = retire()
        val target = try { Contract.uuid(id.trim().lowercase()) } catch (_: ProtocolException) {
            mutable.value = HostBindingState(error = "binding.input_invalid", formRevision = mutable.value.formRevision + 1); return
        }
        val secret = code.trim()
        try { Contract.nonce(secret) } catch (_: ProtocolException) {
            mutable.value = HostBindingState(id = target, error = "binding.input_invalid", formRevision = mutable.value.formRevision + 1); return
        }
        publicResumeId = null
        mutable.value = HostBindingState(HostBindingPhase.LOADING, target)
        start(stamp) {
            var opened: HostBindingRequest? = null
            try {
                opened = api.prepareHostBinding(target, secret)
                current(stamp)
                val details = opened.details
                if (details.confirmedByMe) {
                    opened.close(); opened = null
                    synchronized(this) { current(stamp); publicResumeId = target }
                    observe(stamp, details)
                } else if (!details.canConfirm()) {
                    publish(stamp, HostBindingState(HostBindingPhase.UNAVAILABLE, target, details, unavailable(details)))
                } else {
                    synchronized(this) { current(stamp); intent = opened; opened = null }
                    publish(stamp, HostBindingState(HostBindingPhase.REVIEW, target, details))
                    delay(reviewLifetime(details))
                    synchronized(this) { current(stamp); intent?.close(); intent = null }
                    publish(stamp, HostBindingState(HostBindingPhase.UNAVAILABLE, target, details, "binding.expired"))
                }
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { failed(stamp, target, error) }
            finally { opened?.close() }
        }
    }
    @Synchronized fun confirm() {
        if (closed || !active || mutable.value.phase != HostBindingPhase.REVIEW) return
        val prepared = intent ?: return
        val details = prepared.details
        if (!details.canConfirm()) { retire(); mutable.value = HostBindingState(HostBindingPhase.UNAVAILABLE, details.id, details, unavailable(details)); return }
        intent = null // Transfer ownership before retiring the review's expiry job.
        val stamp = retire()
        mutable.value = HostBindingState(HostBindingPhase.CONFIRMING, details.id, details)
        start(stamp) {
            try {
                val accepted = prepared.confirm {
                    synchronized(this) { current(stamp); publicResumeId = details.id }
                }
                current(stamp)
                synchronized(this) { current(stamp); publicResumeId = details.id }
                observe(stamp, accepted)
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { failed(stamp, details.id, error, details) }
            finally { prepared.close() }
        }
    }
    @Synchronized fun lookup(id: String = mutable.value.id) {
        if (closed || !active) return
        val stamp = retire()
        val target = try { Contract.uuid(id.trim().lowercase()) } catch (_: ProtocolException) {
            mutable.value = HostBindingState(error = "binding.input_invalid", formRevision = mutable.value.formRevision + 1); return
        }
        mutable.value = HostBindingState(HostBindingPhase.CHECKING, target)
        start(stamp) {
            try {
                val details = api.bindingStatus(target); current(stamp)
                if (!details.confirmedByMe) {
                    synchronized(this) { current(stamp); publicResumeId = null }
                    publish(stamp, HostBindingState(HostBindingPhase.ENTER, target, error = "binding.code_required"))
                } else {
                    synchronized(this) { current(stamp); publicResumeId = target }
                    observe(stamp, details)
                }
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { failed(stamp, target, error) }
        }
    }
    @Synchronized fun enterAnother() {
        if (closed || !active) return
        retire(); publicResumeId = null
        mutable.value = HostBindingState(formRevision = mutable.value.formRevision + 1)
    }
    private suspend fun observe(stamp: Long, original: HostBindingDetails) {
        var details = original
        val pollingDeadline = System.nanoTime() + options.pollingMillis * 1_000_000
        while (true) {
            current(stamp)
            if (!details.confirmedByMe || details.protocolVersion != 1L || details.expired() || details.state in setOf("denied", "cancelled")) {
                publish(stamp, HostBindingState(HostBindingPhase.UNAVAILABLE, details.id, details, unavailable(details))); return
            }
            var phase = HostBindingPhase.WAITING_HOST
            if (details.state == "approved") {
                val response = api.runtimes(); current(stamp)
                response.exactKeys("ok", "data")
                if (response["ok"] != JsonBoolean(true)) throw ProtocolException()
                val entries = response.obj("data").array("items").map { RuntimeDirectoryEntry.parse(it as? JsonObject ?: throw ProtocolException()) }
                val grant = entries.singleOrNull { it.id == details.runtimeId }
                if (grant != null && grant.organizationId == details.organizationId && grant.hostId == details.hostId && grant.protocolVersion == 1L &&
                    grant.scope?.actions?.any { it in setOf("host.list", "session.list") } == true && (grant.expiresAt == null || grant.expiresAt > System.currentTimeMillis())) {
                    publish(stamp, HostBindingState(HostBindingPhase.READY, details.id, details)); onReady(); return
                }
                phase = HostBindingPhase.WAITING_ACCESS
            }
            publish(stamp, HostBindingState(phase, details.id, details))
            if (System.nanoTime() >= pollingDeadline) {
                if (details.state != "approved") {
                    delay(reviewLifetime(details))
                    publish(stamp, HostBindingState(HostBindingPhase.UNAVAILABLE, details.id, details, "binding.expired"))
                }
                return
            }
            delay(minOf(options.pollMillis, reviewLifetime(details)))
            val next = api.bindingStatus(details.id); current(stamp)
            if (next.reviewHash != original.reviewHash) throw HostBindingException("binding.details_changed")
            details = next
        }
    }
    private fun reviewLifetime(details: HostBindingDetails) = (details.expiresAt - System.currentTimeMillis()).coerceIn(1, 300_000)
    private fun unavailable(details: HostBindingDetails) = when {
        details.protocolVersion != 1L -> "binding.protocol_unsupported"
        details.expired() -> "binding.expired"
        details.userConfirmed && !details.confirmedByMe -> "binding.confirmed_elsewhere"
        else -> "binding.unavailable"
    }
    private fun failed(stamp: Long, id: String, error: Exception, details: HostBindingDetails? = null) {
        val code = when (error) {
            is HostBindingException -> error.code
            is RemoteRequestException -> if (error.code in authorityErrors) error.code else "network.unavailable"
            is LoginException -> "auth.expired"
            is ProtocolException -> "protocol.invalid"
            else -> "network.unavailable"
        }
        val uncertain = synchronized(this) { current(stamp); publicResumeId == id }
        publish(stamp, HostBindingState(if (uncertain) HostBindingPhase.UNKNOWN else HostBindingPhase.ERROR, id, details, code))
        if (code in authorityErrors) onAuthorityFailure(code)
    }
    @Synchronized override fun close() {
        if (closed) return
        closed = true; retire(); scope.cancel(); mutable.value = HostBindingState(HostBindingPhase.CLOSED)
    }
    companion object { private val authorityErrors = setOf("auth.expired", "auth.proof_invalid", "auth.identity_mismatch", "access.denied", "access.revoked", "access.organization_missing", "device.invalid") }
}
