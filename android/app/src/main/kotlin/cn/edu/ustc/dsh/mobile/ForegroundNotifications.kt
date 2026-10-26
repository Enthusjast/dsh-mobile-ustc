package cn.edu.ustc.dsh.mobile

import cn.edu.ustc.dsh.command.CommandOwner
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*

enum class NotificationPhase { LOADING, UNCONFIGURED, UNAVAILABLE, DISABLED, WAITING, ACTIVE, ERROR }
data class NotificationUiState(val phase: NotificationPhase = NotificationPhase.LOADING, val busy: Boolean = false, val allowed: Boolean = false, val canEnable: Boolean = false,
    val expiresAt: Long? = null, val error: String? = null, val items: List<NotificationReference> = emptyList(), val cursor: String? = null, val note: String? = null)

/** Foreground authenticated enrollment/read flow. Receiving and deletion-only work have no account token. */
internal class ForegroundNotifications(private val api: RemoteApi, private val http: LoginHttp, private val center: NotificationCenter, private val provider: DevicePushProvider,
    private val owner: CommandOwner, private val origin: String, parent: CoroutineScope, private val current: () -> Unit, private val navigate: (NotificationReference) -> Unit) : AutoCloseable {
    private val scope = CoroutineScope(SupervisorJob(parent.coroutineContext[Job]) + Dispatchers.Main.immediate)
    private val mutable = MutableStateFlow(NotificationUiState())
    val state = mutable.asStateFlow()
    private var action: Job? = null
    private var readJob: Job? = null
    private var capabilities: PushCapabilities? = null
    init { refresh() }
    private fun check() { current(); if (!scope.isActive) throw CancellationException() }
    private fun owned(): PushRoute? = center.snapshot().route?.takeIf { it.owner == owner.fingerprint && it.deployment == owner.deploymentHash && it.publicConfig == provider.configuration?.fingerprint }
    private fun code(error: Exception): String = when (error) {
        is RemoteRequestException -> error.code
        is ProtocolException -> "protocol.invalid"
        else -> error.message?.takeIf { it in setOf("push.stale", "push.cleanup_required", "push.cleanup_failed", "push.storage_unavailable", "push.provider_unavailable", "push.permission_required", "push.not_configured", "push.services_unavailable") } ?: "push.unavailable"
    }
    private fun perform(work: suspend () -> Unit) {
        if (action?.isActive == true || !scope.isActive) return
        mutable.update { it.copy(busy = true, error = null) }
        action = scope.launch {
            try { check(); work() }
            catch (error: CancellationException) { throw error }
            catch (error: Exception) { if (scope.isActive) mutable.update { it.copy(phase = NotificationPhase.ERROR, error = code(error)) } }
            finally { if (scope.isActive) mutable.update { it.copy(busy = false) } }
        }
    }
    fun refresh() = perform {
        val config = provider.configuration
        center.reconcileDeployment(owner.deploymentHash, config?.fingerprint)
        center.ensureChannel()
        val available = provider.availability()
        if (config == null) { mutable.value = NotificationUiState(NotificationPhase.UNCONFIGURED, error = "push.not_configured", allowed = center.allowed()); return@perform }
        val caps = api.pushCapabilities(); check()
        if (caps.project != config.projectId || caps.packageName != config.packageName) throw RemoteRequestException("auth.identity_mismatch")
        capabilities = caps
        val route = owned()
        if (center.snapshot().route != null && route == null) center.retire()
        val allowed = center.allowed()
        if (route?.active == true && !allowed) { center.retire(owner.fingerprint); mutable.value = NotificationUiState(NotificationPhase.DISABLED, allowed = false, error = "push.permission_required"); return@perform }
        if (route != null) {
            val binding = api.pushStatus(route.id); check(); center.update(owner.fingerprint, binding)
            showBinding(binding, available, allowed)
            if (binding.state == PushBindingState.ACTIVE) flushReceipts()
        } else mutable.value = NotificationUiState(if (available == "ready") NotificationPhase.DISABLED else NotificationPhase.UNAVAILABLE, allowed = allowed, canEnable = available == "ready" && allowed, error = available.takeIf { it != "ready" })
        center.drain(http)
    }
    private fun showBinding(binding: PushBinding, available: String, allowed: Boolean) {
        mutable.update { it.copy(phase = when (binding.state) { PushBindingState.PENDING -> NotificationPhase.WAITING; PushBindingState.ACTIVE -> NotificationPhase.ACTIVE; else -> NotificationPhase.DISABLED },
            expiresAt = binding.expiresAt, allowed = allowed, canEnable = available == "ready" && allowed, error = null) }
    }
    fun enable() = perform {
        val config = provider.configuration ?: throw IllegalStateException("push.not_configured")
        val caps = capabilities ?: api.pushCapabilities().also { capabilities = it }
        if (caps.project != config.projectId || caps.packageName != config.packageName) throw RemoteRequestException("auth.identity_mismatch")
        if (!center.allowed()) throw IllegalStateException("push.permission_required")
        if (provider.availability() != "ready") throw IllegalStateException(provider.availability())
        if (!center.drain(http)) throw IllegalStateException("push.cleanup_failed")
        val fid = provider.register(); check()
        var route = owned()
        if (route != null && (route.address != fid || route.expires <= System.currentTimeMillis())) { center.retire(owner.fingerprint); route = null }
        if (route == null) {
            if (!center.drain(http)) throw IllegalStateException("push.cleanup_failed")
            check(); route = center.stage(owner.fingerprint, owner.deploymentHash, config, origin, owner.organizationId, fid)
        }
        val original = route
        var binding = api.registerPush(original.registration(), ::check); check(); center.update(owner.fingerprint, binding)
        showBinding(binding, "ready", true)
        if (binding.state == PushBindingState.PENDING) {
            val challenge = withTimeoutOrNull((binding.challengeExpiresAt - System.currentTimeMillis()).coerceAtLeast(1)) {
                while (true) { check(); center.challenge(owner.fingerprint, original.id)?.let { return@withTimeoutOrNull it }; delay(200) }
                @Suppress("UNREACHABLE_CODE") null
            } ?: throw RemoteRequestException("push.expired")
            check(); binding = api.confirmPush(original.id, challenge, ::check); check(); center.update(owner.fingerprint, binding)
            showBinding(binding, "ready", true)
        }
        if (binding.state == PushBindingState.ACTIVE) flushReceipts()
    }
    fun renew() = perform {
        val route = owned()?.takeIf { it.active } ?: throw IllegalStateException("push.stale")
        if (!center.allowed()) throw IllegalStateException("push.permission_required")
        val binding = api.renewPush(route.id, ::check); check(); center.update(owner.fingerprint, binding); showBinding(binding, provider.availability(), true)
    }
    fun disable() {
        cancelRead()
        action?.cancel()
        center.retire(owner.fingerprint)
        mutable.value = NotificationUiState(NotificationPhase.DISABLED, allowed = center.allowed(), canEnable = provider.availability() == "ready" && center.allowed())
        action = scope.launch {
            runCatching { provider.unregister() }
            if (!center.drain(http)) mutable.update { it.copy(error = "push.cleanup_failed") }
        }
    }
    private suspend fun flushReceipts() {
        val snapshot = center.snapshot(); val route = snapshot.route?.takeIf { it.owner == owner.fingerprint && it.active } ?: return
        for (receipt in snapshot.receipts) {
            check()
            try { api.notificationReceipt(receipt.id, receipt.state, ::check); center.receiptDone(owner.fingerprint, receipt) }
            catch (error: CancellationException) { throw error }
            catch (error: RemoteRequestException) { if (error.code in setOf("access.denied", "push.expired")) center.receiptDone(owner.fingerprint, receipt) else throw error }
        }
    }
    fun inbox(more: Boolean = false) {
        cancelRead()
        readJob = scope.launch {
            try {
                check(); val route = owned()?.takeIf { it.active && it.expires > System.currentTimeMillis() } ?: throw IllegalStateException("push.stale")
                val page = api.notificationInbox(route.id, if (more) mutable.value.cursor else null); check()
                if (!center.matches(owner.fingerprint, route.id)) throw IllegalStateException("push.stale")
                mutable.update { it.copy(items = if (more) (it.items + page.items).distinctBy { row -> row.id }.takeLast(256) else page.items, cursor = page.cursor, error = null) }
                flushReceipts()
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { mutable.update { it.copy(error = code(error)) } }
        }
    }
    fun open(binding: String, id: String?) {
        cancelRead()
        readJob = scope.launch {
            try {
                check(); val route = owned()?.takeIf { it.id == binding && it.active && it.expires > System.currentTimeMillis() } ?: throw IllegalStateException("push.stale")
                if (id == null) { inbox(); return@launch }
                val ref = api.notification(id, route.id, ::check); check()
                if (!center.matches(owner.fingerprint, binding)) throw IllegalStateException("push.stale")
                center.opened(owner.fingerprint, id); flushReceipts()
                check()
                if (!center.matches(owner.fingerprint, binding)) throw IllegalStateException("push.stale")
                if (ref.kind != "approval") mutable.update { it.copy(items = listOf(ref), note = "此版本暂不支持该提醒入口，请从在线会话核对交互。", error = null) }
                else if (!ref.actionable()) mutable.update { it.copy(items = listOf(ref), note = notificationReferenceText(ref), error = null) }
                else navigate(ref)
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { mutable.update { it.copy(error = code(error)) } }
        }
    }
    fun cancelRead() { readJob?.cancel(); readJob = null }
    override fun close() { scope.cancel(); center.retirePending(owner.fingerprint) }
}

internal fun notificationReferenceText(ref: NotificationReference) = when {
    ref.availability == "host_offline" -> "主机离线，无法核对当前详情。"
    ref.availability == "stale_epoch" -> "提醒对应的运行代次已结束。"
    !ref.actionable() -> "提醒已结束或过期。"
    ref.kind == "question" -> "有待核对的用户提问"
    ref.kind == "timed_question" -> "有待核对的限时提问"
    else -> "有待核对的工具审批"
}
