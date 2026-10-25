package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class SessionApprovalAccount(val hostId: String, val key: RegisteredApprovalKey, val journal: ApprovalDecisionJournal) {
    init {
        Contract.uuid(hostId)
        if (!key.active || key.userId != journal.owner.userId || key.deviceId != journal.owner.deviceId) throw RemoteRequestException("auth.identity_mismatch")
    }
}
data class ApprovalClientState(val view: SessionApprovalState = SessionApprovalState(), val records: List<PendingApprovalDecision> = emptyList(),
    val supported: Boolean = false, val connected: Boolean = false, val contentReady: Boolean = false, val signing: Boolean = false, val sending: Boolean = false, val error: String? = null)

/** Foreground owner of approval controls on the reader's socket. HTTP never holds its model lock. */
class SessionApprovalClient internal constructor(private val api: RemoteApi, private val account: SessionApprovalAccount,
    private val runtime: String, private val session: String, owner: CoroutineScope) : AutoCloseable {
    private class SendLease(val handle: ApprovalReviewHandle, val context: ApprovalContext, val deadline: Long) { val active = AtomicBoolean(true) }
    private class Signing(val handle: ApprovalReviewHandle, val choice: ApprovalChoice, val prepared: PreparedApprovalSignature)
    private class StatusRpc(val approval: String, val result: CompletableDeferred<ApprovalStatus>)
    private class Endpoint(val connection: SessionRelayConnection, parent: CoroutineScope) {
        val scope = CoroutineScope(SupervisorJob(parent.coroutineContext[Job]) + Dispatchers.Default)
        val active = AtomicBoolean(true)
        val content = AtomicBoolean()
        val journalReady = AtomicBoolean()
        val watch = UUID.randomUUID().toString()
        val metadata = linkedMapOf<String, ApprovalStatus>()
        val pending = linkedMapOf<String, ApprovalStatus>()
        val persist = Channel<Unit>(Channel.CONFLATED)
        val refresh = Channel<Unit>(Channel.CONFLATED)
        val statusRequests = mutableMapOf<String, StatusRpc>()
        val retired = linkedSetOf<String>()
        var snapshot: JsonObject? = null
        var route: SessionRoute? = null
        var sync: String? = null
        var book: SessionApprovals? = null
        var details: String? = null
        var signing: Signing? = null
        @Volatile var lease: SendLease? = null
        var sending = false
        var watchDeadline = Long.MAX_VALUE
    }
    private val scope = CoroutineScope(SupervisorJob(owner.coroutineContext[Job]) + Dispatchers.Default)
    private val endpoint = AtomicReference<Endpoint?>()
    private val closed = AtomicBoolean()
    private val lock = Mutex()
    private val recordsLock = Mutex()
    private val mutable = MutableStateFlow(ApprovalClientState())
    val state: StateFlow<ApprovalClientState> = mutable.asStateFlow()
    init { scope.coroutineContext[Job]!!.invokeOnCompletion { close() } }

    @Synchronized internal fun connected(connection: SessionRelayConnection) {
        if (closed.get()) return
        disconnected()
        if (SIGNED_APPROVAL_CAPABILITY !in connection.identity.capabilities) {
            publishUnsupported(); return
        }
        val ep = Endpoint(connection, scope)
        endpoint.set(ep)
        ep.scope.launch {
            try {
                val originals = recordsLock.withLock { load(ep) }
                lock.withLock { requireCurrent(ep); ep.journalReady.set(true); rows(ep, originals) }
                ep.watchDeadline = System.nanoTime() + 10_000_000_000
                connection.send(ApprovalTransport.subscribe(runtime, ep.watch))
                launch { ticker(ep) }
                launch { persist(ep) }
                launch { reconcile(ep) }
                awaitCancellation()
            } catch (error: CancellationException) { throw error }
            catch (_: Exception) { failStorage(ep) }
            finally { withContext(NonCancellable) { lock.withLock {
                ep.book?.close(); ep.signing?.prepared?.cancel(); ep.lease?.active?.set(false)
                ep.statusRequests.values.forEach { it.result.cancel() }; ep.statusRequests.clear()
            } } }
        }
    }
    @Synchronized private fun publishUnsupported() { if (!closed.get()) mutable.value = ApprovalClientState(error = "approval.unsupported") }
    private fun requireCurrent(ep: Endpoint, content: Boolean = false) {
        if (closed.get() || endpoint.get() !== ep || !ep.active.get() || !ep.scope.isActive || content && (!ep.content.get() || !ep.journalReady.get())) throw ApprovalStateException("approval.stale")
        ep.connection.checkCurrent()
    }
    private fun current(content: Boolean = false) = (endpoint.get() ?: throw ApprovalStateException("approval.stale")).also { requireCurrent(it, content) }

    internal suspend fun contentReady(route: SessionRoute, sync: String) = lock.withLock {
        val ep = endpoint.get() ?: return@withLock
        requireCurrent(ep)
        if (route.runtimeId != runtime || route.sessionId != session) throw ProtocolException()
        if (ep.route != null && ep.route != route) throw ApprovalStateException("approval.resync_required")
        if (ep.route == route && ep.sync == sync && ep.content.get()) return@withLock
        if (ep.sync != null && ep.sync != sync) clearReview(ep)
        ep.route = route; ep.sync = sync; ep.content.set(true)
        installBook(ep); publish(ep)
    }
    internal suspend fun contentOffline() = lock.withLock {
        val ep = endpoint.get() ?: return@withLock
        ep.content.set(false); clearReview(ep); publish(ep)
    }
    private fun installBook(ep: Endpoint) {
        val route = ep.route ?: return
        val snapshot = ep.snapshot ?: return
        if (ep.book != null) return
        val book = SessionApprovals(route, account.hostId, ep.connection.identity.connectionId, ep.watch)
        book.snapshot(snapshot)
        ep.metadata.values.forEach { book.update(it) }
        ep.book = book
    }
    private fun put(ep: Endpoint, status: ApprovalStatus) {
        if (status.runtimeId != runtime) throw ProtocolException()
        if (status.sessionId != session) return
        if (status.id !in ep.metadata && ep.metadata.size >= 256) throw ApprovalStateException("approval.resync_required")
        val next = ep.metadata[status.id]?.advance(status) ?: status
        ep.metadata[status.id] = next; ep.book?.update(next)
    }
    private fun enqueue(ep: Endpoint, status: ApprovalStatus) {
        if (status.sessionId != session) return
        if (status.id !in ep.pending && ep.pending.size >= 64) throw ApprovalStateException("approval.resync_required")
        ep.pending[status.id] = ep.pending[status.id]?.advance(status) ?: status
        ep.persist.trySend(Unit)
    }
    internal suspend fun accept(frame: JsonObject) = lock.withLock {
        val ep = current()
        val id = Contract.uuid(frame.string("request_id"))
        when (frame.string("type")) {
            "approval.snapshot" -> {
                if (ep.snapshot != null) throw ProtocolException()
                val statuses = ApprovalTransport.snapshot(frame, runtime, ep.watch)
                ep.snapshot = frame
                statuses.forEach { put(ep, it); enqueue(ep, it) }
                installBook(ep)
            }
            "approval.reference" -> {
                val rpc = ep.statusRequests[id]
                if (id != ep.watch && rpc == null) {
                    if (id in ep.retired) return@withLock
                    throw ProtocolException()
                }
                if (id == ep.watch && ep.snapshot == null) throw ProtocolException()
                val status = ApprovalTransport.reference(frame, runtime, id)
                if (rpc != null && (rpc.approval != status.id || status.sessionId != session)) throw ProtocolException()
                put(ep, status); enqueue(ep, status); rpc?.result?.complete(status)
            }
            "approval.details", "approval.fragment", "approval.error" -> {
                if (id != ep.details) {
                    if (id in ep.retired) return@withLock
                    throw ProtocolException()
                }
                val book = ep.book ?: throw ProtocolException()
                if (frame.string("type") == "approval.error") { book.detailsError(frame); retire(ep, id); ep.details = null }
                else if (book.details(frame) != null) { retire(ep, id); ep.details = null }
            }
            else -> throw ProtocolException()
        }
        publish(ep)
    }
    internal suspend fun error(frame: JsonObject, code: String): Boolean = lock.withLock {
        val ep = endpoint.get() ?: return@withLock false
        val id = (frame.fields["request_id"] as? JsonString)?.value ?: return@withLock false
        when {
            id == ep.watch -> { throw ApprovalStateException("approval.resync_required") }
            id == ep.details -> { ep.book?.detailsFailed(id, code); retire(ep, id); ep.details = null; publish(ep); true }
            id in ep.statusRequests -> { ep.statusRequests[id]!!.result.completeExceptionally(RemoteRequestException(code)); true }
            else -> id in ep.retired
        }
    }
    suspend fun requestDetails(approval: String) {
        val ep = current(true)
        val frame = lock.withLock {
            requireCurrent(ep, true); clearReview(ep)
            val id = UUID.randomUUID().toString()
            (ep.book ?: throw ApprovalStateException("approval.stale")).beginDetails(approval, id).also { ep.details = id; publish(ep, error = null) }
        }
        try { ep.connection.send(frame) } catch (failure: Exception) { ep.connection.close(); throw failure }
    }
    suspend fun dismissReview() = lock.withLock { endpoint.get()?.let { clearReview(it); publish(it) } }
    private fun clearReview(ep: Endpoint) {
        ep.details?.let { retire(ep, it) }; ep.details = null
        ep.signing?.prepared?.cancel(); ep.signing = null; ep.lease?.active?.set(false); ep.lease = null
        ep.book?.clearReview()
    }
    suspend fun prepareSignature(handle: ApprovalReviewHandle, choice: ApprovalChoice): PreparedApprovalSignature {
        val ep = current(true)
        return lock.withLock {
            currentCoroutineContext().ensureActive()
            requireCurrent(ep, true)
            if (ep.signing != null || ep.sending) throw ApprovalStateException("approval.busy")
            if (mutable.value.records.any { it.intent.approvalId == handle.approvalId }) throw CommandDataException("approval.reconcile_required")
            val context = ep.book?.requireReview(handle) ?: throw ApprovalStateException("approval.stale")
            val prepared = ApprovalSignatures.prepare(context, choice, account.key, System.currentTimeMillis())
            ep.signing = Signing(handle, choice, prepared); publish(ep, error = null)
            prepared
        }
    }
    suspend fun cancelSignature(expected: PreparedApprovalSignature? = null) = lock.withLock { endpoint.get()?.let {
        if (expected == null || it.signing?.prepared === expected) { it.signing?.prepared?.cancel(); it.signing = null; publish(it) }
    } }

    suspend fun submit(handle: ApprovalReviewHandle, signed: SignedApprovalDecision): String {
        val ep = current(true)
        val lease = lock.withLock {
            requireCurrent(ep, true)
            val signing = ep.signing ?: throw ApprovalStateException("approval.stale")
            if (signing.handle != handle || signing.choice != signed.decision.choice || ep.sending) throw ApprovalStateException("approval.stale")
            lease(ep, handle).also { ep.sending = true; ep.signing = null; publish(ep, error = null) }
        }
        var saved: ApprovalDecisionIntent? = null
        try {
            val intent = ApprovalDecisionIntent.create(UUID.randomUUID().toString(), account.journal.owner, account.key, lease.context, signed, System.currentTimeMillis())
            recordsLock.withLock { checkLease(ep, lease, intent); account.journal.create(intent); saved = intent }
            syncRows(ep)
            send(ep, lease, intent, false)
            return intent.requestId
        } catch (failure: CancellationException) { throw failure }
        catch (failure: Exception) { saved?.let { markUncertain(ep, it.requestId, failure) }; throw failure }
        finally { withContext(NonCancellable) { lock.withLock { ep.sending = false; ep.lease?.active?.set(false); publish(ep) } }; query() }
    }
    suspend fun sendPending(handle: ApprovalReviewHandle, id: String) {
        val ep = current(true)
        val lease = lock.withLock {
            requireCurrent(ep, true)
            if (ep.sending || ep.signing != null) throw ApprovalStateException("approval.busy")
            lease(ep, handle).also { ep.sending = true; publish(ep, error = null) }
        }
        try {
            val row = recordsLock.withLock { load(ep).singleOrNull { it.intent.requestId == Contract.uuid(id) } }
                ?: throw CommandDataException("approval.not_found")
            if (!row.intent.context.let { lease.context.bindingSha256 == it.bindingSha256 } || row.intent.approvalId != handle.approvalId) throw CommandDataException("approval.request_conflict")
            send(ep, lease, row.intent, row.attempts > 0)
        } catch (failure: CancellationException) { throw failure }
        catch (failure: Exception) { markUncertain(ep, id, failure); throw failure }
        finally { withContext(NonCancellable) { lock.withLock { ep.sending = false; ep.lease?.active?.set(false); publish(ep) } }; query() }
    }
    private fun lease(ep: Endpoint, handle: ApprovalReviewHandle): SendLease {
        val context = ep.book?.requireReview(handle) ?: throw ApprovalStateException("approval.stale")
        val remaining = ep.book!!.state().items.single { it.handle == handle }.remainingMillis
        return SendLease(handle, context, System.nanoTime() + remaining * 1_000_000).also { ep.lease?.active?.set(false); ep.lease = it }
    }
    private fun checkLease(ep: Endpoint, lease: SendLease, intent: ApprovalDecisionIntent) {
        requireCurrent(ep, true)
        if (!lease.active.get() || System.nanoTime() >= lease.deadline || !lease.context.current(System.currentTimeMillis()) || !intent.current(System.currentTimeMillis()) ||
            intent.context.bindingSha256 != lease.context.bindingSha256) throw ApprovalStateException("approval.stale")
        if (!visible(ep, intent)) throw RemoteRequestException("access.denied")
    }
    private suspend fun send(ep: Endpoint, lease: SendLease, intent: ApprovalDecisionIntent, retry: Boolean) {
        val proof = if (retry) status(ep, intent.approvalId) else null
        val attempted = recordsLock.withLock {
            // Background reconciliation cannot retire the manual retry between
            // its pending proof and the next durable attempt marker.
            if (proof != null) account.journal.rearm(intent.requestId, proof)
            checkLease(ep, lease, intent)
            account.journal.beginAttempt(intent.requestId)
        }
        syncRows(ep)
        val call = ep.scope.async { api.submitApproval(ep.connection.identity.connectionId, attempted.intent, account.journal.owner) { checkLease(ep, lease, attempted.intent) } }
        val response = try { call.await() } finally { call.cancel() }
        recordsLock.withLock { account.journal.record(intent.requestId, response.status, forwarding = response.delivery) }
        lock.withLock { if (endpoint.get() === ep) { put(ep, response.status); publish(ep) } }
        syncRows(ep)
    }
    private suspend fun markUncertain(ep: Endpoint, id: String, failure: Exception) {
        val code = when (failure) { is CommandDataException -> failure.code; is ApprovalStateException -> failure.code; is RemoteRequestException -> failure.code; else -> "approval.delivery_unconfirmed" }
        runCatching { recordsLock.withLock { account.journal.uncertain(id, code) }; syncRows(ep) }
        lock.withLock { publish(ep, error = code) }
    }
    fun query() { endpoint.get()?.refresh?.trySend(Unit) }
    suspend fun discardUnsent(id: String) {
        val ep = current()
        val original = recordsLock.withLock {
            requireCurrent(ep)
            val original = load(ep).singleOrNull { it.intent.requestId == Contract.uuid(id) } ?: throw CommandDataException("approval.not_found")
            account.journal.discard(id)
            original
        }
        lock.withLock { if (endpoint.get() === ep) {
            if (ep.book?.state()?.items?.any { it.handle?.approvalId == original.intent.approvalId } == true) clearReview(ep)
            publish(ep)
        } }
        syncRows(ep)
    }
    private suspend fun status(ep: Endpoint, approval: String): ApprovalStatus {
        val id = UUID.randomUUID().toString(); val result = CompletableDeferred<ApprovalStatus>(ep.scope.coroutineContext[Job])
        lock.withLock { requireCurrent(ep); if (ep.statusRequests.size >= 4) throw ApprovalStateException("approval.busy"); ep.statusRequests[id] = StatusRpc(approval, result) }
        try {
            ep.connection.send(ApprovalTransport.status(runtime, id, approval))
            return withTimeout(5000) { result.await() }
        } finally { withContext(NonCancellable) { lock.withLock { ep.statusRequests.remove(id); retire(ep, id); result.cancel() } } }
    }
    private suspend fun reconcile(ep: Endpoint) {
        while (ep.scope.isActive) {
            try {
                val originals = recordsLock.withLock { load(ep) }
                for (row in originals) {
                    if (row.delivery in setOf(ApprovalDecisionDelivery.CONFLICT, ApprovalDecisionDelivery.ENDED) || row.remote?.hostState in setOf(ApprovalHostState.SETTLED, ApprovalHostState.DENIED, ApprovalHostState.EXPIRED, ApprovalHostState.CANCELLED, ApprovalHostState.INVALIDATED)) continue
                    val proof = status(ep, row.intent.approvalId)
                    recordsLock.withLock { account.journal.record(row.intent.requestId, proof) }
                    delay(100)
                }
                syncRows(ep)
            } catch (failure: CancellationException) { throw failure }
            catch (_: Exception) { lock.withLock { publish(ep, error = "approval.status_unavailable") } }
            withTimeoutOrNull(5000) { ep.refresh.receive() }
        }
    }
    private suspend fun persist(ep: Endpoint) {
        for (ignored in ep.persist) {
            val batch = lock.withLock { ep.pending.values.toList().also { ep.pending.clear() } }
            try {
                recordsLock.withLock {
                    val originals = load(ep)
                    for (status in batch) originals.filter { it.intent.approvalId == status.id }.forEach { account.journal.record(it.intent.requestId, status) }
                }
                syncRows(ep)
            } catch (failure: CancellationException) { throw failure }
            catch (_: Exception) { failStorage(ep) }
        }
    }
    private suspend fun syncRows(ep: Endpoint) {
        val originals = recordsLock.withLock { load(ep) }
        lock.withLock { if (endpoint.get() === ep && ep.active.get()) rows(ep, originals) }
    }
    private fun rows(ep: Endpoint, originals: List<PendingApprovalDecision>) {
        originals.forEach { it.remote?.let { status -> put(ep, status) } }
        publish(ep, originals)
    }
    private fun visible(ep: Endpoint, intent: ApprovalDecisionIntent): Boolean = intent.sessionId in ep.connection.identity.scope.sessions ||
        intent.context.root.obj("workspace").string("workspace_id") in ep.connection.identity.scope.workspaces
    private suspend fun load(ep: Endpoint) = account.journal.list(runtime, session).filter { visible(ep, it.intent) }
    private suspend fun ticker(ep: Endpoint) {
        while (ep.scope.isActive) {
            delay(250)
            lock.withLock {
                if (ep.snapshot == null && System.nanoTime() >= ep.watchDeadline) { ep.connection.close(); return }
                if (ep.book?.detailsTimedOut() == true) { ep.details?.let { ep.book?.detailsFailed(it, "approval.unavailable"); retire(ep, it) }; ep.details = null }
                publish(ep)
            }
        }
    }
    private fun retire(ep: Endpoint, id: String) { ep.retired += id; if (ep.retired.size > 256) ep.retired.remove(ep.retired.first()) }
    private suspend fun failStorage(ep: Endpoint) = lock.withLock {
        ep.journalReady.set(false); clearReview(ep); publish(ep, error = "data.unavailable")
    }
    @Synchronized private fun publish(ep: Endpoint, records: List<PendingApprovalDecision> = mutable.value.records, error: String? = mutable.value.error) {
        if (closed.get() || endpoint.get() !== ep || !ep.active.get()) return
        val view = ep.book?.state() ?: SessionApprovalState(loaded = ep.snapshot != null)
        if (ep.details != null && view.loadingId == null) { retire(ep, ep.details!!); ep.details = null }
        ep.signing?.let { signing -> if (view.items.none { it.handle == signing.handle && it.canReview }) { signing.prepared.cancel(); ep.signing = null } }
        ep.lease?.let { lease -> if (view.items.none { it.handle == lease.handle && it.canReview }) lease.active.set(false) }
        mutable.value = ApprovalClientState(view, records, true, ep.journalReady.get(), ep.content.get(), ep.signing != null, ep.sending, error)
    }
    @Synchronized internal fun disconnected() {
        val old = endpoint.getAndSet(null)
        old?.active?.set(false); old?.content?.set(false); old?.lease?.active?.set(false); old?.scope?.cancel()
        mutable.value = ApprovalClientState()
    }
    @Synchronized override fun close() { if (closed.compareAndSet(false, true)) { disconnected(); scope.cancel() } }
}
