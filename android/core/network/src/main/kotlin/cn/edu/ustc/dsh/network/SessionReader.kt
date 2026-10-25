package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.auth.LoginException
import cn.edu.ustc.dsh.auth.LoginFailure
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import cn.edu.ustc.dsh.command.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

enum class SessionReadPhase { CONNECTING, SYNCING, READY, BACKOFF, OFFLINE, AUTH_REQUIRED, REVOKED, ERROR, CLOSED }
data class SessionReadState(val phase: SessionReadPhase, val window: SessionTranscript? = null, val error: String? = null, val loadingOlder: Boolean = false, val pageError: String? = null, val runtimeEpoch: String? = null, val cacheError: String? = null)
internal class SessionReaderOptions(val heartbeatMillis: Long = 20_000, val openingMillis: Long = 15_000, val pageMillis: Long = 15_000,
    val backoffMillis: (Int) -> Long = { retry -> val cap = minOf(60_000L, 1000L shl retry.coerceAtMost(6)); cap / 2 + SecureRandom().nextInt((cap / 2 + 1).toInt()) })

/** One foreground session. Each physical reconnection obtains a fresh ticket/subscription/snapshot. */
class SessionReader internal constructor(
    private val api: RemoteApi, private val deviceId: String, private val runtimeId: String, private val sessionId: String,
    private val readScope: RelayScope, owner: CoroutineScope, private val options: SessionReaderOptions = SessionReaderOptions(), private val journal: CommandJournal? = null,
    private val transcripts: TranscriptCache? = null, private val workspaceId: String? = null,
) : AutoCloseable {
    private val scope = CoroutineScope(SupervisorJob(owner.coroutineContext[Job]) + Dispatchers.Default)
    val commands: SessionCommands?
    private val mutable = MutableStateFlow(SessionReadState(SessionReadPhase.CONNECTING))
    val state: StateFlow<SessionReadState> = mutable.asStateFlow()
    private val connection = AtomicReference<SessionRelayConnection?>()
    private val closed = AtomicBoolean()
    private val pages = Channel<Unit>(1)
    private val retries = Channel<Unit>(Channel.CONFLATED)
    private val cache = AtomicReference<SessionTranscript?>()
    private val cacheUntil = AtomicLong()
    private val cacheDeadline = AtomicLong()
    private val cacheSince = AtomicLong()
    private val leaseConnection = AtomicReference<String?>()
    private var cacheEpoch: String? = null
    private var maxMessages = 30
    private class CacheWrite(val generation: Long, val epoch: String, val transcript: SessionTranscript, val now: Long)
    private val cacheWrites = Channel<CacheWrite>(Channel.CONFLATED)
    private val cacheGeneration = AtomicLong()
    private val cacheLock = Mutex()
    private val cacheProblem = AtomicReference<String?>()
    private class Stop(val phase: SessionReadPhase, val reason: String) : IllegalStateException(reason)
    private class RetryRead : IllegalStateException()

    init {
        listOf(deviceId, runtimeId, sessionId).forEach(Contract::uuid)
        workspaceId?.let(Contract::uuid)
        if (transcripts != null && (transcripts.owner.deviceId != deviceId || journal != null && transcripts.owner.fingerprint != journal.owner.fingerprint)) throw ProtocolException()
        if ("session.read" !in readScope.actions || readScope.actions.any { it !in setOf("session.read", "message.submit", "session.cancel", "command.status") } || journal == null && readScope.actions != setOf("session.read")) throw ProtocolException()
        commands = journal?.let { SessionCommands(api, it, runtimeId, sessionId, readScope, scope) }
        scope.coroutineContext[Job]!!.invokeOnCompletion { commands?.close(); cacheWrites.cancel(); connection.getAndSet(null)?.close(); cache.set(null); mutable.value = SessionReadState(SessionReadPhase.CLOSED) }
        scope.launch {
            while (isActive) {
                delay(1000)
                if (!cacheValid()) {
                    cache.set(null)
                    mutable.update { if (it.phase == SessionReadPhase.READY) it else it.copy(window = null) }
                }
            }
        }
        scope.launch { run() }
        if (transcripts != null) scope.launch {
            for (write in cacheWrites) {
                try {
                    cacheLock.withLock {
                        if (write.generation == cacheGeneration.get() && scope.isActive) transcripts.saveTranscript(runtimeId, sessionId, workspaceId, write.epoch, write.transcript, write.now)
                    }
                    cacheProblem.compareAndSet("data.cache_unavailable", null)
                } catch (error: CancellationException) { throw error }
                catch (_: Exception) { cacheProblem.set("data.cache_unavailable") }
                if (scope.isActive) mutable.update { it.copy(cacheError = cacheProblem.get()) }
            }
        }
    }
    fun loadOlder() {
        while (true) {
            val old = mutable.value
            if (old.phase != SessionReadPhase.READY || old.loadingOlder || old.window?.hasMore != true) return
            if (!mutable.compareAndSet(old, old.copy(loadingOlder = true, pageError = null))) continue
            if (pages.trySend(Unit).isFailure) mutable.update { it.copy(loadingOlder = false) }
            return
        }
    }
    fun retry() { if (mutable.value.phase in setOf(SessionReadPhase.BACKOFF, SessionReadPhase.ERROR, SessionReadPhase.OFFLINE)) retries.trySend(Unit) }
    private fun cacheValid(): Boolean = System.currentTimeMillis() in cacheSince.get() until cacheUntil.get() && System.nanoTime() < cacheDeadline.get()
    private fun cached(): SessionTranscript? = cache.get().takeIf { cacheValid() }
    private fun cachedState(phase: SessionReadPhase, error: String? = null) = SessionReadState(phase, cached(), error, cacheError = cacheProblem.get())
    private suspend fun invalidateCache(runtime: Boolean) {
        cacheGeneration.incrementAndGet()
        while (cacheWrites.tryReceive().isSuccess) { /* Retire pre-revocation snapshots. */ }
        cacheLock.withLock {
            try {
                if (runtime) { journal?.revokeSessionCommands(runtimeId); transcripts?.removeRuntimeTranscripts(runtimeId) }
                else transcripts?.removeTranscript(runtimeId, sessionId)
            } catch (error: CancellationException) { throw error }
            catch (_: Exception) { cacheProblem.set("data.cache_unavailable") }
        }
    }
    private fun lease(connected: SessionRelayConnection, deadline: Long, until: Long) {
        if (leaseConnection.get() != connected.identity.connectionId) {
            cacheUntil.set(until); cacheSince.set(connected.identity.connectedAt); cacheDeadline.set(deadline); leaseConnection.set(connected.identity.connectionId)
        } else {
            cacheUntil.getAndUpdate { minOf(it, until) }; cacheDeadline.getAndUpdate { minOf(it, deadline) }
        }
    }
    private suspend fun pause(delayMillis: Long?) {
        if (delayMillis == null) retries.receive() else withTimeoutOrNull(delayMillis.coerceAtLeast(1)) { retries.receive() }
    }
    private suspend fun run() {
        var failures = 0
        var resyncs = 0
        while (scope.isActive) {
            try {
                mutable.value = cachedState(SessionReadPhase.CONNECTING)
                if (journal != null && api.me().userId != journal.owner.userId) throw RemoteRequestException("auth.identity_mismatch")
                val ticket = api.sessionTicket(runtimeId, deviceId, readScope)
                val connected = ticket.connect()
                connection.set(connected)
                currentCoroutineContext().ensureActive()
                commands?.authorizeStatusReads()
                var cacheUntil: Long? = connected.identity.leaseExpiresAt
                if (transcripts != null) {
                    try {
                        cacheUntil = minOf(cacheUntil!!, api.cachedReadUntil(runtimeId, sessionId, workspaceId, connected.identity.grantVersion))
                        cacheProblem.compareAndSet("cache.authorization_unavailable", null)
                    } catch (error: CancellationException) { throw error }
                    catch (error: LoginException) { throw error }
                    catch (error: Exception) {
                        if (error is RemoteRequestException && error.code in setOf("access.denied", "access.revoked", "device.invalid", "auth.expired", "auth.proof_invalid", "auth.identity_mismatch")) throw error
                        cacheUntil = null; cache.set(null); cacheProblem.set("cache.authorization_unavailable")
                    }
                }
                val until = cacheUntil ?: connected.identity.connectedAt
                val deadline = System.nanoTime() + (until - System.currentTimeMillis()).coerceAtLeast(0) * 1_000_000
                val priorCache = cached()
                if (priorCache == null) cache.set(null)
                if (cacheUntil != null) lease(connected, deadline, until)
                // A workspace hello alone cannot prove that this session is
                // still in that workspace. Check exact current membership first.
                if (transcripts != null && cacheUntil != null && cached() == null) {
                    try {
                        val stored = transcripts.loadTranscript(runtimeId, sessionId, workspaceId)
                        currentCoroutineContext().ensureActive()
                        if (stored != null) { cache.set(stored.transcript); cacheEpoch = stored.epoch; lease(connected, deadline, until) }
                    } catch (error: CancellationException) { throw error }
                    catch (_: Exception) { cacheProblem.set("data.cache_unavailable") }
                }
                try { consume(connected, deadline, until, cacheUntil != null) } finally { commands?.disconnected(); connection.compareAndSet(connected, null); connected.close() }
            } catch (error: CancellationException) { throw error }
            catch (_: RetryRead) { failures = 0; resyncs = 0 }
            catch (error: Stop) {
                if (error.phase in setOf(SessionReadPhase.REVOKED, SessionReadPhase.AUTH_REQUIRED)) {
                    cache.set(null); mutable.update { it.copy(window = null, runtimeEpoch = null) }; commands?.close()
                    if (error.phase == SessionReadPhase.REVOKED) invalidateCache(true)
                }
                mutable.value = cachedState(error.phase, error.reason)
                if (error.phase in setOf(SessionReadPhase.REVOKED, SessionReadPhase.AUTH_REQUIRED)) return
                failures = 0; resyncs = 0
                pause(null)
            } catch (error: LoginException) {
                cache.set(null); commands?.close(); mutable.value = SessionReadState(SessionReadPhase.AUTH_REQUIRED, error = "auth.expired"); return
            } catch (error: RemoteRequestException) {
                val phase = if (error.code in setOf("access.denied", "access.revoked", "device.invalid", "auth.identity_mismatch", "access.organization_missing")) SessionReadPhase.REVOKED
                    else if (error.code in setOf("auth.expired", "auth.proof_invalid")) SessionReadPhase.AUTH_REQUIRED else null
                if (phase != null) {
                    cache.set(null); mutable.update { it.copy(window = null, runtimeEpoch = null) }; commands?.close()
                    if (phase == SessionReadPhase.REVOKED) invalidateCache(true)
                    mutable.value = SessionReadState(phase, error = error.code); return
                }
                mutable.value = cachedState(SessionReadPhase.BACKOFF, error.code); pause(options.backoffMillis(failures++))
            } catch (error: SessionDataException) {
                if (error.code in setOf("protocol.snapshot_too_large", "client.history_limit") && maxMessages > 1) maxMessages = (maxMessages / 2).coerceAtLeast(1)
                else if (error.code == "protocol.unsupported" || ++resyncs > 3) {
                    mutable.value = cachedState(SessionReadPhase.ERROR, error.code); pause(null); resyncs = 0; continue
                }
                mutable.value = cachedState(SessionReadPhase.BACKOFF, error.code); pause(options.backoffMillis(resyncs))
            } catch (_: ProtocolException) {
                mutable.value = cachedState(SessionReadPhase.ERROR, "protocol.invalid"); pause(null)
            } catch (error: RelayException) {
                if (error.code in setOf("network.proxy_unsupported", "network.insecure_endpoint", "protocol.invalid", "protocol.frame_too_large")) {
                    mutable.value = cachedState(SessionReadPhase.ERROR, error.code); pause(null)
                } else { mutable.value = cachedState(SessionReadPhase.BACKOFF, error.code); pause(options.backoffMillis(failures++)) }
            } catch (_: Exception) {
                mutable.value = cachedState(SessionReadPhase.ERROR, "network.unavailable"); pause(null)
            } finally { connection.getAndSet(null)?.close(); while (pages.tryReceive().isSuccess) { /* Retire old-generation page intents. */ } }
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private suspend fun consume(connected: SessionRelayConnection, leaseDeadline: Long, cacheUntil: Long, allowOfflineCache: Boolean): Unit = coroutineScope {
        mutable.value = cachedState(SessionReadPhase.SYNCING)
        val request = UUID.randomUUID().toString()
        connected.send(jsonObject("v" to 1L.json(), "type" to "session.subscribe".json(), "request_id" to request.json(), "runtime_id" to runtimeId.json(), "session_id" to sessionId.json(),
            "payload" to jsonObject("max_messages" to maxMessages.toLong().json())))
        val lock = Mutex()
        var route: SessionRoute? = null
        var fragments: SessionFragments? = null
        val window = SessionWindow(request)
        var dirty = false
        var offline = false
        var commandAttached = false
        var savedKey: String? = null
        var pageId: String? = null
        var pageDeadline = Long.MAX_VALUE
        var openingDeadline = System.nanoTime() + options.openingMillis * 1_000_000
        val lastPong = AtomicLong(System.nanoTime())
        suspend fun publish() {
            if (offline || !window.ready || !scope.isActive) return
            val snapshot = window.snapshot()
            if (!commandAttached) { commands?.ready(connected, route!!.epoch); commandAttached = true }
            if (allowOfflineCache) lease(connected, leaseDeadline, cacheUntil)
            val durable = window.snapshot(durableOnly = true)
            if (durable.durableOnly) {
                if (allowOfflineCache) cache.set(durable)
                val key = "${window.syncId}:${durable.records.firstOrNull()?.seq}:${durable.cursor}"
                if (transcripts != null && key != savedKey) {
                    cacheWrites.trySend(CacheWrite(cacheGeneration.get(), route!!.epoch, durable, System.currentTimeMillis())); savedKey = key
                }
            }
            mutable.value = SessionReadState(SessionReadPhase.READY, snapshot, loadingOlder = window.paging, pageError = mutable.value.pageError, runtimeEpoch = route!!.epoch, cacheError = cacheProblem.get())
            dirty = false
        }
        val heartbeat = launch {
            while (isActive) {
                delay(options.heartbeatMillis)
                if ((System.nanoTime() - lastPong.get()) / 1_000_000 > options.heartbeatMillis * 2 + 5000) throw RelayException("relay.timeout")
                connected.send(jsonObject("v" to 1L.json(), "type" to "ping".json(), "payload" to jsonObject()))
            }
        }
        val publisher = launch { while (isActive) { delay(100); lock.withLock { if (dirty) publish() } } }
        val retryer = launch { retries.receive(); throw RetryRead() }
        val authority = launch {
            while (isActive && transcripts != null && allowOfflineCache) {
                delay(2000)
                if (cached() == null) continue
                try {
                    // Catalog-only moves need not change a grant version. Do
                    // not rely solely on the runtime's control notifications.
                    val current = withTimeoutOrNull(2000) { api.cachedReadUntil(runtimeId, sessionId, workspaceId, connected.identity.grantVersion) }
                    if (current == null) cacheProblem.set("cache.authorization_unavailable")
                    // Revalidation can shorten the original lease, never extend it.
                    else {
                        cacheProblem.compareAndSet("cache.authorization_unavailable", null)
                        this@SessionReader.cacheUntil.getAndUpdate { minOf(it, current) }
                        cacheDeadline.getAndUpdate { minOf(it, System.nanoTime() + (current - System.currentTimeMillis()).coerceAtLeast(0) * 1_000_000) }
                    }
                } catch (error: CancellationException) { throw error }
                catch (error: LoginException) { throw Stop(SessionReadPhase.AUTH_REQUIRED, "auth.expired") }
                catch (error: RemoteRequestException) {
                    if (error.code in setOf("access.denied", "access.revoked", "device.invalid", "auth.identity_mismatch")) throw Stop(SessionReadPhase.REVOKED, error.code)
                    if (error.code in setOf("auth.expired", "auth.proof_invalid")) throw Stop(SessionReadPhase.AUTH_REQUIRED, error.code)
                    cacheProblem.set("cache.authorization_unavailable")
                } catch (_: Exception) { cacheProblem.set("cache.authorization_unavailable") }
                mutable.update { it.copy(cacheError = cacheProblem.get()) }
            }
        }
        val pager = launch {
            for (ignored in pages) {
                val prepared = lock.withLock {
                    try {
                        window.page(UUID.randomUUID().toString())?.also { pageId = it.requestId; pageDeadline = System.nanoTime() + options.pageMillis * 1_000_000 }
                    } catch (error: SessionDataException) { mutable.update { it.copy(loadingOlder = false, pageError = error.code) }; null }
                } ?: continue
                val target = route ?: throw SessionDataException()
                connected.send(routed("session.page", prepared.requestId, target, prepared.payload))
            }
        }
        // Logical deadlines must not cancel a socket read: cancellation intentionally closes TLS.
        // A tiny bounded queue keeps one transport receiver alive while page deadlines expire.
        val incoming = Channel<JsonObject>(2)
        val receiver = launch {
            try { while (isActive) incoming.send(connected.receive()) }
            catch (error: CancellationException) { throw error }
            // Drain already-received control frames before propagating EOF. A peer
            // commonly closes immediately after its ordered revocation marker.
            catch (error: Exception) { incoming.close(error) }
        }
        try {
            while (isActive) {
                val timeout = lock.withLock {
                    if (System.nanoTime() >= pageDeadline) {
                        pageId?.let(window::pageFailed); pageId = null; pageDeadline = Long.MAX_VALUE
                        mutable.update { it.copy(loadingOlder = false, pageError = "network.page_timeout") }
                    }
                    minOf(if (!window.ready && !offline) ((openingDeadline - System.nanoTime()) / 1_000_000).coerceAtLeast(0) else 45_000,
                        if (offline) 45_000 else fragments?.pendingMillis() ?: 45_000, if (offline) 45_000 else window.settlementMillis() ?: 45_000,
                        if (pageDeadline == Long.MAX_VALUE) 45_000 else ((pageDeadline - System.nanoTime()) / 1_000_000).coerceAtLeast(1))
                }
                if (timeout <= 0) throw SessionDataException()
                // A new page may be queued while no frames arrive; notice its deadline promptly.
                // Select atomically; timeout cancellation of Channel.receive can otherwise
                // discard an element that arrived at the cancellation boundary.
                val frame = select<JsonObject?> {
                    incoming.onReceive { it }
                    onTimeout(minOf(timeout, 100L)) { null }
                } ?: continue
                val type = frame.string("type")
                when (type) {
                    "command.receipt" -> {
                        val current = route ?: throw ProtocolException()
                        commands?.hint(CommandReceipt.socket(frame, runtimeId, current.epoch))
                    }
                    "pong" -> {
                        relayEnvelope(frame, "pong", "v", "type", "payload")
                        val payload = frame.obj("payload"); payload.exactKeys("connection_id", "server_time")
                        if (payload.string("connection_id") != connected.identity.connectionId || kotlin.math.abs(relayTime(payload.string("server_time")) - System.currentTimeMillis()) > 30_000) throw ProtocolException()
                        lastPong.set(System.nanoTime())
                    }
                    "session.subscribed" -> lock.withLock {
                        relayEnvelope(frame, type, "v", "type", "request_id", "runtime_id", "runtime_epoch", "session_id", "subscription_id", "payload")
                        if (frame.string("request_id") != request || frame.string("runtime_id") != runtimeId || frame.string("session_id") != sessionId || route != null) throw SessionDataException()
                        frame.obj("payload").exactKeys()
                        val accepted = SessionRoute(runtimeId, Contract.uuid(frame.string("runtime_epoch")), sessionId, Contract.uuid(frame.string("subscription_id")))
                        if (cacheEpoch != null && cacheEpoch != accepted.epoch) { cache.set(null); mutable.update { it.copy(window = null) }; invalidateCache(false) }
                        cacheEpoch = accepted.epoch; route = accepted; fragments = SessionFragments(accepted)
                        offline = false; openingDeadline = System.nanoTime() + options.openingMillis * 1_000_000
                    }
                    "access.revoked" -> { relayEnvelope(frame, type, "v", "type", "payload"); frame.obj("payload").exactKeys("code"); throw Stop(SessionReadPhase.REVOKED, "access.revoked") }
                    "runtime.changed" -> {
                        relayEnvelope(frame, type, "v", "type", "payload"); frame.obj("payload").exactKeys("runtime_id")
                        if (frame.obj("payload").string("runtime_id") != runtimeId) throw ProtocolException()
                        cache.set(null); mutable.update { it.copy(window = null) }; invalidateCache(false); throw SessionDataException()
                    }
                    "server.draining" -> {
                        relayEnvelope(frame, type, "v", "type", "payload"); frame.obj("payload").exactKeys("reason")
                        if (frame.obj("payload").string("reason") != "server_draining") throw ProtocolException(); throw RelayException()
                    }
                    "error", "session.error", "session.closed" -> lock.withLock {
                        SessionJson.fields(frame, setOf("v", "type", "payload"), setOf("request_id", "runtime_id", "runtime_epoch", "session_id", "subscription_id"))
                        if (frame.integer("v", 1, 1) != 1L || frame.fields["runtime_id"]?.let { it != runtimeId.json() } == true || frame.fields["session_id"]?.let { it != sessionId.json() } == true) throw ProtocolException()
                        route?.let { current ->
                            if (frame.fields["runtime_epoch"]?.let { it != current.epoch.json() } == true || frame.fields["subscription_id"]?.let { it != current.subscriptionId.json() } == true) throw SessionDataException()
                        }
                        val payload = frame.obj("payload"); payload.exactKeys("code")
                        val code = payload.string("code")
                        if (code in setOf("access.denied", "access.revoked", "device.invalid")) throw Stop(SessionReadPhase.REVOKED, code)
                        if (code in setOf("auth.expired", "auth.proof_invalid")) throw Stop(SessionReadPhase.AUTH_REQUIRED, code)
                        if (frame.fields["request_id"] == pageId?.json() && pageId != null) {
                            window.pageFailed(pageId!!); pageId = null; pageDeadline = Long.MAX_VALUE
                            mutable.update { it.copy(loadingOlder = false, pageError = if (code in errors) code else "protocol.invalid") }
                        } else {
                            val command = frame.fields["request_id"]?.let { id ->
                                if (id == request.json()) false else commands?.failed((id as? JsonString)?.value ?: throw ProtocolException(), code) ?: false
                            } ?: false
                            if (!command && frame.fields["request_id"]?.let { it != request.json() } == true) throw ProtocolException()
                            if (command && code !in setOf("runtime.offline", "runtime.changed")) return@withLock
                            when (code) {
                                "runtime.offline" -> {
                                    // The phone remains online even when its host is
                                    // absent. Keep heartbeat/control delivery so a
                                    // revoked cached view can be cleared promptly.
                                    offline = true; dirty = false; commands?.disconnected()
                                    pageId?.let(window::pageFailed); pageId = null; pageDeadline = Long.MAX_VALUE
                                    mutable.value = cachedState(SessionReadPhase.OFFLINE, code)
                                }
                                "runtime.changed", "protocol.resync_required", "protocol.snapshot_too_large" -> throw SessionDataException(code)
                                else -> throw Stop(SessionReadPhase.ERROR, if (code in errors) code else "protocol.invalid")
                            }
                        }
                    }
                    else -> lock.withLock {
                        val assembled = (fragments ?: throw SessionDataException()).accept(frame) ?: return@withLock
                        try {
                            if (window.accept(assembled)) {
                                if (assembled.type in setOf("session.page.result", "session.snapshot")) { pageId = null; pageDeadline = Long.MAX_VALUE }
                                dirty = true
                                if (assembled.type != "assistant.chunk") publish()
                            }
                        } catch (error: SessionDataException) {
                            if (assembled.type != "session.page.result" || error.code != "client.history_limit") throw error
                            window.pageFailed(assembled.requestId); pageId = null; pageDeadline = Long.MAX_VALUE
                            mutable.update { it.copy(loadingOlder = false, pageError = error.code) }
                        }
                    }
                }
            }
        } finally { receiver.cancel(); incoming.cancel(); heartbeat.cancel(); publisher.cancel(); pager.cancel(); retryer.cancel(); authority.cancel(); fragments?.clear() }
    }
    private fun routed(kind: String, request: String, route: SessionRoute, payload: JsonObject) = jsonObject("v" to 1L.json(), "type" to kind.json(), "request_id" to request.json(),
        "runtime_id" to route.runtimeId.json(), "runtime_epoch" to route.epoch.json(), "session_id" to route.sessionId.json(), "subscription_id" to route.subscriptionId.json(), "payload" to payload)
    override fun close() {
        if (closed.compareAndSet(false, true)) {
            commands?.close()
            scope.cancel(); connection.getAndSet(null)?.close(); pages.cancel(); retries.cancel(); cacheWrites.cancel(); cache.set(null); mutable.value = SessionReadState(SessionReadPhase.CLOSED)
        }
    }
    companion object { private val errors = setOf("runtime.offline", "session.not_found", "access.denied", "access.revoked", "auth.expired", "auth.proof_invalid", "protocol.invalid", "protocol.unsupported", "protocol.resync_required", "protocol.snapshot_too_large", "rate.limited", "internal") }
}
