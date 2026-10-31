package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.command.CommandDataException
import cn.edu.ustc.dsh.command.PendingCommand
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.Collections
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong

private val modelCatalogContexts = AtomicLong()

/** EMPTY is a complete empty directory; PARTIAL may be empty but is never called complete. */
enum class SessionModelCatalogPhase { UNAVAILABLE, SNAPSHOT_REQUIRED, IDLE, LOADING, READY, EMPTY, PARTIAL, OFFLINE, CATALOG_CHANGED, DENIED, ERROR, CLOSED }
data class SessionModelCatalogState(
    val phase: SessionModelCatalogPhase = SessionModelCatalogPhase.SNAPSHOT_REQUIRED,
    val items: List<SessionModelItem> = emptyList(),
    val hasMore: Boolean = false,
    val unavailableProviderCount: Int = 0,
    val inFlight: Int = 0,
    val error: String? = null,
    val canSelect: Boolean = false,
    val contextId: Long = 0,
)

/** No socket reader, disk catalog or implicit reload. The SessionReader dispatches every response. */
class SessionModels internal constructor(private val commands: SessionCommands?, private val clock: () -> Long = System::nanoTime,
    private val queryMillis: Long = 5_000) : AutoCloseable {
    private class Endpoint(val binding: SessionModelBinding, val selectable: Boolean, val alive: () -> Boolean, val send: suspend (JsonObject) -> Unit)
    private class Pending(val query: SessionModelsGet, val deadline: Long)
    private val lock = Any()
    private var contextId = modelCatalogContexts.incrementAndGet()
    private val mutable = MutableStateFlow(SessionModelCatalogState(contextId = contextId))
    val state: StateFlow<SessionModelCatalogState> = mutable.asStateFlow()
    private var endpoint: Endpoint? = null
    private var attachedBinding: SessionModelBinding? = null
    private var pending: Pending? = null
    private var nextCursor: String? = null
    private var pageBytes = 0
    private var pageCount = 0
    private val cursorDigests = HashSet<String>()
    private val providers = HashMap<String, String>()
    private var closed = false

    internal fun connected(capabilities: Set<String>, allowed: Boolean) = synchronized(lock) {
        if (!closed) retireLocked(when {
            !allowed -> SessionModelCatalogPhase.DENIED
            SESSION_MODELS_CAPABILITY !in capabilities || "session.read.v1" !in capabilities -> SessionModelCatalogPhase.UNAVAILABLE
            else -> SessionModelCatalogPhase.SNAPSHOT_REQUIRED
        }, when {
            !allowed -> "access.denied"
            SESSION_MODELS_CAPABILITY !in capabilities || "session.read.v1" !in capabilities -> "protocol.unsupported"
            else -> null
        })
    }

    internal fun ready(binding: SessionModelBinding, selectable: Boolean, alive: () -> Boolean, send: suspend (JsonObject) -> Unit) = synchronized(lock) {
        if (closed || mutable.value.phase in setOf(SessionModelCatalogPhase.UNAVAILABLE, SessionModelCatalogPhase.DENIED) || !alive()) return@synchronized
        if (attachedBinding == binding) return@synchronized
        clearLocked()
        endpoint = Endpoint(binding, selectable && commands != null, alive, send)
        attachedBinding = binding
        mutable.value = SessionModelCatalogState(SessionModelCatalogPhase.IDLE, contextId = contextId)
    }

    /** Explicit first request only. Re-entering the screen must not restart an existing directory. */
    suspend fun loadInitial(limit: Int = 25): Boolean = request(limit, initial = true, reload = false)
    suspend fun loadNext(limit: Int = 25): Boolean = request(limit, initial = false, reload = false)
    suspend fun reload(limit: Int = 25): Boolean = request(limit, initial = true, reload = true)
    private suspend fun request(limit: Int, initial: Boolean, reload: Boolean): Boolean {
        if (limit !in 1..50) throw ProtocolException()
        val prepared = synchronized(lock) {
            val target = endpoint ?: return false
            if (closed || !target.alive() || pending != null) return false
            if (initial && !reload && mutable.value.phase != SessionModelCatalogPhase.IDLE) return false
            if (!initial && (nextCursor == null || mutable.value.phase !in setOf(SessionModelCatalogPhase.READY, SessionModelCatalogPhase.PARTIAL))) return false
            if (initial) clearLocked()
            val query = SessionModelsGet(UUID.randomUUID().toString(), target.binding, limit, if (initial) null else nextCursor)
            pending = Pending(query, clock() + queryMillis * 1_000_000)
            mutable.value = mutable.value.copy(phase = SessionModelCatalogPhase.LOADING, inFlight = 1, error = null, canSelect = false)
            target to query
        }
        try { prepared.first.send(prepared.second.frame()) }
        catch (error: Exception) {
            synchronized(lock) {
                if (!closed && endpoint === prepared.first && pending?.query === prepared.second) retireLocked(SessionModelCatalogPhase.OFFLINE, "runtime.offline")
            }
            throw error
        }
        return true
    }

    internal fun accept(frame: JsonObject): Boolean {
        val result: SessionModelsResult?
        val error: SessionModelsError?
        when (frame.string("type")) {
            "session.models.result" -> { result = SessionModelsResult.parse(frame); error = null }
            "session.models.error" -> { result = null; error = SessionModelsError.parse(frame) }
            else -> throw ProtocolException()
        }
        return synchronized(lock) {
            val query = pending?.query ?: return@synchronized false
            val binding = result?.binding ?: error!!.binding
            val requestId = result?.requestId ?: error!!.requestId
            val target = endpoint ?: return@synchronized false
            if (closed || !target.alive() || requestId != query.requestId || binding != query.binding || target.binding != binding) return@synchronized false
            pending = null
            if (error != null) { failureLocked(error.code); return@synchronized true }
            val page = result!!
            if (page.items.size > query.limit || pageBytes + page.encodedBytes > 4 * 1024 * 1024 ||
                mutable.value.items.size + page.items.size > 8192 || ++pageCount > 8192) {
                failureLocked("protocol.snapshot_too_large"); return@synchronized true
            }
            var previous = mutable.value.items.lastOrNull()
            for (item in page.items) {
                if (previous != null && compare(previous, item) >= 0) { failureLocked("protocol.invalid"); return@synchronized true }
                val old = providers.putIfAbsent(item.provider.id, item.provider.label)
                if (old != null && old != item.provider.label) { failureLocked("protocol.invalid"); return@synchronized true }
                if (providers.size > 128) { failureLocked("protocol.snapshot_too_large"); return@synchronized true }
                previous = item
            }
            if (pageCount > 1 && page.unavailableProviderCount != mutable.value.unavailableProviderCount) {
                failureLocked("protocol.resync_required"); return@synchronized true
            }
            val cursor = page.nextCursor
            if (cursor != null && !cursorDigests.add(sha256(cursor.toByteArray(Charsets.UTF_8)))) {
                failureLocked("protocol.resync_required"); return@synchronized true
            }
            pageBytes += page.encodedBytes; nextCursor = cursor
            val items = Collections.unmodifiableList(mutable.value.items + page.items)
            val phase = when {
                page.unavailableProviderCount > 0 -> SessionModelCatalogPhase.PARTIAL
                items.isEmpty() -> SessionModelCatalogPhase.EMPTY
                else -> SessionModelCatalogPhase.READY
            }
            mutable.value = SessionModelCatalogState(phase, items, cursor != null, page.unavailableProviderCount, canSelect = target.selectable && items.isNotEmpty(), contextId = contextId)
            true
        }
    }

    /** Handles outer rejection without stealing a transcript/command response. */
    internal fun error(frame: JsonObject, code: String): Boolean = synchronized(lock) {
        val query = pending?.query ?: return@synchronized false
        if (frame.fields["request_id"] != query.requestId.json()) return@synchronized false
        val binding = query.binding
        val expected = mapOf("runtime_id" to binding.runtimeId, "runtime_epoch" to binding.epoch,
            "session_id" to binding.sessionId, "subscription_id" to binding.subscriptionId)
        if (expected.any { (key, value) -> frame.fields[key]?.let { it != value.json() } == true }) return@synchronized false
        pending = null
        failureLocked(if (code in SessionModelsError.codes || code == "protocol.unsupported") code else "protocol.invalid")
        true
    }

    /** Reader's logical deadline never cancels receive() or starts another request. */
    internal fun tick() = synchronized(lock) {
        if (!closed && pending?.let { clock() >= it.deadline } == true) { pending = null; failureLocked("network.models_timeout") }
    }
    internal fun disconnected(code: String = "runtime.offline") = synchronized(lock) {
        if (!closed) retireLocked(when {
            code in setOf("access.denied", "access.revoked", "auth.expired", "auth.proof_invalid", "device.invalid", "auth.identity_mismatch", "access.organization_missing") -> SessionModelCatalogPhase.DENIED
            code in setOf("protocol.resync_required", "runtime.changed") -> SessionModelCatalogPhase.CATALOG_CHANGED
            code == "protocol.unsupported" -> SessionModelCatalogPhase.UNAVAILABLE
            code.startsWith("protocol.") -> SessionModelCatalogPhase.ERROR
            else -> SessionModelCatalogPhase.OFFLINE
        }, code)
    }

    suspend fun select(providerId: String, modelId: String, reasoningEffortId: String? = null): String {
        val target = synchronized(lock) { validateLocked(providerId, modelId, reasoningEffortId, null) }
        return commands!!.selectModel(providerId, modelId, reasoningEffortId, target.binding.epoch)
    }
    /** Query original persisted request IDs; unknown outcomes are never recreated as a new selection. */
    fun querySelection() { commands?.query() }
    internal fun validate(record: PendingCommand) = synchronized(lock) {
        val payload = record.intent.payload
        validateLocked(payload.string("provider"), payload.string("model"), (payload.fields["reasoning_effort"] as? JsonString)?.value, record.intent.epoch)
        Unit
    }
    private fun validateLocked(provider: String, model: String, effort: String?, epoch: String?): Endpoint {
        val target = endpoint ?: throw CommandDataException("model.stale")
        if (closed || !target.alive() || !mutable.value.canSelect || !target.selectable || epoch != null && epoch != target.binding.epoch) throw CommandDataException("model.stale")
        val item = mutable.value.items.firstOrNull { it.provider.id == provider && it.model.id == model } ?: throw CommandDataException("model.unavailable")
        if (effort != null && item.reasoningEfforts.none { it.id == effort }) throw CommandDataException("model.effort_unavailable")
        return target
    }
    private fun compare(left: SessionModelItem, right: SessionModelItem): Int {
        val provider = left.provider.id.compareTo(right.provider.id)
        return if (provider == 0) left.model.id.compareTo(right.model.id) else provider
    }
    private fun failureLocked(code: String) {
        clearLocked()
        val phase = when (code) {
            "protocol.resync_required", "runtime.changed" -> SessionModelCatalogPhase.CATALOG_CHANGED
            "runtime.offline" -> SessionModelCatalogPhase.OFFLINE
            "access.denied" -> SessionModelCatalogPhase.DENIED
            "protocol.unsupported" -> SessionModelCatalogPhase.UNAVAILABLE
            else -> SessionModelCatalogPhase.ERROR
        }
        mutable.value = SessionModelCatalogState(phase, error = code, contextId = contextId)
        if (phase in setOf(SessionModelCatalogPhase.OFFLINE, SessionModelCatalogPhase.DENIED, SessionModelCatalogPhase.UNAVAILABLE)) endpoint = null
    }
    private fun clearLocked() {
        pending = null; nextCursor = null; pageBytes = 0; pageCount = 0; cursorDigests.clear(); providers.clear()
        contextId = modelCatalogContexts.incrementAndGet()
        mutable.value = SessionModelCatalogState(SessionModelCatalogPhase.IDLE, contextId = contextId)
    }
    private fun retireLocked(phase: SessionModelCatalogPhase, code: String?) {
        endpoint = null; attachedBinding = null; clearLocked(); mutable.value = SessionModelCatalogState(phase, error = code, contextId = contextId)
    }
    override fun close() = synchronized(lock) {
        if (!closed) { closed = true; retireLocked(SessionModelCatalogPhase.CLOSED, null) }
    }
}
