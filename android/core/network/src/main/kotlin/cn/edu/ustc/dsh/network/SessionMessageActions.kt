package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.UUID

enum class SessionMessageActionPhase { UNAVAILABLE, SNAPSHOT_REQUIRED, IDLE, LOADING, READY, STALE, OFFLINE, DENIED, ERROR, CLOSED }
data class SessionMessageActionState(val phase: SessionMessageActionPhase = SessionMessageActionPhase.SNAPSHOT_REQUIRED,
    val preview: SessionMessagePreview? = null, val busy: Boolean = false, val error: String? = null, val canFork: Boolean = false,
    val originalRequestId: String? = null, val canPreview: Boolean = false)

/** Minted only by an exact Host confirmation. The chooser must recheck current immediately before launch. */
class AuthorizedMessageShare internal constructor(val text: String, val anchor: SessionForkAnchor, private val proof: () -> Boolean) {
    fun current(): Boolean = proof()
    override fun toString() = "AuthorizedMessageShare"
}

/** Uses the existing reader's dispatch and foreground transcript, never copied text or a second receiver. */
class SessionMessageActions internal constructor(private val commands: SessionCommands?, private val workspaceId: String?,
    private val clock: () -> Long = System::nanoTime, private val queryMillis: Long = 6_000) : AutoCloseable {
    private class Endpoint(val binding: SessionActionBinding, var snapshot: SessionTranscript, var canFork: Boolean,
        var alive: () -> Boolean, var send: suspend (JsonObject) -> Unit)
    private class Pending(val id: String, val target: Endpoint, val seq: Long, val version: String, val anchor: SessionForkAnchor?,
        val generation: Long, val deadline: Long, val reply: CompletableDeferred<SessionMessagePreview>?)
    private class Proof(val anchor: SessionForkAnchor, val localVersion: String)
    private val lock = Any()
    private val mutable = MutableStateFlow(SessionMessageActionState())
    val state: StateFlow<SessionMessageActionState> = mutable.asStateFlow()
    val canPreview: Boolean get() = synchronized(lock) { mutable.value.canPreview && endpoint?.alive() == true && !closed }
    private var endpoint: Endpoint? = null
    private var pending: Pending? = null
    private var selected: Proof? = null
    private var generation = 0L
    private var closed = false
    init { workspaceId?.let(Contract::uuid) }

    internal fun connected(caps: Set<String>, allowed: Boolean) = synchronized(lock) {
        if (!closed) retireLocked(when { !allowed -> SessionMessageActionPhase.DENIED
            SESSION_MESSAGE_ACTIONS_CAPABILITY !in caps || "session.read.v1" !in caps -> SessionMessageActionPhase.UNAVAILABLE
            else -> SessionMessageActionPhase.SNAPSHOT_REQUIRED }, if (!allowed) "access.denied" else if (SESSION_MESSAGE_ACTIONS_CAPABILITY !in caps || "session.read.v1" !in caps) "protocol.unsupported" else null)
    }
    internal fun ready(binding: SessionActionBinding, snapshot: SessionTranscript, canFork: Boolean, alive: () -> Boolean, send: suspend (JsonObject) -> Unit) = synchronized(lock) {
        if (closed || mutable.value.phase in setOf(SessionMessageActionPhase.UNAVAILABLE, SessionMessageActionPhase.DENIED) || !alive()) return@synchronized
        val old = endpoint
        if (old == null || old.binding != binding) {
            clearLocked("message.stale")
            endpoint = Endpoint(binding, snapshot, canFork && commands != null && workspaceId != null, alive, send)
            mutable.value = SessionMessageActionState(SessionMessageActionPhase.IDLE, canPreview = true)
        } else {
            old.snapshot = snapshot; old.canFork = canFork && commands != null && workspaceId != null; old.alive = alive; old.send = send
            val chosen = selected
            val wait = pending
            if (chosen != null && localVersionLocked(old, chosen.anchor.nativeSeq) != chosen.localVersion ||
                wait != null && localVersionLocked(old, wait.seq) != wait.version) {
                failureLocked("message.stale")
            }
        }
        refreshOriginalLocked()
    }
    /** Only an exact current visible item can nominate a native event; arbitrary ID substrings never do. */
    suspend fun previewMessage(itemId: String): Boolean {
        val seq = synchronized(lock) {
            val target = endpoint ?: throw CommandDataException("message.stale")
            val item = target.snapshot.items.firstOrNull { it.id == itemId && it.persisted && !it.live && it.role in setOf(ConversationRole.USER, ConversationRole.ASSISTANT) }
                ?: throw CommandDataException("message.not_persisted")
            target.snapshot.records.firstOrNull { "event:${it.seq}" == item.id && eligibleLocked(target, it.seq) != null }?.seq
                ?: throw CommandDataException("message.unavailable")
        }
        return preview(seq)
    }
    suspend fun preview(nativeSeq: Long): Boolean {
        if (nativeSeq !in 0..MAX_SAFE_INTEGER) throw ProtocolException()
        val wait = synchronized(lock) {
            val target = currentLocked()
            if (pending != null) return false
            val version = localVersionLocked(target, nativeSeq) ?: throw CommandDataException("message.not_persisted")
            clearLocked("message.stale")
            val request = Pending(UUID.randomUUID().toString(), target, nativeSeq, version, null, generation, clock() + queryMillis * 1_000_000, null)
            pending = request
            mutable.value = SessionMessageActionState(SessionMessageActionPhase.LOADING, busy = true, canPreview = true)
            refreshOriginalLocked()
            request
        }
        try { wait.target.send(wait.target.binding.envelope("session.message.preview.get", wait.id,
            jsonObject("sync_id" to wait.target.binding.syncId.json(), "native_seq" to nativeSeq.json()))) }
        catch (error: Exception) {
            synchronized(lock) { if (pending === wait) failureLocked(if (error is CancellationException) "message.stale" else "runtime.offline") }
            throw error
        }
        return true
    }
    suspend fun confirmShare(anchor: SessionForkAnchor): AuthorizedMessageShare {
        val wait = synchronized(lock) {
            val target = validateAnchorLocked(anchor, false)
            if (pending != null) throw CommandDataException("message.busy")
            val preview = mutable.value.preview ?: throw CommandDataException("message.stale")
            if (!preview.shareable || preview.text.isNullOrEmpty()) throw CommandDataException("message.unavailable")
            generation++
            Pending(UUID.randomUUID().toString(), target, anchor.nativeSeq, selected!!.localVersion, anchor, generation,
                clock() + queryMillis * 1_000_000, CompletableDeferred()).also {
                pending = it; mutable.value = mutable.value.copy(busy = true, error = null, canFork = false)
            }
        }
        try {
            val confirmed = withTimeout(queryMillis) {
                wait.target.send(wait.target.binding.envelope("session.message.preview.confirm", wait.id,
                    jsonObject("sync_id" to wait.target.binding.syncId.json(), "anchor" to anchor.json())))
                wait.reply!!.await()
            }
            return synchronized(lock) {
                if (!proofCurrentLocked(wait.target, wait.generation, anchor, wait.version) || !confirmed.shareable || confirmed.text.isNullOrEmpty()) throw CommandDataException("message.stale")
                val text = confirmed.text ?: throw CommandDataException("message.stale")
                AuthorizedMessageShare(text, anchor) { synchronized(lock) { proofCurrentLocked(wait.target, wait.generation, anchor, wait.version) && mutable.value.preview?.text == text } }
            }
        } catch (error: TimeoutCancellationException) {
            synchronized(lock) { if (generation == wait.generation) failureLocked("network.message_timeout") }
            throw CommandDataException("network.message_timeout")
        } finally {
            synchronized(lock) {
                if (pending === wait) {
                    pending = null; generation++; wait.reply?.cancel()
                    mutable.value = mutable.value.copy(busy = false)
                    refreshOriginalLocked()
                }
            }
        }
    }
    suspend fun fork(anchor: SessionForkAnchor): String {
        val target = synchronized(lock) {
            val current = validateAnchorLocked(anchor, true)
            if (mutable.value.busy || pending != null) throw CommandDataException("message.busy")
            refreshOriginalLocked()
            val original = originalLocked(anchor)
            if (original != null || unresolvedLocked().isNotEmpty()) throw CommandDataException("command.reconcile_required")
            mutable.value = mutable.value.copy(busy = true, canFork = false, error = null)
            current
        }
        try {
            val id = commands!!.forkSession(anchor, workspaceId!!, target.binding.epoch)
            synchronized(lock) {
                if (endpoint === target) { mutable.value = mutable.value.copy(originalRequestId = id); refreshOriginalLocked() }
            }
            return id
        } finally { synchronized(lock) { if (endpoint === target) { mutable.value = mutable.value.copy(busy = false); refreshOriginalLocked() } } }
    }
    fun queryFork(requestId: String? = null) {
        synchronized(lock) {
            requestId?.let(Contract::uuid)
            val target = endpoint ?: throw CommandDataException("message.stale")
            val id = requestId ?: mutable.value.originalRequestId
            if (id != null && sourceRecordsLocked(target).none { it.intent.requestId == id }) throw CommandDataException("command.not_found")
            refreshOriginalLocked()
        }
        commands?.query()
    }
    internal fun validate(record: PendingCommand): Unit = synchronized(lock) {
        val target = currentLocked()
        if (record.intent.kind != CommandKind.FORK || record.intent.runtimeId != target.binding.runtimeId || record.intent.sessionId != target.binding.sessionId ||
            record.intent.epoch != target.binding.epoch || record.intent.payload.string("workspace_id") != workspaceId || !target.canFork) throw CommandDataException("access.denied")
        val anchor = SessionForkAnchor.parse(record.intent.payload.obj("anchor"))
        validateAnchorLocked(anchor, false)
        if (sourceRecordsLocked(target).any { it.intent.requestId != record.intent.requestId && it.remote !in setOf(RemoteCommandState.SETTLED, RemoteCommandState.REJECTED) }) throw CommandDataException("command.reconcile_required")
        Unit
    }
    internal fun accept(frame: JsonObject): Boolean {
        val type = frame.string("type")
        if (type !in setOf("session.message.preview.result", "session.message.preview.error")) throw ProtocolException()
        val binding = SessionActionBinding.parseFrame(frame)
        val error = if (type.endsWith(".error")) sessionActionError(frame.obj("payload")) else null
        val preview = if (error == null) SessionMessagePreview.parse(frame.obj("payload")) else null
        return synchronized(lock) {
            val wait = pending ?: return@synchronized false
            val target = endpoint ?: return@synchronized false
            if (closed || !target.alive() || wait.target !== target || binding != target.binding || frame.string("request_id") != wait.id || generation != wait.generation) return@synchronized false
            if (clock() >= wait.deadline) { failureLocked("network.message_timeout"); return@synchronized true }
            if (error != null) { failureLocked(error); return@synchronized true }
            val result = preview!!
            if (result.anchor.subscriptionId != binding.subscriptionId || result.anchor.syncId != binding.syncId || result.anchor.nativeSeq != wait.seq ||
                wait.anchor != null && wait.anchor != result.anchor || localVersionLocked(target, wait.seq) != wait.version ||
                wait.anchor != null && (result.text != mutable.value.preview?.text || !result.shareable)) {
                failureLocked("message.stale"); return@synchronized true
            }
            pending = null; selected = Proof(result.anchor, wait.version)
            mutable.value = SessionMessageActionState(SessionMessageActionPhase.READY, result, canPreview = true)
            refreshOriginalLocked()
            wait.reply?.complete(result)
            true
        }
    }
    internal fun error(frame: JsonObject, code: String): Boolean = synchronized(lock) {
        val wait = pending ?: return@synchronized false
        if (frame.fields["request_id"] != wait.id.json()) return@synchronized false
        val binding = wait.target.binding
        if (mapOf("runtime_id" to binding.runtimeId, "runtime_epoch" to binding.epoch, "session_id" to binding.sessionId, "subscription_id" to binding.subscriptionId,
                "sync_id" to binding.syncId).any { (key, value) -> frame.fields[key]?.let { it != value.json() } == true }) return@synchronized false
        failureLocked(if (code in SESSION_ACTION_ERROR_CODES || code == "protocol.unsupported") code else "protocol.invalid"); true
    }
    internal fun tick() = synchronized(lock) {
        if (closed) return@synchronized
        if (endpoint?.alive() == false) retireLocked(SessionMessageActionPhase.STALE, "message.stale")
        else if (pending?.let { clock() >= it.deadline } == true) failureLocked("network.message_timeout")
        else refreshOriginalLocked()
    }
    fun dismiss() = synchronized(lock) {
        if (closed) return@synchronized
        clearLocked("message.stale")
        mutable.value = mutable.value.copy(phase = if (endpoint != null) SessionMessageActionPhase.IDLE else mutable.value.phase,
            preview = null, busy = false, error = null, canFork = false, canPreview = endpoint?.alive() == true)
        refreshOriginalLocked()
    }
    internal fun disconnected(code: String = "runtime.offline") = synchronized(lock) { if (!closed) retireLocked(phase(code), code) }
    private fun currentLocked(): Endpoint {
        val target = endpoint ?: throw CommandDataException("message.stale")
        if (closed || !target.alive()) throw CommandDataException("message.stale")
        return target
    }
    private fun validateAnchorLocked(anchor: SessionForkAnchor, fork: Boolean): Endpoint {
        val target = currentLocked(); val proof = selected ?: throw CommandDataException("message.stale")
        if (anchor != proof.anchor || anchor.subscriptionId != target.binding.subscriptionId || anchor.syncId != target.binding.syncId ||
            localVersionLocked(target, anchor.nativeSeq) != proof.localVersion) throw CommandDataException("message.stale")
        if (fork && (!target.canFork || commands == null || workspaceId == null)) throw CommandDataException("access.denied")
        return target
    }
    private fun proofCurrentLocked(target: Endpoint, serial: Long, anchor: SessionForkAnchor, version: String): Boolean =
        !closed && endpoint === target && target.alive() && generation == serial && selected?.anchor == anchor && selected?.localVersion == version &&
            localVersionLocked(target, anchor.nativeSeq) == version
    private fun eligibleLocked(target: Endpoint, seq: Long): SessionRecord? {
        val snapshot = target.snapshot
        if (seq > snapshot.persistedThrough || snapshot.items.none { it.id == "event:$seq" && !it.live && it.persisted && it.role in setOf(ConversationRole.USER, ConversationRole.ASSISTANT) }) return null
        val record = snapshot.records.firstOrNull { it.seq == seq && !it.replacement && it.type in setOf("user/message", "assistant/message") } ?: return null
        if (snapshot.records.any {
                val replace = it.raw.fields["surface_op"] as? JsonObject
                it.seq > seq && replace != null && replace.string("op") == "replace" && seq in replace.integer("startSeq", 0)..replace.integer("endSeq", 0)
            }) return null
        return record
    }
    private fun localVersionLocked(target: Endpoint, seq: Long): String? = eligibleLocked(target, seq)?.let {
        it.messageVersionSha256
    }
    private fun sourceRecordsLocked(target: Endpoint): List<PendingCommand> = commands?.state?.value?.records?.filter {
        it.intent.kind == CommandKind.FORK && it.intent.runtimeId == target.binding.runtimeId && it.intent.sessionId == target.binding.sessionId
    } ?: emptyList()
    private fun unresolvedLocked(): List<PendingCommand> = endpoint?.let { target -> sourceRecordsLocked(target).filter { it.remote !in setOf(RemoteCommandState.SETTLED, RemoteCommandState.REJECTED) } } ?: emptyList()
    private fun originalLocked(anchor: SessionForkAnchor): PendingCommand? = endpoint?.let { target -> sourceRecordsLocked(target).firstOrNull {
        it.intent.payload.string("workspace_id") == workspaceId && SessionForkAnchor.parse(it.intent.payload.obj("anchor")) == anchor
    } }
    private fun refreshOriginalLocked() {
        val target = endpoint ?: return
        val unresolved = unresolvedLocked()
        val exact = selected?.anchor?.let(::originalLocked)
        val explicit = mutable.value.originalRequestId?.let { id -> sourceRecordsLocked(target).firstOrNull { it.intent.requestId == id && (it in unresolved || exact?.intent?.requestId == id) } }
        val original = exact ?: explicit ?: unresolved.singleOrNull()
        mutable.value = mutable.value.copy(originalRequestId = original?.intent?.requestId,
            canFork = !mutable.value.busy && selected != null && target.canFork && target.alive() && unresolved.isEmpty() && exact == null)
    }
    private fun phase(code: String) = when {
        code.startsWith("access.") || code.startsWith("auth.") || code == "device.invalid" -> SessionMessageActionPhase.DENIED
        code in setOf("message.stale", "runtime.changed", "protocol.resync_required") -> SessionMessageActionPhase.STALE
        code == "runtime.offline" -> SessionMessageActionPhase.OFFLINE
        code == "protocol.unsupported" -> SessionMessageActionPhase.UNAVAILABLE
        else -> SessionMessageActionPhase.ERROR
    }
    private fun clearLocked(code: String) {
        generation++; selected = null
        pending?.reply?.completeExceptionally(CommandDataException(code)); pending = null
    }
    private fun failureLocked(code: String) {
        clearLocked(code)
        val phase = phase(code)
        if (phase in setOf(SessionMessageActionPhase.DENIED, SessionMessageActionPhase.OFFLINE, SessionMessageActionPhase.UNAVAILABLE)) endpoint = null
        mutable.value = SessionMessageActionState(phase, error = code, canPreview = endpoint?.alive() == true)
        refreshOriginalLocked()
    }
    private fun retireLocked(phase: SessionMessageActionPhase, code: String?) {
        clearLocked(code ?: "message.stale"); endpoint = null; mutable.value = SessionMessageActionState(phase, error = code)
    }
    override fun close() = synchronized(lock) { if (!closed) { closed = true; retireLocked(SessionMessageActionPhase.CLOSED, null) } }
}
