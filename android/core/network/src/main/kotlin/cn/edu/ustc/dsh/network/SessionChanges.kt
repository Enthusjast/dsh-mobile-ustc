package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.Base64
import java.util.Collections
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong

private val changesContexts = AtomicLong()
enum class SessionChangesPhase { UNAVAILABLE, SNAPSHOT_REQUIRED, IDLE, LOADING, READY, EMPTY, STALE, OFFLINE, DENIED, ERROR, CLOSED }
data class SessionChangesState(val phase: SessionChangesPhase = SessionChangesPhase.SNAPSHOT_REQUIRED, val files: List<SessionChangeFile> = emptyList(),
    val manifest: SessionChangesManifest? = null, val patch: SessionChangesPatch? = null, val loading: Boolean = false, val error: String? = null,
    val hasMore: Boolean = false, val patchHasMore: Boolean = false, val contextId: Long = 0, val canCopyComplete: Boolean = false)

/** One explicitly requested, reader-bound Git snapshot. No cache, automatic requests or socket reader. */
class SessionChanges internal constructor(private val clock: () -> Long = System::nanoTime,
    private val wallClock: () -> Long = System::currentTimeMillis, private val queryMillis: Long = 16_000) : AutoCloseable {
    private class Endpoint(val binding: SessionActionBinding, val alive: () -> Boolean, val send: suspend (JsonObject) -> Unit)
    private class Pending(val id: String, val type: String, val target: Endpoint, val deadline: Long, val limit: Int, val fileId: String?)
    private val lock = Any()
    private var contextId = changesContexts.incrementAndGet()
    private val mutable = MutableStateFlow(SessionChangesState(contextId = contextId))
    val state: StateFlow<SessionChangesState> = mutable.asStateFlow()
    private var endpoint: Endpoint? = null
    private var pending: Pending? = null
    private var cursor: String? = null
    private val cursors = HashSet<String>()
    private val patchCursors = HashSet<String>()
    private var pages = 0
    private var observedAt = 0L
    private var expiresNanos = 0L
    private var selectedFile: SessionChangeFile? = null
    private val fragments = ArrayList<ByteArray>()
    private var patchByteCount = 0
    private var patchNewlines = 0
    private var patchLastByte: Byte? = null
    private var patchPages = 0
    private var patchLines = 0
    private var closed = false

    internal fun connected(caps: Set<String>, allowed: Boolean) = synchronized(lock) {
        if (!closed) retireLocked(when { !allowed -> SessionChangesPhase.DENIED
            SESSION_CHANGES_CAPABILITY !in caps || "session.read.v1" !in caps -> SessionChangesPhase.UNAVAILABLE
            else -> SessionChangesPhase.SNAPSHOT_REQUIRED }, if (!allowed) "access.denied" else if (SESSION_CHANGES_CAPABILITY !in caps || "session.read.v1" !in caps) "protocol.unsupported" else null)
    }
    internal fun ready(binding: SessionActionBinding, alive: () -> Boolean, send: suspend (JsonObject) -> Unit) = synchronized(lock) {
        if (closed || mutable.value.phase in setOf(SessionChangesPhase.UNAVAILABLE, SessionChangesPhase.DENIED) || !alive()) return@synchronized
        if (endpoint?.binding == binding) return@synchronized
        clearLocked(); endpoint = Endpoint(binding, alive, send)
    }
    suspend fun loadInitial(limit: Int = 20): Boolean = request(limit, false, false, null)
    suspend fun loadNext(limit: Int = 20): Boolean = request(limit, true, false, null)
    suspend fun reload(limit: Int = 20): Boolean = request(limit, false, true, null)
    suspend fun loadPatch(fileId: String): Boolean = request(20, false, false, Contract.uuid(fileId))
    suspend fun loadNextPatch(): Boolean {
        val fileId = synchronized(lock) { selectedFile?.fileId } ?: return false
        return request(20, true, false, fileId)
    }

    private suspend fun request(limit: Int, more: Boolean, reload: Boolean, fileId: String?): Boolean {
        if (limit !in 1..20) throw ProtocolException()
        val prepared = synchronized(lock) {
            val target = endpoint ?: return false
            expireLocked()
            if (closed || !target.alive() || pending != null) return false
            val patch = fileId != null
            if (patch) {
                if (!currentSnapshotLocked()) return false
                val file = mutable.value.files.firstOrNull { it.fileId == fileId } ?: return false
                if (more && (selectedFile !== file || mutable.value.patch?.nextCursor == null)) return false
                if (!more) { clearPatchLocked(); selectedFile = file }
            } else {
                if (more && (cursor == null || !currentSnapshotLocked())) return false
                if (!more && !reload && mutable.value.phase != SessionChangesPhase.IDLE) return false
                if (!more) clearLocked()
            }
            var payload = jsonObject("sync_id" to target.binding.syncId.json())
            if (patch) payload = payload.with("snapshot_id" to mutable.value.manifest!!.snapshotId.json(), "file_id" to fileId!!.json())
            else payload = payload.with("limit" to limit.toLong().json())
            val next = if (!more) null else if (patch) mutable.value.patch?.nextCursor else cursor
            if (next != null) payload = payload.with("cursor" to next.json())
            val type = if (patch) "session.changes.patch.get" else "session.changes.get"
            val wait = Pending(UUID.randomUUID().toString(), type, target, clock() + queryMillis * 1_000_000, limit, fileId)
            pending = wait; mutable.value = mutable.value.copy(phase = SessionChangesPhase.LOADING, loading = true, error = null, canCopyComplete = false)
            wait to target.binding.envelope(type, wait.id, payload)
        }
        try { prepared.first.target.send(prepared.second) }
        catch (error: Exception) {
            synchronized(lock) { if (pending === prepared.first) retireLocked(SessionChangesPhase.OFFLINE, "runtime.offline") }
            throw error
        }
        return true
    }

    internal fun accept(frame: JsonObject): Boolean {
        val type = frame.string("type")
        if (type !in setOf("session.changes.result", "session.changes.error", "session.changes.patch.result", "session.changes.patch.error")) throw ProtocolException()
        val binding = SessionActionBinding.parseFrame(frame)
        val payload = frame.obj("payload")
        val failure = if (type.endsWith(".error")) sessionActionError(payload) else null
        val page = if (type == "session.changes.result") SessionChangesPage.parse(payload) else null
        val patch = if (type == "session.changes.patch.result") SessionChangesPatch.parse(payload) else null
        return synchronized(lock) {
            val wait = pending ?: return@synchronized false
            val target = endpoint ?: return@synchronized false
            if (closed || !target.alive() || target !== wait.target || binding != target.binding || frame.string("request_id") != wait.id) return@synchronized false
            val prefix = if (wait.fileId == null) "session.changes" else "session.changes.patch"
            if (type != "$prefix.result" && type != "$prefix.error") throw ProtocolException()
            if (clock() >= wait.deadline) { failureLocked("network.changes_timeout"); return@synchronized true }
            pending = null
            if (failure != null) { failureLocked(failure); return@synchronized true }
            if (++pages > 64) { failureLocked("changes.limit"); return@synchronized true }
            if (page != null) acceptPageLocked(page, wait) else acceptPatchLocked(patch!!, wait)
            true
        }
    }
    private fun acceptPageLocked(page: SessionChangesPage, wait: Pending) {
        val old = mutable.value.manifest
        val now = wallClock()
        if (page.syncId != wait.target.binding.syncId || page.files.size > wait.limit || page.manifest.expiresAt <= now || page.manifest.expiresAt > now + 31_000 ||
            old != null && old != page.manifest || mutable.value.files.size + page.files.size > 128 ||
            page.files.any { file -> mutable.value.files.any { it.fileId == file.fileId } } || !rememberCursorLocked(page.nextCursor)) {
            failureLocked("changes.stale"); return
        }
        if (old == null) { observedAt = now; expiresNanos = clock() + (page.manifest.expiresAt - now) * 1_000_000 }
        val files = Collections.unmodifiableList(mutable.value.files + page.files)
        cursor = page.nextCursor
        mutable.value = mutable.value.copy(phase = if (files.isEmpty()) SessionChangesPhase.EMPTY else SessionChangesPhase.READY,
            files = files, manifest = page.manifest, loading = false, hasMore = cursor != null, canCopyComplete = false)
        mutable.value = mutable.value.copy(canCopyComplete = completePatchLocked() != null)
    }
    private fun acceptPatchLocked(page: SessionChangesPatch, wait: Pending) {
        val manifest = mutable.value.manifest
        val file = selectedFile
        if (!currentSnapshotLocked() || manifest == null || file == null || page.fileId != file.fileId || page.fileId != wait.fileId || page.snapshotId != manifest.snapshotId ||
            page.syncId != wait.target.binding.syncId || page.version != manifest.version || page.kind != file.kind || ++patchPages > 64 || !rememberCursorLocked(page.nextCursor, patchCursors)) {
            failureLocked("changes.stale"); return
        }
        val bytes = sessionChangeBytes(page.patchBase64)
        patchLines += page.hunks.sumOf { it.lines.size }
        val nextSize = patchByteCount + bytes.size
        if (nextSize.toLong() > file.patchBytes || nextSize > SESSION_CHANGES_MAX_PATCH_BYTES || patchLines > 20_000) {
            bytes.fill(0); failureLocked("changes.limit"); return
        }
        fragments += bytes; patchByteCount = nextSize
        patchNewlines += bytes.count { it == 10.toByte() }
        if (bytes.isNotEmpty()) patchLastByte = bytes.last()
        val physicalLines = patchNewlines + if (patchByteCount > 0 && patchLastByte != 10.toByte()) 1 else 0
        if (physicalLines > 20_000 || page.nextCursor == null && patchByteCount.toLong() != file.patchBytes) { failureLocked("protocol.invalid"); return }
        var complete = false
        var text = page.patchUtf8
        var encoded = page.patchBase64
        if (page.nextCursor == null && file.complete && file.kind != "binary") {
            val allBytes = ByteArray(patchByteCount)
            var offset = 0
            for (fragment in fragments) { fragment.copyInto(allBytes, offset); offset += fragment.size }
            val fullText = sessionChangeUtf8(allBytes)
            if (fullText != null) {
                complete = true; text = fullText; encoded = Base64.getEncoder().encodeToString(allBytes)
            }
            allBytes.fill(0)
        }
        if (page.nextCursor == null) { fragments.forEach { it.fill(0) }; fragments.clear() }
        val combined = page.copy(complete = complete, copyable = complete, partial = !complete,
            patchBase64 = encoded, patchUtf8 = text,
            hunks = Collections.unmodifiableList((mutable.value.patch?.hunks ?: emptyList()) + page.hunks))
        mutable.value = mutable.value.copy(phase = SessionChangesPhase.READY, patch = combined, patchHasMore = page.nextCursor != null, loading = false, canCopyComplete = complete)
    }
    fun completePatch(): String? = synchronized(lock) { expireLocked(); completePatchLocked() }
    private fun completePatchLocked(): String? {
        val target = endpoint ?: return null
        val patch = mutable.value.patch ?: return null
        val manifest = mutable.value.manifest ?: return null
        val file = selectedFile ?: return null
        if (closed || !target.alive() || mutable.value.loading || !currentSnapshotLocked() || !file.complete || file.kind == "binary" || !patch.complete || patch.partial ||
            patch.nextCursor != null || patch.version != manifest.version || patch.snapshotId != manifest.snapshotId || patch.fileId != file.fileId || patchByteCount.toLong() != file.patchBytes) return null
        return patch.patchUtf8
    }
    private fun rememberCursorLocked(next: String?, seen: MutableSet<String> = cursors) = next == null || seen.add(next)
    private fun currentSnapshotLocked(): Boolean = mutable.value.manifest?.let { wallClock() in observedAt until it.expiresAt && clock() < expiresNanos } == true
    private fun expireLocked() { if (mutable.value.manifest != null && !currentSnapshotLocked()) failureLocked("changes.stale") }
    internal fun tick() = synchronized(lock) {
        if (closed) return@synchronized
        if (endpoint?.alive() == false) retireLocked(SessionChangesPhase.STALE, "changes.stale")
        else { expireLocked(); if (pending?.let { clock() >= it.deadline } == true) failureLocked("network.changes_timeout") }
    }
    internal fun error(frame: JsonObject, code: String): Boolean = synchronized(lock) {
        val wait = pending ?: return@synchronized false
        if (frame.fields["request_id"] != wait.id.json()) return@synchronized false
        val binding = wait.target.binding
        if (mapOf("runtime_id" to binding.runtimeId, "runtime_epoch" to binding.epoch, "session_id" to binding.sessionId, "subscription_id" to binding.subscriptionId,
                "sync_id" to binding.syncId).any { (key, value) -> frame.fields[key]?.let { it != value.json() } == true }) return@synchronized false
        failureLocked(if (code in SESSION_ACTION_ERROR_CODES || code == "protocol.unsupported") code else "protocol.invalid"); true
    }
    internal fun disconnected(code: String = "runtime.offline") = synchronized(lock) { if (!closed) retireLocked(phase(code), code) }
    private fun phase(code: String) = when {
        code.startsWith("access.") || code.startsWith("auth.") || code == "device.invalid" -> SessionChangesPhase.DENIED
        code in setOf("changes.stale", "runtime.changed", "protocol.resync_required") -> SessionChangesPhase.STALE
        code == "runtime.offline" -> SessionChangesPhase.OFFLINE
        code == "protocol.unsupported" -> SessionChangesPhase.UNAVAILABLE
        else -> SessionChangesPhase.ERROR
    }
    private fun failureLocked(code: String) {
        val phase = phase(code); clearLocked()
        if (phase in setOf(SessionChangesPhase.DENIED, SessionChangesPhase.UNAVAILABLE, SessionChangesPhase.OFFLINE)) endpoint = null
        mutable.value = SessionChangesState(phase, error = code, contextId = contextId)
    }
    private fun clearPatchLocked() {
        patchCursors.clear()
        fragments.forEach { it.fill(0) }; fragments.clear(); patchByteCount = 0; patchNewlines = 0; patchLastByte = null
        selectedFile = null; patchPages = 0; patchLines = 0
        mutable.value = mutable.value.copy(patch = null, patchHasMore = false, canCopyComplete = false)
    }
    private fun clearLocked() {
        pending = null; cursor = null; cursors.clear(); pages = 0; observedAt = 0; expiresNanos = 0; clearPatchLocked()
        contextId = changesContexts.incrementAndGet(); mutable.value = SessionChangesState(SessionChangesPhase.IDLE, contextId = contextId)
    }
    private fun retireLocked(phase: SessionChangesPhase, code: String?) { endpoint = null; clearLocked(); mutable.value = SessionChangesState(phase, error = code, contextId = contextId) }
    override fun close() = synchronized(lock) { if (!closed) { closed = true; retireLocked(SessionChangesPhase.CLOSED, null) } }
}
