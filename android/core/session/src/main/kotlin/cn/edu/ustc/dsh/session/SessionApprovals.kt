package cn.edu.ustc.dsh.session

import cn.edu.ustc.dsh.protocol.*
import java.util.Collections
import java.util.UUID

class ApprovalStateException(val code: String) : IllegalStateException(code)
data class ApprovalReviewHandle(val connectionId: String, val runtimeId: String, val epoch: String, val sessionId: String,
    val approvalId: String, val executionId: String, val bindingSha256: String, val reviewId: String)
class PresentedApproval(val status: ApprovalStatus, val remainingMillis: Long, val canReview: Boolean, val handle: ApprovalReviewHandle?, val context: ApprovalContext?) {
    override fun toString() = "PresentedApproval(${status.state.wire})"
}
data class SessionApprovalState(val items: List<PresentedApproval> = emptyList(), val loaded: Boolean = false, val loadingId: String? = null, val error: String? = null)

/** Serialized by its connection owner. Contexts, handles and lookups never enter transcript storage. */
class SessionApprovals(private val route: SessionRoute, private val hostId: String, private val connectionId: String, private val watchId: String) : AutoCloseable {
    private class Entry(var status: ApprovalStatus, var deadline: Long, val observedAt: Long, var retired: Boolean)
    private class Lookup(val transfer: ApprovalDetailsTransfer, val started: Long)
    private class Review(val handle: ApprovalReviewHandle, val context: ApprovalContext)
    private val entries = linkedMapOf<String, Entry>()
    private var loaded = false
    private var closed = false
    private var lookup: Lookup? = null
    private var review: Review? = null
    private var error: String? = null
    init { listOf(hostId, connectionId, watchId).forEach(Contract::uuid) }

    fun snapshot(frame: JsonObject, nowMillis: Long = System.currentTimeMillis(), nowNanos: Long = System.nanoTime()) {
        ensureOpen()
        if (loaded) throw ApprovalStateException("approval.resync_required")
        val statuses = ApprovalTransport.snapshot(frame, route.runtimeId, watchId)
        for (status in statuses) if (status.sessionId == route.sessionId) update(status, nowMillis, nowNanos)
        loaded = true
    }
    fun reference(frame: JsonObject, requestId: String = watchId, nowMillis: Long = System.currentTimeMillis(), nowNanos: Long = System.nanoTime()) {
        ensureOpen()
        if (!loaded) throw ApprovalStateException("approval.resync_required")
        update(ApprovalTransport.reference(frame, route.runtimeId, requestId), nowMillis, nowNanos)
    }

    /** Also accepts a separately correlated, authenticated HTTP admission result. */
    fun update(status: ApprovalStatus, nowMillis: Long = System.currentTimeMillis(), nowNanos: Long = System.nanoTime()) {
        ensureOpen()
        if (status.runtimeId != route.runtimeId) throw ApprovalStateException("approval.resync_required")
        if (status.sessionId != route.sessionId) return
        val current = entries[status.id]
        if (current != null && !current.status.sameRequest(status)) throw ApprovalStateException("approval.resync_required")
        if (current == null && entries.size >= 256) throw ApprovalStateException("approval.resync_required")
        val deadline = nowNanos + (status.expiresAt - nowMillis).coerceIn(0, MAX_APPROVAL_LIFETIME_MS + APPROVAL_CLOCK_SKEW_MS) * 1_000_000
        val retired = !status.pending(nowMillis) || status.epoch != route.epoch
        val entry = current ?: Entry(status, deadline, nowNanos, retired)
        if (current != null) {
            entry.status = advance(entry.status, status)
            entry.deadline = minOf(entry.deadline, deadline)
            entry.retired = entry.retired || retired || nowNanos < entry.observedAt
        }
        entries[status.id] = entry
        if (!available(entry, nowMillis, nowNanos)) clearFor(status.id)
    }

    fun beginDetails(approvalId: String, requestId: String, nowMillis: Long = System.currentTimeMillis(), nowNanos: Long = System.nanoTime()): JsonObject {
        ensureOpen()
        val entry = entries[Contract.uuid(approvalId)] ?: throw ApprovalStateException("approval.stale")
        if (!loaded || !available(entry, nowMillis, nowNanos)) throw ApprovalStateException("approval.stale")
        if (lookup != null) throw ApprovalStateException("approval.busy")
        review = null; error = null
        lookup = Lookup(ApprovalDetailsTransfer(entry.status, requestId, hostId), nowNanos)
        return ApprovalTransport.details(entry.status, requestId)
    }

    fun details(frame: JsonObject, nowMillis: Long = System.currentTimeMillis(), nowNanos: Long = System.nanoTime()): ApprovalReviewHandle? {
        ensureOpen()
        val active = lookup ?: throw ApprovalStateException("approval.stale")
        val entry = entries[active.transfer.reference.id] ?: throw ApprovalStateException("approval.stale")
        try {
            if (!available(entry, nowMillis, nowNanos) || detailsTimedOut(nowNanos)) throw ApprovalStateException("approval.stale")
            val context = active.transfer.accept(frame, nowNanos) ?: return null
            if (!entry.status.matches(context) || !context.current(nowMillis)) throw ApprovalStateException("approval.stale")
            val handle = ApprovalReviewHandle(connectionId, route.runtimeId, route.epoch, route.sessionId, entry.status.id, entry.status.executionId,
                entry.status.bindingSha256, UUID.randomUUID().toString())
            review = Review(handle, context); lookup = null
            return handle
        } catch (failure: Exception) {
            active.transfer.close(); lookup = null; review = null
            throw failure
        }
    }

    fun detailsError(frame: JsonObject): String {
        ensureOpen()
        val active = lookup ?: throw ApprovalStateException("approval.stale")
        val code = ApprovalTransport.error(frame, active.transfer.reference, active.transfer.requestId)
        clearReview(); error = code
        return code
    }
    fun detailsTimedOut(nowNanos: Long = System.nanoTime()): Boolean = lookup?.let {
        nowNanos < it.started || nowNanos - it.started >= 10_000_000_000 || it.transfer.pendingMillis(nowNanos) == 0L
    } ?: false
    fun detailsFailed(requestId: String, code: String): Boolean {
        if (lookup?.transfer?.requestId != requestId) return false
        clearReview()
        error = if (code in setOf("approval.stale", "approval.expired", "runtime.offline", "rate.limited")) code else "approval.unavailable"
        return true
    }
    fun clearReview() { lookup?.transfer?.close(); lookup = null; review = null }

    fun requireReview(handle: ApprovalReviewHandle, nowMillis: Long = System.currentTimeMillis(), nowNanos: Long = System.nanoTime()): ApprovalContext {
        ensureOpen()
        val current = review ?: throw ApprovalStateException("approval.stale")
        val entry = entries[handle.approvalId] ?: throw ApprovalStateException("approval.stale")
        if (handle != current.handle || !available(entry, nowMillis, nowNanos) || !current.context.current(nowMillis)) {
            clearReview(); throw ApprovalStateException("approval.stale")
        }
        return current.context
    }

    fun state(nowMillis: Long = System.currentTimeMillis(), nowNanos: Long = System.nanoTime()): SessionApprovalState {
        if (closed) return SessionApprovalState()
        if (review?.context?.current(nowMillis) == false) clearReview()
        for (entry in entries.values) if (!available(entry, nowMillis, nowNanos)) clearFor(entry.status.id)
        val views = entries.values.map { entry ->
            val active = review?.takeIf { it.handle.approvalId == entry.status.id }
            PresentedApproval(entry.status, minOf((entry.deadline - nowNanos) / 1_000_000, entry.status.expiresAt - nowMillis).coerceAtLeast(0),
                available(entry, nowMillis, nowNanos), active?.handle, active?.context)
        }
        return SessionApprovalState(Collections.unmodifiableList(views), loaded, lookup?.transfer?.reference?.id, error)
    }

    private fun available(entry: Entry, nowMillis: Long, nowNanos: Long): Boolean {
        if (entry.retired) return false
        if (nowNanos < entry.observedAt || nowNanos >= entry.deadline || !entry.status.pending(nowMillis)) { entry.retired = true; return false }
        return true
    }
    private fun clearFor(id: String) {
        if (lookup?.transfer?.reference?.id == id) { lookup?.transfer?.close(); lookup = null }
        if (review?.handle?.approvalId == id) review = null
    }
    private fun ensureOpen() { if (closed) throw ApprovalStateException("approval.stale") }
    override fun close() { closed = true; clearReview(); entries.clear(); loaded = false; error = null }

    /** Metadata has no sequence. Preserve proved decisions/results when a racing RPC returns an older fact. */
    private fun advance(old: ApprovalStatus, next: ApprovalStatus): ApprovalStatus {
        if (old.decision != null && next.decision != null && old.decision != next.decision || old.decisionSha256 != null && next.decisionSha256 != null && old.decisionSha256 != next.decisionSha256)
            throw ApprovalStateException("approval.resync_required")
        if (old.decision != null && next.decision == null || old.decisionSha256 != null && next.decisionSha256 == null) return old
        val terminal = setOf(ApprovalHostState.SETTLED, ApprovalHostState.DENIED, ApprovalHostState.EXPIRED, ApprovalHostState.CANCELLED, ApprovalHostState.INVALIDATED)
        if (old.hostState in terminal) {
            if (next.hostState in terminal && (old.hostState != next.hostState || old.outcome != next.outcome)) throw ApprovalStateException("approval.resync_required")
            return old
        }
        if (old.hostState in setOf(ApprovalHostState.CONSUMED, ApprovalHostState.OUTCOME_UNKNOWN) && next.hostState in setOf(null, ApprovalHostState.APPROVED)) return old
        if (old.state != ApprovalRemoteState.PENDING && next.state == ApprovalRemoteState.PENDING) return old
        if (old.state == ApprovalRemoteState.OUTCOME_UNKNOWN && next.state == ApprovalRemoteState.ALLOWED && next.hostState != ApprovalHostState.SETTLED) return old
        return next
    }
}
