package cn.edu.ustc.dsh.command

import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.protocol.*

/** Immutable original proof. Restoring its signature is historical verification, never permission to replay. */
class ApprovalDecisionIntent private constructor(val requestId: String, val ownerHash: String, val context: ApprovalContext, val signed: SignedApprovalDecision) {
    val approvalId = context.root.string("approval_id")
    val runtimeId = context.root.string("runtime_id")
    val sessionId = context.root.string("session_id")
    val epoch = context.root.string("runtime_epoch")
    val decision get() = signed.decision
    val digest = JsonDocument.of(jsonObject("domain" to "dsh-mobile-ustc/local-approval-intent/v1".json(), "request_id" to requestId.json(),
        "owner_sha256" to ownerHash.json(), "binding_sha256" to context.bindingSha256.json(), "decision_jws" to signed.compact.json())).sha256()
    val bytes get() = context.document.canonicalBytes().size.toLong() + signed.compact.length
    fun current(now: Long) = decision.matches(context, now)
    override fun toString() = "ApprovalDecisionIntent(${decision.choice.wire})"

    companion object {
        fun create(requestId: String, owner: LocalDataOwner, key: RegisteredApprovalKey, context: ApprovalContext, signed: SignedApprovalDecision, now: Long): ApprovalDecisionIntent {
            ownedKey(owner, key)
            val verified = ApprovalSignatures.verify(signed.compact, key, context, now)
            return ApprovalDecisionIntent(Contract.uuid(requestId), owner.fingerprint, context, verified)
        }
        fun restore(requestId: String, owner: LocalDataOwner, key: RegisteredApprovalKey, contextBytes: ByteArray, compact: String): ApprovalDecisionIntent {
            ownedKey(owner, key)
            if (compact.length !in 1..16 * 1024) throw ProtocolException()
            val context = ApprovalContext.parse(contextBytes)
            val parts = compact.split('.'); if (parts.size != 3) throw ProtocolException()
            // Read only the candidate issue time before independent verification of the whole original proof.
            val candidate = ApprovalDecision.parse(Contract.base64url(parts[1]))
            val verified = ApprovalSignatures.verify(compact, key, context, candidate.issuedAt)
            return ApprovalDecisionIntent(Contract.uuid(requestId), owner.fingerprint, context, verified)
        }
        private fun ownedKey(owner: LocalDataOwner, key: RegisteredApprovalKey) {
            if (!key.active || key.userId != owner.userId || key.deviceId != owner.deviceId) throw CommandDataException("data.owner_mismatch")
        }
    }
}

enum class ApprovalDecisionDelivery { PENDING, RECONCILE, ACCEPTED, CONFLICT, ENDED }
class PendingApprovalDecision(val intent: ApprovalDecisionIntent, val delivery: ApprovalDecisionDelivery, val attempts: Long, val revision: Long,
    val createdAt: Long, val updatedAt: Long, val remote: ApprovalStatus? = null, val forwarding: ApprovalDelivery? = null, val error: String? = null) {
    override fun toString() = "PendingApprovalDecision($delivery)"
}

object ApprovalDecisionEvolution {
    fun created(intent: ApprovalDecisionIntent, now: Long): PendingApprovalDecision {
        if (!intent.current(now)) throw CommandDataException("approval.expired")
        return PendingApprovalDecision(intent, ApprovalDecisionDelivery.PENDING, 0, 1, now, now)
    }
    fun begin(row: PendingApprovalDecision, now: Long): PendingApprovalDecision {
        if (row.delivery != ApprovalDecisionDelivery.PENDING || row.attempts > 0 && row.remote?.pending(now) != true) throw CommandDataException("approval.reconcile_required")
        if (row.attempts >= MAX_SAFE_INTEGER || row.revision >= MAX_SAFE_INTEGER) throw CommandDataException("data.outbox_limit")
        if (!row.intent.current(now)) throw CommandDataException("approval.expired")
        return copy(row, now, delivery = ApprovalDecisionDelivery.RECONCILE, attempts = row.attempts + 1, error = null)
    }
    fun record(row: PendingApprovalDecision, proof: ApprovalStatus, now: Long, forwarding: ApprovalDelivery? = null): PendingApprovalDecision {
        if (!proof.matches(row.intent.context)) throw CommandDataException("approval.request_conflict")
        val remote = try { row.remote?.advance(proof) ?: proof } catch (_: ProtocolException) { throw CommandDataException("approval.state_conflict") }
        if (remote.state == ApprovalRemoteState.PENDING && (remote.decision != null || remote.decisionSha256 != null || remote.hostState != null)) throw CommandDataException("approval.state_conflict")
        val owned = remote.decisionSha256 == row.intent.signed.payloadSha256 && remote.decision == row.intent.decision.choice
        if (remote.decisionSha256 == row.intent.signed.payloadSha256 && !owned || forwarding != null && !owned) throw CommandDataException("approval.state_conflict")
        if (owned && row.attempts == 0L) throw CommandDataException("approval.unsent_receipt")
        val delivery = when {
            owned -> ApprovalDecisionDelivery.ACCEPTED
            remote.decisionSha256 != null || remote.decision != null -> ApprovalDecisionDelivery.CONFLICT
            remote.state != ApprovalRemoteState.PENDING -> ApprovalDecisionDelivery.ENDED
            row.attempts > 0 -> ApprovalDecisionDelivery.RECONCILE
            else -> ApprovalDecisionDelivery.PENDING
        }
        val nextForwarding = listOfNotNull(forwarding, row.forwarding).maxByOrNull { it.ordinal }
        val nextError = if (delivery in setOf(ApprovalDecisionDelivery.ACCEPTED, ApprovalDecisionDelivery.CONFLICT, ApprovalDecisionDelivery.ENDED)) null else row.error
        if (row.remote?.document?.canonicalText() == remote.document.canonicalText() && row.delivery == delivery && row.forwarding == nextForwarding && row.error == nextError) return row
        return copy(row, now, delivery = delivery, remote = remote, forwarding = nextForwarding, error = nextError)
    }
    /** A caller must freshly query and durably retain the proof even if retry is refused. */
    fun rearm(row: PendingApprovalDecision, proof: ApprovalStatus, now: Long): PendingApprovalDecision {
        val current = record(row, proof, now)
        if (row.attempts == 0L || current.delivery != ApprovalDecisionDelivery.RECONCILE || !proof.pending(now) || !row.intent.current(now)) throw CommandDataException("approval.reconcile_required")
        return copy(current, now, delivery = ApprovalDecisionDelivery.PENDING, error = null)
    }
    fun uncertain(row: PendingApprovalDecision, now: Long, code: String): PendingApprovalDecision {
        if (row.delivery != ApprovalDecisionDelivery.RECONCILE) return row
        val fixed = if (code in setOf("approval.delivery_unconfirmed", "approval.status_unavailable", "approval.expired", "approval.stale", "runtime.changed", "auth.expired", "access.revoked")) code else "approval.delivery_unconfirmed"
        return if (row.error == fixed) row else copy(row, now, error = fixed)
    }
    private fun copy(row: PendingApprovalDecision, now: Long, delivery: ApprovalDecisionDelivery = row.delivery, attempts: Long = row.attempts,
        remote: ApprovalStatus? = row.remote, forwarding: ApprovalDelivery? = row.forwarding, error: String?): PendingApprovalDecision {
        if (row.revision >= MAX_SAFE_INTEGER) throw CommandDataException("data.outbox_limit")
        return PendingApprovalDecision(row.intent, delivery, attempts, row.revision + 1, row.createdAt, maxOf(row.updatedAt, now), remote, forwarding, error)
    }
}

interface ApprovalDecisionJournal : AutoCloseable {
    val owner: LocalDataOwner
    suspend fun create(intent: ApprovalDecisionIntent, now: Long = System.currentTimeMillis()): PendingApprovalDecision
    suspend fun list(runtime: String, session: String): List<PendingApprovalDecision>
    /** Commit uncertainty before initiating HTTPS; reconnect never calls this automatically. */
    suspend fun beginAttempt(id: String, now: Long = System.currentTimeMillis()): PendingApprovalDecision
    suspend fun record(id: String, proof: ApprovalStatus, now: Long = System.currentTimeMillis(), forwarding: ApprovalDelivery? = null): PendingApprovalDecision?
    suspend fun uncertain(id: String, code: String, now: Long = System.currentTimeMillis()): PendingApprovalDecision?
    /** Persist stronger proof before rejecting an ineligible same-proof retry. */
    suspend fun rearm(id: String, proof: ApprovalStatus, now: Long = System.currentTimeMillis()): PendingApprovalDecision
    /** Only an original that has never been attempted may be discarded. */
    suspend fun discard(id: String)
}
