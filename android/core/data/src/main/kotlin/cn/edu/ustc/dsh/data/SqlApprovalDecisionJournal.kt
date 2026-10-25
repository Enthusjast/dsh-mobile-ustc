package cn.edu.ustc.dsh.data

import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.protocol.*
import java.util.concurrent.atomic.AtomicBoolean

/** Shares the account's encrypted database/key lifecycle; it never sends or signs a decision. */
internal class SqlApprovalDecisionJournal(private val parent: SqlCommandJournal, private val key: RegisteredApprovalKey) : ApprovalDecisionJournal {
    override val owner get() = parent.owner
    private val closed = AtomicBoolean()
    init { if (!key.active || key.userId != owner.userId || key.deviceId != owner.deviceId) throw CommandDataException("data.owner_mismatch") }
    private suspend fun <T> transaction(action: (CommandDao) -> T): T = parent.transaction { dao ->
        if (closed.get()) throw CommandDataException("data.closed")
        action(dao).also { if (closed.get()) throw CommandDataException("data.closed") }
    }
    override suspend fun create(intent: ApprovalDecisionIntent, now: Long): PendingApprovalDecision = transaction { dao ->
        if (intent.ownerHash != owner.fingerprint) throw CommandDataException("data.owner_mismatch")
        val verified = ApprovalDecisionIntent.restore(intent.requestId, owner, key, intent.context.document.canonicalBytes(), intent.signed.compact)
        if (verified.digest != intent.digest) throw CommandDataException("approval.request_conflict")
        if (dao.get(intent.requestId) != null) throw CommandDataException("approval.request_conflict")
        dao.approvalGet(intent.requestId)?.let { existing ->
            if (existing.digest != intent.digest) throw CommandDataException("approval.request_conflict")
            return@transaction existing.decode()
        }
        if (dao.approvalById(intent.approvalId) != null) throw CommandDataException("approval.reconcile_required")
        if (dao.approvalCount() >= 128 || dao.approvalBytes() + intent.bytes > 8L * 1024 * 1024) dao.evictFinalApprovals()
        if (dao.approvalCount() >= 128 || dao.approvalBytes() + intent.bytes > 8L * 1024 * 1024) throw CommandDataException("data.outbox_limit")
        ApprovalDecisionEvolution.created(verified, now).also { dao.approvalInsert(it.encode()) }
    }
    override suspend fun list(runtime: String, session: String): List<PendingApprovalDecision> = transaction {
        it.approvals(Contract.uuid(runtime), Contract.uuid(session)).map { row -> row.decode() }
    }
    override suspend fun beginAttempt(id: String, now: Long): PendingApprovalDecision = transaction { dao ->
        val row = dao.approvalGet(Contract.uuid(id))?.decode() ?: throw CommandDataException("approval.not_found")
        ApprovalDecisionEvolution.begin(row, now).also { check(dao.approvalUpdate(it.encode()) == 1) }
    }
    override suspend fun record(id: String, proof: ApprovalStatus, now: Long, forwarding: ApprovalDelivery?): PendingApprovalDecision? = transaction { dao ->
        val previous = dao.approvalGet(Contract.uuid(id))?.decode() ?: return@transaction null
        ApprovalDecisionEvolution.record(previous, proof, now, forwarding).also { if (it !== previous) check(dao.approvalUpdate(it.encode()) == 1) }
    }
    override suspend fun uncertain(id: String, code: String, now: Long): PendingApprovalDecision? = transaction { dao ->
        val previous = dao.approvalGet(Contract.uuid(id))?.decode() ?: return@transaction null
        ApprovalDecisionEvolution.uncertain(previous, now, code).also { if (it !== previous) check(dao.approvalUpdate(it.encode()) == 1) }
    }
    override suspend fun rearm(id: String, proof: ApprovalStatus, now: Long): PendingApprovalDecision {
        // Commit newly proved acceptance/termination even when it rules out retry.
        val result = transaction { dao ->
            val previous = dao.approvalGet(Contract.uuid(id))?.decode() ?: throw CommandDataException("approval.not_found")
            val proved = ApprovalDecisionEvolution.record(previous, proof, now)
            if (proved !== previous) check(dao.approvalUpdate(proved.encode()) == 1)
            runCatching { ApprovalDecisionEvolution.rearm(proved, proof, now) }.also { possible ->
                possible.getOrNull()?.let { check(dao.approvalUpdate(it.encode()) == 1) }
            }
        }
        return result.getOrThrow()
    }
    override suspend fun discard(id: String) = transaction { dao ->
        val row = dao.approvalGet(Contract.uuid(id))?.decode() ?: return@transaction
        if (row.attempts > 0) throw CommandDataException("approval.reconcile_required")
        dao.approvalDelete(id)
    }
    override fun close() { closed.set(true) }

    private fun PendingApprovalDecision.encode() = ApprovalDecisionRow(intent.requestId, intent.approvalId, intent.runtimeId, intent.sessionId, intent.context.root.obj("workspace").string("workspace_id"), intent.epoch,
        intent.context.document.canonicalBytes(), intent.signed.compact, intent.digest, delivery.name, attempts, revision, createdAt, updatedAt,
        remote?.document?.canonicalBytes(), forwarding?.name, error, finalized(this))
    private fun ApprovalDecisionRow.decode(): PendingApprovalDecision {
        try {
            val intent = ApprovalDecisionIntent.restore(requestId, owner, key, context, compact)
            val remote = remote?.let { ApprovalStatus.parse(JsonDocument.parse(it).root) }
            val parsed = PendingApprovalDecision(intent, ApprovalDecisionDelivery.valueOf(delivery), attempts, revision, createdAt, updatedAt, remote, forwarding?.let(ApprovalDelivery::valueOf), error)
            if (intent.approvalId != approvalId || intent.runtimeId != runtimeId || intent.sessionId != sessionId || intent.context.root.obj("workspace").string("workspace_id") != workspaceId || intent.epoch != epoch || intent.digest != digest ||
                attempts !in 0..MAX_SAFE_INTEGER || revision !in 1..MAX_SAFE_INTEGER || createdAt < 0 || updatedAt < createdAt ||
                remote?.matches(intent.context) == false || finalized(parsed) != finalized) throw ProtocolException()
            val owned = remote?.decisionSha256 == intent.signed.payloadSha256 && remote?.decision == intent.decision.choice
            if ((parsed.delivery == ApprovalDecisionDelivery.ACCEPTED) != owned || owned && attempts == 0L || forwarding != null && !owned ||
                parsed.delivery == ApprovalDecisionDelivery.RECONCILE && attempts == 0L || parsed.delivery == ApprovalDecisionDelivery.PENDING &&
                attempts > 0 && remote?.state != ApprovalRemoteState.PENDING) throw ProtocolException()
            if (remote == null) {
                if (parsed.delivery != if (attempts == 0L) ApprovalDecisionDelivery.PENDING else ApprovalDecisionDelivery.RECONCILE) throw ProtocolException()
            } else {
                val checked = ApprovalDecisionEvolution.record(parsed, remote, updatedAt, parsed.forwarding)
                if (checked.delivery != parsed.delivery && !(parsed.delivery == ApprovalDecisionDelivery.PENDING && checked.delivery == ApprovalDecisionDelivery.RECONCILE && attempts > 0)) throw ProtocolException()
            }
            return parsed
        } catch (_: Exception) { throw CommandDataException("data.corrupt") }
    }
    private fun finalized(row: PendingApprovalDecision) = row.delivery in setOf(ApprovalDecisionDelivery.CONFLICT, ApprovalDecisionDelivery.ENDED) ||
        row.remote?.hostState in setOf(ApprovalHostState.SETTLED, ApprovalHostState.DENIED, ApprovalHostState.EXPIRED, ApprovalHostState.CANCELLED, ApprovalHostState.INVALIDATED)
}
