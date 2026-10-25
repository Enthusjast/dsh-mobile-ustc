package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Deterministic SDK fixture. SQLCipher/WAL durability is exercised separately on Android. */
internal class MemoryApprovalDecisionJournal(override val owner: LocalDataOwner) : ApprovalDecisionJournal {
    private val records = linkedMapOf<String, PendingApprovalDecision>()
    private val mutex = Mutex()
    var failBegin = false
    override suspend fun create(intent: ApprovalDecisionIntent, now: Long): PendingApprovalDecision = mutex.withLock {
        records[intent.requestId]?.let { if (it.intent.digest != intent.digest) throw CommandDataException("approval.request_conflict"); return@withLock it }
        if (records.values.any { it.intent.approvalId == intent.approvalId }) throw CommandDataException("approval.reconcile_required")
        ApprovalDecisionEvolution.created(intent, now).also { records[intent.requestId] = it }
    }
    override suspend fun list(runtime: String, session: String) = mutex.withLock { records.values.filter { it.intent.runtimeId == runtime && it.intent.sessionId == session } }
    override suspend fun beginAttempt(id: String, now: Long) = mutex.withLock {
        if (failBegin) throw CommandDataException("data.unavailable")
        ApprovalDecisionEvolution.begin(records[id]!!, now).also { records[id] = it }
    }
    override suspend fun record(id: String, proof: ApprovalStatus, now: Long, forwarding: ApprovalDelivery?) = mutex.withLock {
        records[id]?.let { ApprovalDecisionEvolution.record(it, proof, now, forwarding).also { next -> records[id] = next } }
    }
    override suspend fun uncertain(id: String, code: String, now: Long) = mutex.withLock {
        records[id]?.let { ApprovalDecisionEvolution.uncertain(it, now, code).also { next -> records[id] = next } }
    }
    override suspend fun rearm(id: String, proof: ApprovalStatus, now: Long) = mutex.withLock {
        val proved = ApprovalDecisionEvolution.record(records[id]!!, proof, now); records[id] = proved
        runCatching { ApprovalDecisionEvolution.rearm(proved, proof, now).also { records[id] = it } }
    }.getOrThrow()
    override suspend fun discard(id: String) { mutex.withLock { if (records[id]?.attempts?.let { it > 0 } == true) throw CommandDataException("approval.reconcile_required"); records.remove(id) } }
    override fun close() = Unit
}
