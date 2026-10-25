package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.command.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Test-only deterministic persistence boundary; Android tests use real SQLCipher/WAL. */
internal class MemoryCommandJournal(override val owner: CommandOwner) : CommandJournal {
    private val rows = linkedMapOf<String, PendingCommand>()
    private val mutex = Mutex()
    var failBegin = false
    override suspend fun create(intent: CommandIntent, now: Long): PendingCommand = mutex.withLock {
        if(intent.kind.question && intent.questionDefinition==null) throw CommandDataException("question.context_required")
        val old = rows[intent.requestId]
        if (old != null) { if (old.intent.digest != intent.digest || !old.intent.storageBytes().contentEquals(intent.storageBytes())) throw CommandDataException("command.request_conflict"); return@withLock old }
        CommandEvolution.created(intent, now).also { rows[intent.requestId] = it }
    }
    override suspend fun list(runtime: String, session: String) = mutex.withLock { rows.values.filter { it.intent.runtimeId == runtime && it.intent.sessionId == session } }
    override suspend fun listCreations(runtime: String) = mutex.withLock { rows.values.filter { it.intent.runtimeId == runtime && it.intent.kind == CommandKind.CREATE } }
    override suspend fun beginAttempt(id: String, now: Long): PendingCommand = mutex.withLock {
        if (failBegin) throw CommandDataException("data.unavailable")
        CommandEvolution.begin(rows[id]!!, now).also { rows[id] = it }
    }
    override suspend fun record(receipt: CommandReceipt): PendingCommand? = mutex.withLock { rows[receipt.requestId]?.let { CommandEvolution.receipt(it, receipt).also { next -> rows[receipt.requestId] = next } } }
    override suspend fun uncertain(id: String, code: String): PendingCommand? = mutex.withLock { rows[id]?.let { CommandEvolution.uncertain(it, code, System.currentTimeMillis()).also { next -> rows[id] = next } } }
    override suspend fun rearm(id: String, proof: CommandReceipt) = mutex.withLock { CommandEvolution.rearm(rows[id]!!, proof).also { rows[id] = it } }
    override suspend fun rearmUnboundFiles(id: String, now: Long) = mutex.withLock { CommandEvolution.rearmUnboundFiles(rows[id]!!, now).also { rows[id] = it } }
    override suspend fun discard(id: String) { mutex.withLock { rows.remove(id) } }
    override suspend fun revokeRuntime(runtime: String) { mutex.withLock { rows.entries.removeAll { it.value.intent.runtimeId == runtime } } }
    override suspend fun revokeSessionCommands(runtime: String) { mutex.withLock { rows.entries.removeAll { it.value.intent.runtimeId == runtime && it.value.intent.kind != CommandKind.CREATE } } }
    override fun close() = Unit
}
