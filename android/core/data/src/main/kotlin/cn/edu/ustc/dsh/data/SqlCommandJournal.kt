package cn.edu.ustc.dsh.data

import android.content.Context
import androidx.room.Room
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.atomic.AtomicBoolean

/** Entire SQLite/WAL is SQLCipher-encrypted, under noBackupFilesDir. No plaintext fallback. */
class SqlCommandJournal private constructor(override val owner: CommandOwner, private val database: CommandDatabase, private val password: ByteArray, private val vault: DatabaseKeyVault) : CommandJournal {
    private val closed = AtomicBoolean()
    private val lock = Any()
    private suspend fun <T> transaction(action: (CommandDao) -> T): T = withContext(Dispatchers.IO) {
        val operation = currentCoroutineContext()
        checked {
            synchronized(lock) {
                operation.ensureActive()
                if (closed.get()) throw CommandDataException("data.closed")
                vault.unlocked()
                database.runInTransaction(Callable {
                    val result = action(database.commands())
                    operation.ensureActive()
                    if (closed.get()) throw CommandDataException("data.closed")
                    result
                })
            }
        }
    }
    override suspend fun create(intent: CommandIntent, now: Long): PendingCommand = transaction { dao ->
        dao.get(intent.requestId)?.let { existing ->
            if (existing.digest != intent.digest || !existing.intent.contentEquals(intent.storageBytes())) throw CommandDataException("command.request_conflict")
            return@transaction existing.decode()
        }
        val bytes = intent.storageBytes()
        if (dao.count() >= 128 || dao.bytes() + bytes.size > 8L * 1024 * 1024) dao.evictDelivered()
        if (dao.count() >= 128 || dao.bytes() + bytes.size > 8L * 1024 * 1024) throw CommandDataException("data.outbox_limit")
        CommandEvolution.created(intent, now).also { dao.insert(it.encode()) }
    }
    override suspend fun list(runtime: String, session: String): List<PendingCommand> {
        Contract.uuid(runtime); Contract.uuid(session)
        return transaction { it.list(runtime, session).map(CommandRow::decode) }
    }
    override suspend fun beginAttempt(id: String, now: Long) = transaction { dao ->
        val previous = dao.get(Contract.uuid(id))?.decode() ?: throw CommandDataException("command.not_found")
        CommandEvolution.begin(previous, now).also { check(dao.update(it.encode()) == 1) }
    }
    override suspend fun record(receipt: CommandReceipt): PendingCommand? = transaction { dao ->
        val previous = dao.get(receipt.requestId)?.decode() ?: return@transaction null
        CommandEvolution.receipt(previous, receipt).also { next -> if (next !== previous) check(dao.update(next.encode()) == 1) }
    }
    override suspend fun uncertain(id: String, code: String): PendingCommand? = transaction { dao ->
        val previous = dao.get(Contract.uuid(id))?.decode() ?: return@transaction null
        CommandEvolution.uncertain(previous, code, System.currentTimeMillis()).also { next -> if (next !== previous) check(dao.update(next.encode()) == 1) }
    }
    override suspend fun rearm(id: String, proof: CommandReceipt): PendingCommand = transaction { dao ->
        val previous = dao.get(Contract.uuid(id))?.decode() ?: throw CommandDataException("command.not_found")
        CommandEvolution.rearm(previous, proof).also { check(dao.update(it.encode()) == 1) }
    }
    override suspend fun discard(id: String) = transaction { dao ->
        val existing = dao.get(Contract.uuid(id))?.decode() ?: return@transaction
        if (existing.attempts > 0 && existing.remote !in setOf(RemoteCommandState.AGENT_QUEUED, RemoteCommandState.OBSERVED, RemoteCommandState.SETTLED, RemoteCommandState.REJECTED)) throw CommandDataException("command.reconcile_required")
        dao.delete(id)
    }
    override suspend fun revokeRuntime(runtime: String) = transaction { dao -> dao.revokeRuntime(Contract.uuid(runtime)) }
    override fun close() {
        closed.set(true)
        synchronized(lock) { try { database.close() } finally { password.fill(0) } }
    }
    companion object {
        fun open(context: Context, owner: CommandOwner): SqlCommandJournal = checked {
            System.loadLibrary("sqlcipher")
            val directory = directory(context, owner.accountId, owner.organizationId).resolve(owner.fingerprint)
            check(directory.isDirectory || directory.mkdirs())
            val file = File(directory, "commands.db")
            val vault = DatabaseKeyVault(context.applicationContext, owner, directory)
            val password = vault.open(file.exists())
            var database: CommandDatabase? = null
            try {
                database = Room.databaseBuilder(context.applicationContext, CommandDatabase::class.java, file.absolutePath)
                    .openHelperFactory(SupportOpenHelperFactory(password, null, true))
                    .setJournalMode(androidx.room.RoomDatabase.JournalMode.WRITE_AHEAD_LOGGING).build()
                database.openHelper.writableDatabase.execSQL("PRAGMA synchronous=FULL")
                database.runInTransaction {
                    val dao = database.commands()
                    val identity = dao.identity()
                    if (identity == null) dao.identity(DatabaseIdentity(ownerHash = owner.fingerprint))
                    else if (identity.ownerHash != owner.fingerprint) throw CommandDataException("data.owner_mismatch")
                }
                SqlCommandJournal(owner, database, password, vault)
            } catch (error: Exception) { database?.close(); password.fill(0); throw error }
        }
        fun eraseAccount(context: Context, account: String, organization: String) = checked {
            DatabaseKeyVault.eraseScope(account, organization)
            val directory = directory(context, account, organization)
            if (directory.exists()) check(directory.deleteRecursively())
            check(!directory.exists())
        }
        private fun directory(context: Context, account: String, organization: String) =
            File(context.noBackupFilesDir, "mobile-data/${CommandOwner.scopeHash(account, organization)}")
    }
}

private fun PendingCommand.encode() = CommandRow(intent.requestId, intent.runtimeId, intent.sessionId, intent.storageBytes(), intent.digest, delivery.name, remote?.name,
    attempts, revision, createdAt, updatedAt, remoteTimestamp, everHostSaved, everAgentQueued, error)
private fun CommandRow.decode(): PendingCommand {
    val parsed = CommandIntent.parse(JsonDocument.parse(intent).root)
    if (parsed.requestId != requestId || parsed.runtimeId != runtimeId || parsed.sessionId != sessionId || parsed.digest != digest || attempts < 0 || revision < 1 ||
        delivery == CommandDelivery.PENDING.name && attempts != 0L && remote != RemoteCommandState.RECEIVED.name) throw CommandDataException("data.corrupt")
    return PendingCommand(parsed, CommandDelivery.valueOf(delivery), remote?.let(RemoteCommandState::valueOf), attempts, revision, createdAt, updatedAt, remoteTimestamp, everHostSaved, everAgentQueued, error)
}
