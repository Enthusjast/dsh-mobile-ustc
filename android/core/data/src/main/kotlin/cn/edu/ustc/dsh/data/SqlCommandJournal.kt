package cn.edu.ustc.dsh.data

import android.content.Context
import androidx.room.Room
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.crypto.RegisteredApprovalKey
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import kotlinx.coroutines.*
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.atomic.AtomicBoolean

/** Entire SQLite/WAL is SQLCipher-encrypted, under noBackupFilesDir. No plaintext fallback. */
class SqlCommandJournal private constructor(override val owner: CommandOwner, private val database: CommandDatabase, private val password: ByteArray, private val vault: DatabaseKeyVault) : CommandJournal, TranscriptCache {
    private val closed = AtomicBoolean()
    private val lock = Any()
    internal suspend fun <T> transaction(action: (CommandDao) -> T): T = withContext(Dispatchers.IO) {
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
        if (dao.approvalGet(intent.requestId) != null) throw CommandDataException("command.request_conflict")
        if(intent.kind.question && intent.questionDefinition==null) throw CommandDataException("question.context_required")
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
    override suspend fun listCreations(runtime: String): List<PendingCommand> = transaction { it.creations(Contract.uuid(runtime)).map(CommandRow::decode) }
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
    fun approvalDecisions(key: RegisteredApprovalKey): ApprovalDecisionJournal = SqlApprovalDecisionJournal(this, key)
    suspend fun retainApprovals(scopes: Map<String, RelayScope>) = transaction { dao ->
        scopes.keys.forEach(Contract::uuid)
        for (runtime in dao.approvalRuntimes()) {
            val grant = scopes[runtime]
            if (grant == null || !grant.actions.containsAll(setOf("session.read", "approval.decide"))) dao.revokeApprovals(runtime)
            else dao.restrictApprovals(runtime, grant.sessions.toList(), grant.workspaces.toList())
        }
    }
    override suspend fun revokeRuntime(runtime: String) = transaction { dao -> dao.revokeRuntime(Contract.uuid(runtime)); dao.revokeApprovals(runtime); dao.deleteRuntimeCache(runtime) }
    override suspend fun revokeSessionCommands(runtime: String) = transaction { dao -> dao.revokeSessionCommands(Contract.uuid(runtime)); dao.revokeApprovals(runtime); dao.deleteRuntimeCache(runtime) }
    suspend fun retainCreations(scopes: Map<String, RelayScope>) = transaction { dao ->
        scopes.keys.forEach(Contract::uuid)
        for(runtime in dao.creationRuntimes()) {
            val granted=scopes[runtime]
            if(granted==null || "command.status" !in granted.actions) dao.revokeCreations(runtime)
            else dao.restrictCreations(runtime,granted.workspaces.toList())
        }
    }
    override suspend fun loadTranscript(runtime: String, session: String, workspace: String?): CachedTranscript? = transaction { dao ->
        Contract.uuid(runtime); Contract.uuid(session); workspace?.let(Contract::uuid)
        val now = System.currentTimeMillis()
        dao.expireCache((now - CACHE_RETENTION_MILLIS).coerceAtLeast(0), now)
        val row = dao.cachedSession(runtime, session) ?: return@transaction null
        if (row.workspaceId != workspace) { dao.deleteCache(runtime, session); return@transaction null }
        val records = dao.cachedRecords(runtime, session)
        if (records.size != row.recordCount || records.sumOf { it.body.size.toLong() } != row.bytes || row.bytes > CACHE_SESSION_BYTES) throw CommandDataException("data.corrupt")
        val parsed = records.map {
            SessionRecord.parse(SessionJson.parse(it.body)).also { parsed -> if (parsed.seq != it.seq) throw CommandDataException("data.corrupt") }
        }
        dao.touchCache(runtime, session, now)
        CachedTranscript(row.epoch, row.savedAt, parsed)
    }
    override suspend fun saveTranscript(runtime: String, session: String, workspace: String?, epoch: String, transcript: SessionTranscript, now: Long) {
        Contract.uuid(runtime); Contract.uuid(session); Contract.uuid(epoch); workspace?.let(Contract::uuid)
        if (!transcript.durableOnly || transcript.records.any { it.seq > transcript.persistedThrough } || transcript.items.any { it.live || !it.persisted } || now < 0) throw CommandDataException("data.unconfirmed_history")
        withContext(Dispatchers.IO) {
            val encoded = transcript.records.map { CachedRecordRow(runtime, session, it.seq, SessionJson.encode(it.raw)) }
            var bytes = encoded.sumOf { it.body.size.toLong() }; var first = 0
            while (bytes > CACHE_SESSION_BYTES && first < encoded.size) bytes -= encoded[first++].body.size
            val retained = encoded.drop(first)
            transaction { dao ->
                dao.expireCache((now - CACHE_RETENTION_MILLIS).coerceAtLeast(0), now)
                dao.deleteCache(runtime, session)
                while (dao.cacheCount() >= CACHE_SESSIONS || dao.cacheBytes() + bytes > CACHE_TOTAL_BYTES) {
                    val oldest = dao.oldestCache() ?: throw CommandDataException("data.cache_limit")
                    dao.deleteCache(oldest.runtimeId, oldest.sessionId)
                }
                dao.cacheSession(CachedSessionRow(runtime, session, workspace, epoch, now, now, retained.size, bytes))
                dao.cacheRecords(retained)
            }
        }
    }
    override suspend fun removeTranscript(runtime: String, session: String) = transaction { dao -> dao.deleteCache(Contract.uuid(runtime), Contract.uuid(session)) }
    override suspend fun removeRuntimeTranscripts(runtime: String) = transaction { dao -> dao.deleteRuntimeCache(Contract.uuid(runtime)) }
    override suspend fun retainTranscripts(scopes: Map<String, RelayScope>) = transaction { dao ->
        scopes.keys.forEach(Contract::uuid)
        val now = System.currentTimeMillis()
        dao.expireCache((now - CACHE_RETENTION_MILLIS).coerceAtLeast(0), now)
        for (runtime in dao.cachedRuntimes()) {
            val granted = scopes[runtime]
            if (granted == null || "session.read" !in granted.actions) dao.deleteRuntimeCache(runtime)
            else dao.restrictCache(runtime, granted.sessions.toList(), granted.workspaces.toList())
        }
    }
    override fun close() {
        closed.set(true)
        synchronized(lock) { try { database.close() } finally { password.fill(0) } }
    }
    companion object {
        const val CACHE_RETENTION_MILLIS = 30L * 24 * 60 * 60 * 1000
        const val CACHE_SESSIONS = 128
        const val CACHE_SESSION_BYTES = 8L * 1024 * 1024
        const val CACHE_TOTAL_BYTES = 32L * 1024 * 1024
        private val migration1To2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("CREATE TABLE IF NOT EXISTS cached_sessions (runtimeId TEXT NOT NULL, sessionId TEXT NOT NULL, workspaceId TEXT, epoch TEXT NOT NULL, savedAt INTEGER NOT NULL, accessedAt INTEGER NOT NULL, recordCount INTEGER NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY(runtimeId,sessionId))")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_cached_sessions_savedAt ON cached_sessions(savedAt)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_cached_sessions_accessedAt ON cached_sessions(accessedAt)")
                db.execSQL("CREATE TABLE IF NOT EXISTS cached_records (runtimeId TEXT NOT NULL, sessionId TEXT NOT NULL, seq INTEGER NOT NULL, body BLOB NOT NULL, PRIMARY KEY(runtimeId,sessionId,seq), FOREIGN KEY(runtimeId,sessionId) REFERENCES cached_sessions(runtimeId,sessionId) ON UPDATE NO ACTION ON DELETE CASCADE)")
            }
        }
        private val migration2To3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("CREATE TABLE commands_v3 (requestId TEXT NOT NULL, runtimeId TEXT NOT NULL, sessionId TEXT, intent BLOB NOT NULL, digest TEXT NOT NULL, delivery TEXT NOT NULL, remote TEXT, attempts INTEGER NOT NULL, revision INTEGER NOT NULL, createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL, remoteTimestamp TEXT, everHostSaved INTEGER NOT NULL, everAgentQueued INTEGER NOT NULL, error TEXT, workspaceId TEXT, createdSessionId TEXT, PRIMARY KEY(requestId))")
                db.execSQL("INSERT INTO commands_v3(requestId,runtimeId,sessionId,intent,digest,delivery,remote,attempts,revision,createdAt,updatedAt,remoteTimestamp,everHostSaved,everAgentQueued,error) SELECT requestId,runtimeId,sessionId,intent,digest,delivery,remote,attempts,revision,createdAt,updatedAt,remoteTimestamp,everHostSaved,everAgentQueued,error FROM commands")
                db.execSQL("DROP TABLE commands")
                db.execSQL("ALTER TABLE commands_v3 RENAME TO commands")
                db.execSQL("CREATE INDEX index_commands_runtimeId_sessionId_createdAt ON commands(runtimeId,sessionId,createdAt)")
                db.execSQL("CREATE INDEX index_commands_runtimeId_workspaceId_createdAt ON commands(runtimeId,workspaceId,createdAt)")
            }
        }
        private val migration3To4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("CREATE TABLE IF NOT EXISTS approval_decisions (requestId TEXT NOT NULL, approvalId TEXT NOT NULL, runtimeId TEXT NOT NULL, sessionId TEXT NOT NULL, workspaceId TEXT NOT NULL, epoch TEXT NOT NULL, context BLOB NOT NULL, compact TEXT NOT NULL, digest TEXT NOT NULL, delivery TEXT NOT NULL, attempts INTEGER NOT NULL, revision INTEGER NOT NULL, createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL, remote BLOB, forwarding TEXT, error TEXT, finalized INTEGER NOT NULL, PRIMARY KEY(requestId))")
                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_approval_decisions_approvalId ON approval_decisions(approvalId)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_approval_decisions_runtimeId_sessionId_createdAt ON approval_decisions(runtimeId,sessionId,createdAt)")
            }
        }
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
                    .addMigrations(migration1To2, migration2To3, migration3To4)
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
    attempts, revision, createdAt, updatedAt, remoteTimestamp, everHostSaved, everAgentQueued, error, intent.workspaceId, createdSessionId)
private fun CommandRow.decode(): PendingCommand {
    val parsed = CommandIntent.stored(intent)
    if(parsed.kind.question && parsed.questionDefinition==null) throw CommandDataException("data.corrupt")
    if (parsed.requestId != requestId || parsed.runtimeId != runtimeId || parsed.sessionId != sessionId || parsed.workspaceId != workspaceId || parsed.digest != digest || attempts < 0 || revision < 1 ||
        delivery == CommandDelivery.PENDING.name && attempts != 0L && remote != RemoteCommandState.RECEIVED.name) throw CommandDataException("data.corrupt")
    createdSessionId?.let(Contract::uuid)
    if ((parsed.kind == CommandKind.CREATE && remote == RemoteCommandState.SETTLED.name) != (createdSessionId != null)) throw CommandDataException("data.corrupt")
    return PendingCommand(parsed, CommandDelivery.valueOf(delivery), remote?.let(RemoteCommandState::valueOf), attempts, revision, createdAt, updatedAt, remoteTimestamp, everHostSaved, everAgentQueued, error, createdSessionId)
}
