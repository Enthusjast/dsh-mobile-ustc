package cn.edu.ustc.dsh.data

import androidx.room.*

@Entity(tableName = "database_identity")
internal data class DatabaseIdentity(@PrimaryKey val slot: Int = 1, val ownerHash: String)

@Entity(tableName = "commands", indices = [Index(value = ["runtimeId", "sessionId", "createdAt"]), Index(value = ["runtimeId", "workspaceId", "createdAt"])])
internal data class CommandRow(
    @PrimaryKey val requestId: String, val runtimeId: String, val sessionId: String?, val intent: ByteArray, val digest: String,
    val delivery: String, val remote: String?, val attempts: Long, val revision: Long, val createdAt: Long, val updatedAt: Long,
    val remoteTimestamp: String?, val everHostSaved: Boolean, val everAgentQueued: Boolean, val error: String?, val workspaceId: String? = null, val createdSessionId: String? = null,
)

@Entity(tableName = "approval_decisions", indices = [Index(value = ["approvalId"], unique = true), Index(value = ["runtimeId", "sessionId", "createdAt"])])
internal data class ApprovalDecisionRow(
    @PrimaryKey val requestId: String, val approvalId: String, val runtimeId: String, val sessionId: String, val workspaceId: String, val epoch: String,
    val context: ByteArray, val compact: String, val digest: String, val delivery: String, val attempts: Long, val revision: Long,
    val createdAt: Long, val updatedAt: Long, val remote: ByteArray?, val forwarding: String?, val error: String?, val finalized: Boolean,
)

@Entity(tableName = "cached_sessions", primaryKeys = ["runtimeId", "sessionId"], indices = [Index(value = ["savedAt"]), Index(value = ["accessedAt"])])
internal data class CachedSessionRow(val runtimeId: String, val sessionId: String, val workspaceId: String?, val epoch: String, val savedAt: Long, val accessedAt: Long, val recordCount: Int, val bytes: Long)

@Entity(tableName = "cached_records", primaryKeys = ["runtimeId", "sessionId", "seq"], foreignKeys = [ForeignKey(entity = CachedSessionRow::class,
    parentColumns = ["runtimeId", "sessionId"], childColumns = ["runtimeId", "sessionId"], onDelete = ForeignKey.CASCADE)])
internal data class CachedRecordRow(val runtimeId: String, val sessionId: String, val seq: Long, val body: ByteArray)

@Dao internal interface CommandDao {
    @Query("SELECT * FROM database_identity WHERE slot=1") fun identity(): DatabaseIdentity?
    @Insert fun identity(value: DatabaseIdentity)
    @Query("SELECT * FROM commands WHERE requestId=:id") fun get(id: String): CommandRow?
    @Query("SELECT * FROM approval_decisions WHERE requestId=:id") fun approvalGet(id: String): ApprovalDecisionRow?
    @Query("SELECT * FROM approval_decisions WHERE approvalId=:id") fun approvalById(id: String): ApprovalDecisionRow?
    @Query("SELECT * FROM approval_decisions WHERE runtimeId=:runtime AND sessionId=:session ORDER BY createdAt,requestId") fun approvals(runtime: String, session: String): List<ApprovalDecisionRow>
    @Query("SELECT COUNT(*) FROM approval_decisions") fun approvalCount(): Int
    @Query("SELECT COALESCE(SUM(length(context)+length(compact)),0) FROM approval_decisions") fun approvalBytes(): Long
    @Insert fun approvalInsert(row: ApprovalDecisionRow)
    @Update fun approvalUpdate(row: ApprovalDecisionRow): Int
    @Query("DELETE FROM approval_decisions WHERE requestId=:id") fun approvalDelete(id: String)
    @Query("DELETE FROM approval_decisions WHERE runtimeId=:runtime") fun revokeApprovals(runtime: String)
    @Query("SELECT DISTINCT runtimeId FROM approval_decisions") fun approvalRuntimes(): List<String>
    @Query("DELETE FROM approval_decisions WHERE runtimeId=:runtime AND sessionId NOT IN (:sessions) AND workspaceId NOT IN (:workspaces)") fun restrictApprovals(runtime: String, sessions: List<String>, workspaces: List<String>)
    @Query("DELETE FROM approval_decisions WHERE requestId IN (SELECT requestId FROM approval_decisions WHERE finalized=1 ORDER BY createdAt,requestId LIMIT 32)") fun evictFinalApprovals()
    @Query("SELECT * FROM commands WHERE runtimeId=:runtime AND sessionId=:session ORDER BY createdAt,requestId") fun list(runtime: String, session: String): List<CommandRow>
    @Query("SELECT * FROM commands WHERE runtimeId=:runtime AND workspaceId IS NOT NULL ORDER BY createdAt,requestId") fun creations(runtime: String): List<CommandRow>
    @Query("SELECT COUNT(*) FROM commands") fun count(): Int
    @Query("SELECT COALESCE(SUM(length(intent)),0) FROM commands") fun bytes(): Long
    @Insert fun insert(row: CommandRow)
    @Update fun update(row: CommandRow): Int
    @Query("DELETE FROM commands WHERE requestId=:id") fun delete(id: String)
    @Query("DELETE FROM commands WHERE runtimeId=:runtime") fun revokeRuntime(runtime: String)
    @Query("DELETE FROM commands WHERE runtimeId=:runtime AND workspaceId IS NULL") fun revokeSessionCommands(runtime: String)
    @Query("SELECT DISTINCT runtimeId FROM commands WHERE workspaceId IS NOT NULL") fun creationRuntimes(): List<String>
    @Query("DELETE FROM commands WHERE runtimeId=:runtime AND workspaceId IS NOT NULL") fun revokeCreations(runtime: String)
    @Query("DELETE FROM commands WHERE runtimeId=:runtime AND workspaceId IS NOT NULL AND workspaceId NOT IN (:workspaces)") fun restrictCreations(runtime: String, workspaces: List<String>)
    @Query("DELETE FROM commands WHERE requestId IN (SELECT requestId FROM commands WHERE delivery='CONFIRMED' AND remote IN ('AGENT_QUEUED','OBSERVED','SETTLED','REJECTED') ORDER BY createdAt,requestId LIMIT 32)") fun evictDelivered()
    @Query("SELECT * FROM cached_sessions WHERE runtimeId=:runtime AND sessionId=:session") fun cachedSession(runtime: String, session: String): CachedSessionRow?
    @Query("SELECT * FROM cached_records WHERE runtimeId=:runtime AND sessionId=:session ORDER BY seq") fun cachedRecords(runtime: String, session: String): List<CachedRecordRow>
    @Insert fun cacheSession(row: CachedSessionRow)
    @Insert fun cacheRecords(rows: List<CachedRecordRow>)
    @Query("UPDATE cached_sessions SET accessedAt=:now WHERE runtimeId=:runtime AND sessionId=:session") fun touchCache(runtime: String, session: String, now: Long)
    @Query("DELETE FROM cached_sessions WHERE runtimeId=:runtime AND sessionId=:session") fun deleteCache(runtime: String, session: String)
    @Query("DELETE FROM cached_sessions WHERE runtimeId=:runtime") fun deleteRuntimeCache(runtime: String)
    @Query("DELETE FROM cached_sessions WHERE savedAt < :cutoff OR savedAt > :now") fun expireCache(cutoff: Long, now: Long)
    @Query("SELECT COUNT(*) FROM cached_sessions") fun cacheCount(): Int
    @Query("SELECT COALESCE(SUM(bytes),0) FROM cached_sessions") fun cacheBytes(): Long
    @Query("SELECT * FROM cached_sessions ORDER BY accessedAt,savedAt,runtimeId,sessionId LIMIT 1") fun oldestCache(): CachedSessionRow?
    @Query("SELECT DISTINCT runtimeId FROM cached_sessions") fun cachedRuntimes(): List<String>
    @Query("DELETE FROM cached_sessions WHERE runtimeId=:runtime AND sessionId NOT IN (:sessions) AND (workspaceId IS NULL OR workspaceId NOT IN (:workspaces))") fun restrictCache(runtime: String, sessions: List<String>, workspaces: List<String>)
}

@Database(entities = [DatabaseIdentity::class, CommandRow::class, ApprovalDecisionRow::class, CachedSessionRow::class, CachedRecordRow::class], version = 4, exportSchema = true)
internal abstract class CommandDatabase : RoomDatabase() { abstract fun commands(): CommandDao }
