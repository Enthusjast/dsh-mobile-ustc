package cn.edu.ustc.dsh.data

import androidx.room.*

@Entity(tableName = "database_identity")
internal data class DatabaseIdentity(@PrimaryKey val slot: Int = 1, val ownerHash: String)

@Entity(tableName = "commands", indices = [Index(value = ["runtimeId", "sessionId", "createdAt"])])
internal data class CommandRow(
    @PrimaryKey val requestId: String, val runtimeId: String, val sessionId: String, val intent: ByteArray, val digest: String,
    val delivery: String, val remote: String?, val attempts: Long, val revision: Long, val createdAt: Long, val updatedAt: Long,
    val remoteTimestamp: String?, val everHostSaved: Boolean, val everAgentQueued: Boolean, val error: String?,
)

@Dao internal interface CommandDao {
    @Query("SELECT * FROM database_identity WHERE slot=1") fun identity(): DatabaseIdentity?
    @Insert fun identity(value: DatabaseIdentity)
    @Query("SELECT * FROM commands WHERE requestId=:id") fun get(id: String): CommandRow?
    @Query("SELECT * FROM commands WHERE runtimeId=:runtime AND sessionId=:session ORDER BY createdAt,requestId") fun list(runtime: String, session: String): List<CommandRow>
    @Query("SELECT COUNT(*) FROM commands") fun count(): Int
    @Query("SELECT COALESCE(SUM(length(intent)),0) FROM commands") fun bytes(): Long
    @Insert fun insert(row: CommandRow)
    @Update fun update(row: CommandRow): Int
    @Query("DELETE FROM commands WHERE requestId=:id") fun delete(id: String)
    @Query("DELETE FROM commands WHERE runtimeId=:runtime") fun revokeRuntime(runtime: String)
    @Query("DELETE FROM commands WHERE requestId IN (SELECT requestId FROM commands WHERE delivery='CONFIRMED' AND remote IN ('AGENT_QUEUED','OBSERVED','SETTLED','REJECTED') ORDER BY createdAt,requestId LIMIT 32)") fun evictDelivered()
}

@Database(entities = [DatabaseIdentity::class, CommandRow::class], version = 1, exportSchema = true)
internal abstract class CommandDatabase : RoomDatabase() { abstract fun commands(): CommandDao }
