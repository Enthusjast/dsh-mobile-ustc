package cn.edu.ustc.dsh.data

import android.app.KeyguardManager
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import kotlinx.coroutines.runBlocking
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class CacheMigrationTest {
    @Test fun encryptedVersionOneDatabaseKeepsTheOriginalUncertainCommandAndGainsHistoryTables(): Unit = runBlocking { upgrade(1) }
    @Test fun encryptedVersionTwoKeepsHistoryAndIntentWhenCreationTargetsAreAdded(): Unit=runBlocking { upgrade(2) }
    private suspend fun upgrade(version: Int) {
        val instrumentation = InstrumentationRegistry.getInstrumentation(); val context = instrumentation.targetContext
        assumeTrue("explicit owned account fixture required", InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        val guard = context.getSystemService(KeyguardManager::class.java); assertTrue(guard.isDeviceSecure && !guard.isDeviceLocked)
        val owner = LocalDataOwner(UUID.randomUUID().toString(), UUID.randomUUID().toString(), "a".repeat(64), UUID.randomUUID().toString(), UUID.randomUUID().toString())
        val command = CommandIntent.message(UUID.randomUUID().toString(), UUID.randomUUID().toString(), UUID.randomUUID().toString(), "queue", "V1_ENCRYPTED_ORIGINAL_中文🙂")
        val historyEpoch=UUID.randomUUID().toString()
        val history=SessionJson.encode(jsonObject("native_seq" to 0L.json(),"time" to 1000L.json(),"type" to "user/message".json(),"data" to jsonObject("content" to JsonArray(listOf(jsonObject("type" to "text".json(),"text" to "V2_PERSISTED_HISTORY_中文🙂".json()))))))
        val directory = File(context.noBackupFilesDir, "mobile-data/${owner.scopeHash}/${owner.fingerprint}")
        check(directory.mkdirs()); System.loadLibrary("sqlcipher")
        val password = DatabaseKeyVault(context, owner, directory).open(false)
        try {
            val schema = JSONObject(instrumentation.context.assets.open("cn.edu.ustc.dsh.data.CommandDatabase/$version.json").bufferedReader().use { it.readText() }).getJSONObject("database")
            val factory = SupportOpenHelperFactory(password.copyOf(), null, true)
            factory.create(SupportSQLiteOpenHelper.Configuration.builder(context).name(File(directory, "commands.db").absolutePath)
                .callback(object : SupportSQLiteOpenHelper.Callback(version) {
                    override fun onCreate(db: SupportSQLiteDatabase) {
                        val entities = schema.getJSONArray("entities")
                        for (i in 0 until entities.length()) {
                            val entity = entities.getJSONObject(i); val name = entity.getString("tableName")
                            db.execSQL(entity.getString("createSql").replace("\${TABLE_NAME}", name))
                            val indices = entity.optJSONArray("indices")
                            if (indices != null) for (j in 0 until indices.length()) db.execSQL(indices.getJSONObject(j).getString("createSql").replace("\${TABLE_NAME}", name))
                        }
                        val setup = schema.getJSONArray("setupQueries"); for (i in 0 until setup.length()) db.execSQL(setup.getString(i))
                        db.execSQL("INSERT INTO database_identity(slot,ownerHash) VALUES(1,?)", arrayOf(owner.fingerprint))
                        db.execSQL("INSERT INTO commands(requestId,runtimeId,sessionId,intent,digest,delivery,remote,attempts,revision,createdAt,updatedAt,remoteTimestamp,everHostSaved,everAgentQueued,error) VALUES(?,?,?,?,?,'RECONCILE',NULL,1,2,1000,1001,NULL,0,0,NULL)",
                            arrayOf(command.requestId, command.runtimeId, command.sessionId, command.storageBytes(), command.digest))
                        if(version>=2) {
                            val now=System.currentTimeMillis()
                            db.execSQL("INSERT INTO cached_sessions(runtimeId,sessionId,workspaceId,epoch,savedAt,accessedAt,recordCount,bytes) VALUES(?,?,NULL,?,?,?,1,?)",arrayOf<Any?>(command.runtimeId,command.sessionId,historyEpoch,now,now,history.size))
                            db.execSQL("INSERT INTO cached_records(runtimeId,sessionId,seq,body) VALUES(?,?,0,?)",arrayOf(command.runtimeId,command.sessionId,history))
                        }
                    }
                    override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) = error("old fixture cannot upgrade")
                }).build()).use { it.writableDatabase }
            SqlCommandJournal.open(context, owner).use { migrated ->
                val original = migrated.list(command.runtimeId, command.sessionId!!).single()
                assertEquals(command.requestId, original.intent.requestId); assertEquals(command.text(), original.intent.text())
                assertEquals(CommandDelivery.RECONCILE, original.delivery); assertEquals(1L, original.attempts)
                if(version>=2) {
                    val restored=migrated.loadTranscript(command.runtimeId,command.sessionId!!,null)!!
                    assertEquals(historyEpoch,restored.epoch);assertEquals("V2_PERSISTED_HISTORY_中文🙂",restored.transcript.items.single().blocks.single().text)
                }
                val workspace=UUID.randomUUID().toString();val result=UUID.randomUUID().toString()
                val creation=CommandIntent.createSession(UUID.randomUUID().toString(),command.runtimeId,workspace,"standard",historyEpoch)
                migrated.create(creation);migrated.beginAttempt(creation.requestId)
                migrated.record(CommandReceipt(creation.requestId,result,creation.digest,RemoteCommandState.SETTLED,java.time.Instant.now().toString(),workspaceId=workspace))
                assertEquals(result,migrated.listCreations(command.runtimeId).single().createdSessionId)
                val epoch = UUID.randomUUID().toString()
                migrated.saveTranscript(command.runtimeId, command.sessionId!!, null, epoch, CachedTranscript(epoch, System.currentTimeMillis(), emptyList()).transcript)
                assertNotNull(migrated.loadTranscript(command.runtimeId, command.sessionId!!, null))
            }
        } finally { password.fill(0); SqlCommandJournal.eraseAccount(context, owner.accountId, owner.organizationId) }
    }
}
