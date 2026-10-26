package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import androidx.room.RoomDatabase
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.data.SqlCommandJournal
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.runBlocking
import org.junit.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class FileUploadPersistenceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val owner = CommandOwner(UUID.randomUUID().toString(), "11111111-1111-4111-8111-111111111111", "a".repeat(64), "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333")
    private val runtime = "44444444-4444-4444-8444-444444444444"
    private val session = "55555555-5555-4555-8555-555555555555"
    private val workspace = "66666666-6666-4666-8666-666666666666"
    private val opened = mutableListOf<SqlCommandJournal>()
    private fun open(value: CommandOwner = owner) = SqlCommandJournal.open(context, value).also { opened += it }
    private fun intent(request: String = UUID.randomUUID().toString()) = FileUploadIntent(request, runtime, session, workspace, FileManifest("PRIVATE_FILE_资料_${UUID.randomUUID()}.txt", 3, "a".repeat(64)))
    @Before fun guard() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        assertTrue(context.getSystemService(KeyguardManager::class.java).let { it.isDeviceSecure && !it.isDeviceLocked })
    }
    @After fun cleanup() { opened.forEach(SqlCommandJournal::close); SqlCommandJournal.eraseAccount(context, owner.accountId, owner.organizationId) }
    @Test fun encryptedUploadIntentAndItsOriginalMessageSurviveReopen(): Unit = runBlocking {
        val journal = open(); val upload = intent(); val fileId = UUID.randomUUID().toString()
        journal.createUpload(upload); journal.registeredUpload(upload.requestId, fileId)
        val message = CommandIntent.message(UUID.randomUUID().toString(), runtime, session, "queue", "private file message", listOf(fileId))
        journal.create(message)
        val linked = journal.uploads(runtime, session).single()
        assertEquals(message.requestId, linked.messageId)
        val marker = upload.manifest.name.toByteArray()
        val folder = File(context.noBackupFilesDir, "mobile-data/${owner.scopeHash}/${owner.fingerprint}")
        folder.walkTopDown().filter(File::isFile).forEach { file ->
            val bytes = file.readBytes()
            assertFalse(bytes.size >= marker.size && (0..bytes.size - marker.size).any { offset -> marker.indices.all { bytes[offset + it] == marker[it] } })
        }
        journal.close()
        val restored = open()
        assertEquals(upload.digest, restored.uploads(runtime, session).single().intent.digest)
        assertEquals(message.requestId, restored.uploads(runtime, session).single().messageId)
        assertEquals(listOf(fileId), restored.list(runtime, session).single().intent.fileIds())
        val other = CommandOwner(owner.accountId, owner.organizationId, owner.deploymentHash, owner.userId, UUID.randomUUID().toString())
        assertTrue(open(other).uploads(runtime, session).isEmpty())
    }
    @Test fun failedBatchDoesNotPartiallyLinkAnUploadOrCreateAMessage(): Unit = runBlocking {
        val journal = open(); val upload = intent(); val fileId = UUID.randomUUID().toString()
        journal.createUpload(upload); journal.registeredUpload(upload.requestId, fileId)
        val message = CommandIntent.message(UUID.randomUUID().toString(), runtime, session, "queue", "batch", listOf(fileId, UUID.randomUUID().toString()))
        assertThrows(CommandDataException::class.java) { runBlocking { journal.create(message) } }
        assertNull(journal.uploads(runtime, session).single().messageId); assertTrue(journal.list(runtime, session).isEmpty())
        assertThrows(CommandDataException::class.java) { runBlocking { journal.registeredUpload(upload.requestId, UUID.randomUUID().toString()) } }
        assertEquals(fileId, journal.uploads(runtime, session).single().fileId)
        journal.retainUploads(mapOf(runtime to RelayScope(listOf("session.read"), listOf(workspace), emptyList())))
        assertTrue(journal.uploads(runtime, session).isEmpty())
    }
    @Test fun anExplicitUnboundFileRetrySurvivesReopenWithoutInventingAReceipt(): Unit = runBlocking {
        val journal = open(); val upload = intent(); val fileId = UUID.randomUUID().toString()
        journal.createUpload(upload); journal.registeredUpload(upload.requestId, fileId)
        val message = CommandIntent.message(UUID.randomUUID().toString(), runtime, session, "queue", "", listOf(fileId))
        val now = System.currentTimeMillis()
        journal.create(message, now); journal.beginAttempt(message.requestId, now)
        journal.rearmUnboundFiles(message.requestId, now + 1)
        journal.close()
        val restored = open()
        val pending = restored.list(runtime, session).single()
        assertEquals(CommandDelivery.PENDING, pending.delivery); assertNull(pending.remote)
        assertEquals(message.digest, pending.intent.digest); assertEquals(1L, pending.attempts)
        assertThrows(CommandDataException::class.java) { runBlocking { restored.beginAttempt(message.requestId, now + 5002) } }
        restored.rearmUnboundFiles(message.requestId, now + 5003)
        assertEquals(2L, restored.beginAttempt(message.requestId, now + 5004).attempts)
        assertEquals(message.requestId, restored.uploads(runtime, session).single().messageId)
    }
    @Test fun versionFourMigrationPreservesExistingCommandsAndAddsEncryptedUploads(): Unit = runBlocking {
        val journal = open()
        val message = CommandIntent.message(UUID.randomUUID().toString(), runtime, session, "queue", "existing v4 command")
        journal.create(message)
        // Test-only schema fixture: remove the newer file tables to emulate v4. No
        // password or key leaves the existing encrypted Room connection.
        val field = SqlCommandJournal::class.java.getDeclaredField("database").apply { isAccessible = true }
        val database = field.get(journal) as RoomDatabase
        database.openHelper.writableDatabase.execSQL("DROP TABLE file_uploads")
        database.openHelper.writableDatabase.execSQL("DROP TABLE file_exports")
        database.openHelper.writableDatabase.execSQL("PRAGMA user_version=4")
        journal.close()
        val migrated = open()
        assertEquals(message.digest, migrated.list(runtime, session).single().intent.digest)
        val upload = intent(); migrated.createUpload(upload)
        assertEquals(upload.requestId, migrated.uploads(runtime, session).single().intent.requestId)
        migrated.revokeRuntime(runtime); assertTrue(migrated.uploads(runtime, session).isEmpty())
    }
}
