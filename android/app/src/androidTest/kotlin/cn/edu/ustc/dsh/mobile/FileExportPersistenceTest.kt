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
import java.time.Instant
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class FileExportPersistenceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val owner = CommandOwner(UUID.randomUUID().toString(), UUID.randomUUID().toString(), "a".repeat(64), UUID.randomUUID().toString(), UUID.randomUUID().toString())
    private val runtime = UUID.randomUUID().toString(); private val session = UUID.randomUUID().toString(); private val workspace = UUID.randomUUID().toString()
    private val opened = mutableListOf<SqlCommandJournal>()
    private fun open(value: CommandOwner = owner) = SqlCommandJournal.open(context, value).also { opened += it }
    private fun intent(origin: ExportOrigin = ExportOrigin.SESSION_ATTACHMENT) = FileExportIntent(UUID.randomUUID().toString(), runtime, session, UUID.randomUUID().toString(), UUID.randomUUID().toString(), workspace, origin, "PRIVATE_EXPORT_资料.txt", 3)
    private fun status(intent: FileExportIntent, file: String = UUID.randomUUID().toString(), digest: String = "a".repeat(64)) = RemoteExportStatus.parse(jsonObject("file_id" to file.json(), "runtime_id" to runtime.json(), "session_id" to session.json(), "direction" to "from_host".json(),
        "name" to intent.name.json(), "size_bytes" to intent.sizeBytes.json(), "sha256" to digest.json(), "state" to "scanning".json(), "created_at" to Instant.now().minusSeconds(1).toString().json(),
        "upload_expires_at" to Instant.now().plusSeconds(60).toString().json(), "expires_at" to Instant.now().plusSeconds(3600).toString().json()))
    @Before fun guard() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        assertTrue(context.getSystemService(KeyguardManager::class.java).let { it.isDeviceSecure && !it.isDeviceLocked })
    }
    @After fun cleanup() { opened.forEach(SqlCommandJournal::close); SqlCommandJournal.eraseAccount(context, owner.accountId, owner.organizationId) }
    @Test fun encryptedExportIntentAndImmutableManifestSurviveReopenAndRemainDeviceScoped(): Unit = runBlocking {
        val journal = open(); val intent = intent(); val file = status(intent)
        journal.createExport(intent); journal.registeredExport(intent.requestId, file)
        val marker = intent.name.toByteArray()
        File(context.noBackupFilesDir, "mobile-data/${owner.scopeHash}/${owner.fingerprint}").walkTopDown().filter(File::isFile).forEach {
            assertFalse(it.readBytes().toString(Charsets.ISO_8859_1).contains(marker.toString(Charsets.ISO_8859_1)))
        }
        journal.close()
        val restored = open(); val saved = restored.exports(runtime, session).single()
        assertEquals(intent.digest, saved.intent.digest); assertEquals(file.id, saved.fileId); assertEquals(file.manifest.sha256, saved.manifest!!.sha256)
        assertThrows(CommandDataException::class.java) { runBlocking { restored.registeredExport(intent.requestId, status(intent, file.id, "b".repeat(64))) } }
        assertThrows(CommandDataException::class.java) { runBlocking { restored.registeredExport(intent.requestId, status(intent)) } }
        assertTrue(open(CommandOwner(owner.accountId, owner.organizationId, owner.deploymentHash, owner.userId, UUID.randomUUID().toString())).exports(runtime, session).isEmpty())
    }
    @Test fun narrowerSessionGrantPurgesWorkspaceExportWithoutLosingSessionAttachment(): Unit = runBlocking {
        val journal = open(); val attachment = intent(); val artifact = intent(ExportOrigin.WORKSPACE_ARTIFACT)
        journal.createExport(attachment); journal.createExport(artifact)
        journal.retainExports(mapOf(runtime to RelayScope(listOf("session.read", "file.download"), emptyList(), listOf(session))))
        assertEquals(listOf(attachment.requestId), journal.exports(runtime, session).map { it.intent.requestId })
        journal.retainExports(mapOf(runtime to RelayScope(listOf("session.read"), emptyList(), listOf(session))))
        assertTrue(journal.exports(runtime, session).isEmpty())
    }
    @Test fun versionFiveMigrationPreservesCommandsUploadsAndAddsExports(): Unit = runBlocking {
        val journal = open(); val message = CommandIntent.message(UUID.randomUUID().toString(), runtime, session, "queue", "existing command")
        val upload = FileUploadIntent(UUID.randomUUID().toString(), runtime, session, workspace, FileManifest("upload.txt", 3, "b".repeat(64)))
        journal.create(message); journal.createUpload(upload)
        val field = SqlCommandJournal::class.java.getDeclaredField("database").apply { isAccessible = true }
        val database = field.get(journal) as RoomDatabase
        database.openHelper.writableDatabase.execSQL("DROP TABLE file_exports")
        database.openHelper.writableDatabase.execSQL("PRAGMA user_version=5")
        journal.close()
        val restored = open()
        assertEquals(message.digest, restored.list(runtime, session).single().intent.digest)
        assertEquals(upload.digest, restored.uploads(runtime, session).single().intent.digest)
        val export = intent(); restored.createExport(export)
        assertEquals(export.digest, restored.exports(runtime, session).single().intent.digest)
        restored.revokeRuntime(runtime); assertTrue(restored.exports(runtime, session).isEmpty())
    }
}
