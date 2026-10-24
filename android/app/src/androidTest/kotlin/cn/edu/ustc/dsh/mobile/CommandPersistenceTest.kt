package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.data.SqlCommandJournal
import kotlinx.coroutines.*
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class CommandPersistenceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val account = UUID.randomUUID().toString()
    private val org = "11111111-1111-4111-8111-111111111111"
    private val user = "22222222-2222-4222-8222-222222222222"
    private val device = "33333333-3333-4333-8333-333333333333"
    private val runtime = "44444444-4444-4444-8444-444444444444"
    private val session = "55555555-5555-4555-8555-555555555555"
    private val owner get() = CommandOwner(account, org, "a".repeat(64), user, device)
    private val opened = mutableListOf<SqlCommandJournal>()
    private fun open(value: CommandOwner = owner) = SqlCommandJournal.open(context, value).also { opened += it }
    @Before fun requireFixture() {
        assumeTrue("explicit owned account fixture required", InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        val guard = context.getSystemService(KeyguardManager::class.java)
        assertTrue(guard.isDeviceSecure && !guard.isDeviceLocked)
    }
    @After fun cleanup() { opened.forEach(SqlCommandJournal::close); SqlCommandJournal.eraseAccount(context, account, org) }
    private fun intent(text: String = "ENCRYPTED_OUTBOX_中文🙂_${UUID.randomUUID()}", id: String = UUID.randomUUID().toString()) = CommandIntent.message(id, runtime, session, "queue", text)
    @Test fun encryptedWalAndReopenPreserveTheOriginalUncertainRequestWithoutPlaintextFallback(): Unit = runBlocking {
        val command = intent(); val first = open()
        first.create(command); first.beginAttempt(command.requestId)
        val folder = File(context.noBackupFilesDir, "mobile-data/${owner.scopeHash}/${owner.fingerprint}")
        val marker = command.text()!!.toByteArray(Charsets.UTF_8)
        for (file in folder.walkTopDown().filter { it.isFile }) {
            val bytes = file.readBytes()
            assertFalse("plaintext in ${file.name}", bytes.size >= marker.size && (0..bytes.size - marker.size).any { offset -> marker.indices.all { bytes[offset + it] == marker[it] } })
        }
        assertFalse(File(folder, "commands.db").readBytes().take(16).toByteArray().contentEquals("SQLite format 3\u0000".toByteArray()))
        first.close()
        val restored = open().list(runtime, session).single()
        assertEquals(command.requestId, restored.intent.requestId); assertEquals(command.digest, restored.intent.digest); assertEquals(command.text(), restored.intent.text())
        assertEquals(CommandDelivery.RECONCILE, restored.delivery); assertEquals(1L, restored.attempts)
        assertThrows(CommandDataException::class.java) { runBlocking { opened.last().beginAttempt(command.requestId) } }
    }
    @Test fun concurrentIdenticalIdsProduceOneRowAndChangedBodiesCannotReplaceIt(): Unit = runBlocking {
        val journal = open(); val command = intent()
        coroutineScope { repeat(8) { launch(Dispatchers.IO) { journal.create(command) } } }
        assertEquals(1, journal.list(runtime, session).size)
        assertThrows(CommandDataException::class.java) { runBlocking { journal.create(intent("changed", command.requestId)) } }
        assertEquals(command.digest, journal.list(runtime, session).single().intent.digest)
    }
    @Test fun deploymentDeviceAndSessionScopesDoNotReadEachOthersBodies(): Unit = runBlocking {
        val journal = open(); journal.create(intent())
        val otherDevice = CommandOwner(account, org, owner.deploymentHash, user, UUID.randomUUID().toString())
        val otherDeployment = CommandOwner(account, org, "b".repeat(64), user, device)
        assertTrue(open(otherDevice).list(runtime, session).isEmpty()); assertTrue(open(otherDeployment).list(runtime, session).isEmpty())
        assertTrue(journal.list(runtime, UUID.randomUUID().toString()).isEmpty())
    }
    @Test fun losingTheWrappedKeyDoesNotSilentlyReplaceAnExistingDatabase(): Unit = runBlocking {
        val journal = open(); journal.create(intent()); journal.close()
        val folder = File(context.noBackupFilesDir, "mobile-data/${owner.scopeHash}/${owner.fingerprint}")
        check(File(folder, "key.json").delete())
        assertEquals("data.key_missing", assertThrows(CommandDataException::class.java) { open() }.code)
        assertTrue(File(folder, "commands.db").exists())
    }
    @Test fun logoutCryptographicallyErasesTheAccountAndRevocationClearsOnlyTheAffectedRuntime(): Unit = runBlocking {
        val journal = open(); journal.create(intent())
        val otherRuntime = UUID.randomUUID().toString()
        journal.create(CommandIntent.message(UUID.randomUUID().toString(), otherRuntime, session, "queue", "other"))
        journal.revokeRuntime(runtime)
        assertTrue(journal.list(runtime, session).isEmpty()); assertEquals(1, journal.list(otherRuntime, session).size)
        journal.close(); SqlCommandJournal.eraseAccount(context, account, org)
        assertFalse(File(context.noBackupFilesDir, "mobile-data/${owner.scopeHash}").exists())
        assertTrue(open().list(otherRuntime, session).isEmpty())
    }
}
