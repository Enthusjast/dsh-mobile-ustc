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
    @Test fun concurrentFirstOpensPreserveOneDurableWrappedDatabaseKey(): Unit = runBlocking {
        val command = intent(); val start = java.util.concurrent.CountDownLatch(1)
        coroutineScope {
            val jobs = List(4) { async(Dispatchers.IO) {
                start.await()
                SqlCommandJournal.open(context, owner).use { it.create(command) }
            } }
            start.countDown(); jobs.awaitAll()
        }
        SqlCommandJournal.open(context, owner).use { journal ->
            val restored = journal.list(runtime, session).single()
            assertEquals(command.digest, restored.intent.digest); assertEquals(command.text(), restored.intent.text())
        }
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
    @Test fun creationRecoveryPreservesTheWorkspaceIntentAndASeparateSettledSession(): Unit=runBlocking {
        val command=CommandIntent.createSession(UUID.randomUUID().toString(),runtime,session,"standard",UUID.randomUUID().toString())
        val result=UUID.randomUUID().toString();val journal=open()
        journal.create(command);journal.beginAttempt(command.requestId);journal.close()
        val recovered=open();val pending=recovered.listCreations(runtime).single()
        assertNull(pending.intent.sessionId);assertEquals(session,pending.intent.workspaceId);assertEquals(1L,pending.attempts)
        assertEquals(CommandDelivery.RECONCILE,pending.delivery)
        recovered.record(CommandReceipt(command.requestId,result,command.digest,RemoteCommandState.SETTLED,java.time.Instant.now().toString(),workspaceId=session))
        recovered.close()
        val restored=open().listCreations(runtime).single()
        assertEquals(result,restored.createdSessionId);assertNull(restored.intent.sessionId)
        assertArrayEquals(command.storageBytes(),restored.intent.storageBytes());assertFalse(restored.everAgentQueued)
    }
    @Test fun readRevocationPreservesAuthorizedCreationAndAllOperationsShareTheSameRequestNamespace(): Unit=runBlocking {
        val journal=open();val message=intent();journal.create(message)
        val creation=CommandIntent.createSession(UUID.randomUUID().toString(),runtime,session,"standard",UUID.randomUUID().toString())
        journal.create(creation);journal.beginAttempt(creation.requestId)
        assertThrows(CommandDataException::class.java) {runBlocking {journal.create(intent("changed operation",creation.requestId))}}
        journal.revokeSessionCommands(runtime)
        assertTrue(journal.list(runtime,session).isEmpty());assertEquals(creation.requestId,journal.listCreations(runtime).single().intent.requestId)
        journal.retainCreations(mapOf(runtime to cn.edu.ustc.dsh.protocol.RelayScope(listOf("command.status"),listOf(session),emptyList())))
        assertEquals(1,journal.listCreations(runtime).size)
        journal.retainCreations(mapOf(runtime to cn.edu.ustc.dsh.protocol.RelayScope(listOf("command.status"),emptyList(),emptyList())))
        assertTrue(journal.listCreations(runtime).isEmpty())
    }
    @Test fun questionAnswersReopenWithExactTextAndTheirLocalDefinitionWithoutAReplay(): Unit=runBlocking {
        val answers=cn.edu.ustc.dsh.protocol.QuestionAnswers(UUID.randomUUID().toString(),listOf(cn.edu.ustc.dsh.protocol.QuestionAnswer("plan",listOf("继续"),"中文 < & \\ line\n")))
        val command=CommandIntent.answerQuestion(UUID.randomUUID().toString(),runtime,session,UUID.randomUUID().toString(),false,answers,"b".repeat(64))
        val journal=open();journal.create(command);journal.beginAttempt(command.requestId);journal.close()
        val restored=open().list(runtime,session).single()
        assertEquals("b".repeat(64),restored.intent.questionDefinition);assertArrayEquals(command.storageBytes(),restored.intent.storageBytes())
        assertEquals(cn.edu.ustc.dsh.protocol.JsonDocument.of(answers.json()).canonicalText(),cn.edu.ustc.dsh.protocol.JsonDocument.of(cn.edu.ustc.dsh.protocol.QuestionAnswers.parse(restored.intent.payload).json()).canonicalText())
        assertFalse(restored.intent.frame().fields.containsKey("local_context_sha256"));assertEquals(CommandDelivery.RECONCILE,restored.delivery)
        assertThrows(CommandDataException::class.java) {runBlocking {opened.last().beginAttempt(command.requestId)}}
    }
    @Test fun aQuestionCannotBePersistedWithoutContextOrReplaceItsContextUnderTheSameId(): Unit=runBlocking {
        val answers=cn.edu.ustc.dsh.protocol.QuestionAnswers(UUID.randomUUID().toString(),listOf(cn.edu.ustc.dsh.protocol.QuestionAnswer("x",emptyList(),"answer")))
        val command=CommandIntent.answerQuestion(UUID.randomUUID().toString(),runtime,session,UUID.randomUUID().toString(),true,answers,"b".repeat(64))
        val journal=open()
        assertEquals("question.context_required",assertThrows(CommandDataException::class.java) {runBlocking {journal.create(CommandIntent.parse(command.frame()))}}.code)
        journal.create(command)
        val changed=CommandIntent.answerQuestion(command.requestId,runtime,session,command.epoch!!,true,answers,"c".repeat(64))
        assertEquals(command.digest,changed.digest)
        assertThrows(CommandDataException::class.java) {runBlocking {journal.create(changed)}}
        assertEquals(command.questionDefinition,journal.list(runtime,session).single().intent.questionDefinition)
    }
}
