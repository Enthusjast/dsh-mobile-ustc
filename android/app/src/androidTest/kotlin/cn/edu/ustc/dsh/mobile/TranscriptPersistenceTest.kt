package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.data.SqlCommandJournal
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import kotlinx.coroutines.runBlocking
import org.junit.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class TranscriptPersistenceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val account = UUID.randomUUID().toString()
    private val org = "11111111-1111-4111-8111-111111111111"
    private val runtime = "44444444-4444-4444-8444-444444444444"
    private val session = "55555555-5555-4555-8555-555555555555"
    private val epoch = "66666666-6666-4666-8666-666666666666"
    private val owner = LocalDataOwner(account, org, "a".repeat(64), "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333")
    private val opened = mutableListOf<SqlCommandJournal>()
    private fun open() = SqlCommandJournal.open(context, owner).also(opened::add)
    @Before fun requireFixture() {
        assumeTrue("explicit owned account fixture required", InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        val guard = context.getSystemService(KeyguardManager::class.java)
        assertTrue(guard.isDeviceSecure && !guard.isDeviceLocked)
    }
    @After fun cleanup() { opened.forEach { it.close() }; SqlCommandJournal.eraseAccount(context, account, org) }
    private fun window(text: String? = "缓存正文") = SessionWindow(epoch).apply {
        val records = text?.let {
            val content = JsonArray(listOf(jsonObject("type" to "text".json(), "text" to it.json())))
            listOf(jsonObject("native_seq" to 0L.json(), "time" to 1000L.json(), "type" to "user/message".json(), "data" to jsonObject("content" to content)))
        } ?: emptyList()
        accept(SessionContent("session.snapshot", epoch, epoch, jsonObject("cursor" to (if (text == null) -1L else 0L).json(), "has_more" to JsonBoolean(false), "records" to JsonArray(records), "assistant" to JsonNull)))
    }
    private fun durable(text: String? = "缓存正文") = window(text).apply {
        accept(SessionContent("session.checkpoint", epoch, epoch, jsonObject("state" to "persisted".json(), "through_seq" to (if (text == null) -1L else 0L).json())))
    }.snapshot(durableOnly = true)
    @Test fun cachedUnicodeIsEncryptedInTheDatabaseAndWalAndSurvivesReopen(): Unit = runBlocking {
        val text = "CACHED_HISTORY_SECRET_中文🙂_${UUID.randomUUID()}"
        val journal = open(); journal.saveTranscript(runtime, session, null, epoch, durable(text))
        val marker = text.toByteArray(Charsets.UTF_8)
        val folder = File(context.noBackupFilesDir, "mobile-data/${owner.scopeHash}/${owner.fingerprint}")
        for (file in folder.walkTopDown().filter { it.isFile }) {
            val bytes = file.readBytes()
            assertFalse("plaintext in ${file.name}", bytes.size >= marker.size && (0..bytes.size - marker.size).any { offset -> marker.indices.all { bytes[offset + it] == marker[it] } })
        }
        journal.close()
        val restored = open().loadTranscript(runtime, session, null)!!
        assertEquals(text, restored.transcript.items.single().blocks.single().text)
        assertEquals(epoch, restored.epoch); assertFalse(restored.transcript.taskRunning)
    }
    @Test fun expiryAndClockRollbackRemoveHistoryWithoutDiscardingUnknownCommands(): Unit = runBlocking {
        val journal = open()
        val command = CommandIntent.message(UUID.randomUUID().toString(), runtime, session, "queue", "unresolved")
        journal.create(command); journal.beginAttempt(command.requestId)
        journal.saveTranscript(runtime, session, null, epoch, durable(), System.currentTimeMillis() - SqlCommandJournal.CACHE_RETENTION_MILLIS - 1000)
        assertNull(journal.loadTranscript(runtime, session, null))
        journal.saveTranscript(runtime, session, null, epoch, durable(), System.currentTimeMillis() + 60_000)
        assertNull(journal.loadTranscript(runtime, session, null))
        assertEquals(CommandDelivery.RECONCILE, journal.list(runtime, session).single().delivery)
    }
    @Test fun currentScopePrunesUnlistedRuntimesAndDisallowedSessionsAndWorkspaceChanges(): Unit = runBlocking {
        val journal = open(); val workspace = UUID.randomUUID().toString()
        val second = UUID.randomUUID().toString(); val denied = UUID.randomUUID().toString(); val sibling = UUID.randomUUID().toString()
        journal.saveTranscript(runtime, session, null, epoch, durable())
        journal.saveTranscript(runtime, second, workspace, epoch, durable())
        journal.saveTranscript(runtime, denied, null, epoch, durable())
        journal.saveTranscript(sibling, session, null, epoch, durable())
        journal.retainTranscripts(mapOf(runtime to RelayScope(listOf("session.read"), listOf(workspace), listOf(session))))
        assertNotNull(journal.loadTranscript(runtime, session, null)); assertNotNull(journal.loadTranscript(runtime, second, workspace))
        assertNull(journal.loadTranscript(runtime, denied, null)); assertNull(journal.loadTranscript(sibling, session, null))
        assertNull(journal.loadTranscript(runtime, second, UUID.randomUUID().toString()))
        assertNull(journal.loadTranscript(runtime, second, workspace))
        journal.revokeRuntime(runtime); assertNull(journal.loadTranscript(runtime, session, null))
    }
    @Test fun observationAndUnconfirmedEmptySnapshotsCannotBecomeOfflineHistory(): Unit = runBlocking {
        val journal = open()
        for (unproved in listOf(window().snapshot(), window().snapshot(durableOnly = true), window(null).snapshot(durableOnly = true))) {
            assertEquals("data.unconfirmed_history", assertThrows(CommandDataException::class.java) { runBlocking { journal.saveTranscript(runtime, session, null, epoch, unproved) } }.code)
        }
        journal.saveTranscript(runtime, session, null, epoch, durable(null))
        assertTrue(journal.loadTranscript(runtime, session, null)!!.transcript.items.isEmpty())
    }
    @Test fun historyCapacityEvictsTheLeastRecentlyUsedSessionAndPreservesUnresolvedIntent(): Unit = runBlocking {
        val journal = open(); val ids = List(SqlCommandJournal.CACHE_SESSIONS + 1) { UUID.randomUUID().toString() }
        val now = System.currentTimeMillis() - 100_000
        val command = CommandIntent.message(UUID.randomUUID().toString(), runtime, session, "queue", "keep original")
        journal.create(command); journal.beginAttempt(command.requestId)
        for (i in 0 until SqlCommandJournal.CACHE_SESSIONS) journal.saveTranscript(runtime, ids[i], null, epoch, durable(null), now + i)
        assertNotNull(journal.loadTranscript(runtime, ids.first(), null))
        journal.saveTranscript(runtime, ids.last(), null, epoch, durable(null), now + ids.size)
        assertNotNull(journal.loadTranscript(runtime, ids.first(), null)); assertNull(journal.loadTranscript(runtime, ids[1], null))
        assertNotNull(journal.loadTranscript(runtime, ids.last(), null)); assertEquals(1L, journal.list(runtime, session).single().attempts)
    }
}
