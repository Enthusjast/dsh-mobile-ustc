package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.network.SessionReadPhase
import cn.edu.ustc.dsh.data.SqlCommandJournal
import cn.edu.ustc.dsh.protocol.LocalDataOwner
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AccountSessionTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private var fixture: AccountFixture? = null
    private var controller: LoginController? = null
    private fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
    @Before fun setup() {
        assumeTrue("explicit account fixture required", InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        val context = instrumentation.targetContext
        val guard = context.getSystemService(KeyguardManager::class.java)
        assertTrue("secure unlocked fixture required", guard.isDeviceSecure && !guard.isDeviceLocked)
        fixture = AccountFixture(context).also { it.seed() }
        main { controller = LoginController(context, fixture!!.http, fixture!!.environment()); controller!!.foreground(true) }
        until("authorized directory") { controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing && it.runtimes.size == 1 } }
    }
    @After fun cleanup() { main { controller?.close() }; fixture?.close() }
    private fun until(label: String, condition: () -> Boolean) {
        val deadline = android.os.SystemClock.elapsedRealtime() + 30_000
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            fixture!!.failure.get()?.let { throw AssertionError(it) }
            if (condition()) return
            Thread.sleep(25)
        }
        throw AssertionError("Timed out: $label; phase=${controller?.state?.value?.phase}; read=${controller?.state?.value?.reader?.phase}")
    }
    private fun openDirectory() {
        main { controller!!.openRuntime(fixture!!.runtimeId) }
        until("session directory") { controller!!.state.value.let { !it.loadingSessions && it.sessions.size == 1 } }
    }
    private fun openRead() {
        openDirectory(); main { controller!!.openSession(fixture!!.sessionId) }
        until("confirmed session snapshot") { controller!!.state.value.reader?.let { it.phase == SessionReadPhase.READY && it.window?.persistedThrough == 2L } == true }
    }
    private fun cachedHistory() = fixture!!.let { test ->
        val saved = test.checkpoint()!!
        val owner = LocalDataOwner(saved.accountId, saved.organizationId, saved.session.deploymentFingerprint, saved.userId, saved.deviceId!!)
        SqlCommandJournal.open(instrumentation.targetContext, owner).use { database -> runBlocking { database.loadTranscript(test.runtimeId, test.sessionId, null) } }
    }

    @Test fun confirmedHistorySurvivesControllerRecreationAndHostOfflineAfterFreshAuthorization() {
        val test = fixture!!; openRead()
        until("history transaction committed") { cachedHistory()?.transcript?.items?.size == 1 }
        main { controller!!.close(); controller = null }
        test.runtimeOffline = true
        val tickets = test.ticketRequests.get()
        main { controller = LoginController(instrumentation.targetContext, test.http, test.environment()); controller!!.foreground(true) }
        until("revalidated account and directory") { controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing && it.runtimes.size == 1 } }
        openDirectory(); main { controller!!.openSession(test.sessionId) }
        until("host offline with encrypted history") { controller!!.state.value.reader?.let { it.phase == SessionReadPhase.OFFLINE && it.window != null } == true }
        val restored = controller!!.state.value.reader!!.window!!
        assertEquals("电脑当前消息", restored.items.single().blocks.single().text)
        assertFalse(restored.taskRunning); assertFalse(restored.items.any { it.live }); assertTrue(test.ticketRequests.get() > tickets)
        test.revokeSession()
        until("offline host view revoked through the live control connection") { controller!!.state.value.let { !it.refreshing && it.selectedSessionId == null && it.runtimes.single().access?.grantVersion == 8L } }
        assertNull(cachedHistory())
    }

    @Test fun authoritativeReadRemovalErasesPersistedHistoryAndRetiresItsWriter() {
        val owner = controller!!; val test = fixture!!; openRead()
        until("history before revoke") { cachedHistory() != null }
        test.allowSessionRead = false; main { owner.refresh() }
        until("scope removal applied") { owner.state.value.let { !it.refreshing && it.selectedSessionId == null && it.runtimes.single().access?.grantVersion == 8L } }
        assertNull(cachedHistory()); assertNull(owner.state.value.reader); assertNotNull(test.checkpoint())
    }

    @Test fun platformKeyReadPagesAndReopensWithAFreshSubscriptionAcrossForegroundChanges() {
        val owner = controller!!; val test = fixture!!
        openRead()
        assertEquals("电脑当前消息", owner.state.value.reader!!.window!!.items.single().blocks.single().text)
        main { owner.loadOlder() }
        until("fixed history page") { owner.state.value.reader?.window?.hasMore == false }
        assertEquals(listOf("最早的消息", "更早的消息", "电脑当前消息"), owner.state.value.reader!!.window!!.items.map { it.blocks.single().text })
        main { owner.foreground(false) }
        assertNull(owner.state.value.reader?.window)
        until("background transport closed") { test.relayClosures.get() >= 1 }
        main { owner.foreground(true) }
        until("fresh foreground snapshot") { test.subscriptions.get() == 2 && owner.state.value.reader?.phase == SessionReadPhase.READY }
        assertEquals(2, test.ticketRequests.get()); assertEquals(1, owner.state.value.reader!!.window!!.items.size)
        main { owner.cancel() }
        until("local logout") { owner.state.value.phase == HomePhase.SIGNED_OUT }
        assertNull(owner.state.value.reader); assertTrue(owner.state.value.sessions.isEmpty()); assertNull(test.vault.read())
    }

    @Test fun aLateSessionDirectoryCannotRestoreBodyOrSelectionAfterLogout() {
        val owner = controller!!; val test = fixture!!; test.holdSessions = true
        main { owner.openRuntime(test.runtimeId) }
        until("delayed directory request") { test.sessionRequests.get() == 1 }
        main { owner.cancel() }
        until("logged out") { owner.state.value.phase == HomePhase.SIGNED_OUT }
        Thread.sleep(2300)
        assertNull(owner.state.value.selectedRuntimeId); assertNull(owner.state.value.reader); assertTrue(owner.state.value.sessions.isEmpty())
        assertEquals(0, test.ticketRequests.get())
    }

    @Test fun listPermissionNeverBecomesReadPermissionAndNarrowerDirectoryRetiresTheConnection() {
        val owner = controller!!; val test = fixture!!
        openRead(); test.allowSessionRead = false
        main { owner.refresh() }
        until("narrower directory applied") { owner.state.value.let { !it.refreshing && !it.loadingSessions && it.selectedSessionId == null && it.runtimes.single().access?.grantVersion == 8L } }
        assertNull(owner.state.value.reader)
        val acceptedBefore = test.ticketRequests.get()
        main { owner.openSession(test.sessionId) }
        assertNull(owner.state.value.selectedSessionId); assertEquals(acceptedBefore, test.ticketRequests.get())
        assertEquals(HomePhase.READY, owner.state.value.phase); assertNotNull(test.checkpoint())
    }

    @Test fun sessionRevocationClearsTheReadViewAndRetainsAnOtherwiseAuthorizedAccount() {
        val owner = controller!!; val test = fixture!!
        openRead(); test.revokeSession()
        until("revoked body cleared and current grant reconciled") { owner.state.value.let { !it.refreshing && !it.loadingSessions && it.selectedSessionId == null && it.runtimes.single().access?.grantVersion == 8L } }
        assertNull(owner.state.value.reader); assertEquals(HomePhase.READY, owner.state.value.phase)
        assertNotNull(test.checkpoint()); assertEquals(1, test.ticketRequests.get())
    }
}
