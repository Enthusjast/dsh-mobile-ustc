package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.network.SessionReadPhase
import cn.edu.ustc.dsh.network.UploadPhase
import cn.edu.ustc.dsh.command.RemoteCommandState
import cn.edu.ustc.dsh.protocol.sha256
import org.junit.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class FileSelectionTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private var fixture: AccountFixture? = null
    private var controller: LoginController? = null
    private fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
    @Before fun setup() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        val context = instrumentation.targetContext
        val guard = context.getSystemService(KeyguardManager::class.java)
        assertTrue(guard.isDeviceSecure && !guard.isDeviceLocked)
        fixture = AccountFixture(context).also { it.chatMode = true; it.fileMode = true; it.seed() }
        main { controller = LoginController(context, fixture!!.http, fixture!!.environment()); controller!!.foreground(true) }
        await { controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing && it.runtimes.isNotEmpty() } }
        main { controller!!.openRuntime(fixture!!.runtimeId) }
        await { controller!!.state.value.let { !it.loadingSessions && it.sessions.isNotEmpty() } }
        main { controller!!.openSession(fixture!!.sessionId) }
        await { controller!!.state.value.let { it.reader?.phase == SessionReadPhase.READY && it.uploads != null } }
    }
    @After fun cleanup() { main { controller?.close() }; fixture?.close() }
    private fun await(check: () -> Boolean) {
        val deadline = android.os.SystemClock.elapsedRealtime() + 45_000
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            fixture!!.failure.get()?.let { throw AssertionError(it) }
            if (check()) return
            Thread.sleep(25)
        }
        throw AssertionError("file selection fixture timed out")
    }
    @Test fun pickerCancellationRestoresOnlyTheOriginalDraftAcrossForegroundReopen() {
        val owner = controller!!
        main { owner.pickFixtureDocument(null, "PICKER_PRIVATE_DRAFT", "steer") }
        val token = owner.state.value.documentPicker!!.id
        main { owner.documentPicked(UUID.randomUUID().toString(), null) }
        assertEquals(token, owner.state.value.documentPicker!!.id)
        main { owner.foreground(false); owner.documentPicked(token, null); owner.foreground(true) }
        await { owner.state.value.let { it.reader?.phase == SessionReadPhase.READY && it.uploads != null } }
        assertNull(owner.state.value.documentPicker)
        assertEquals("PICKER_PRIVATE_DRAFT", owner.state.value.composer!!.value.text)
        assertEquals("steer", owner.state.value.composer!!.mode)
        assertTrue(owner.state.value.uploads!!.rows.isEmpty()); assertEquals(0, fixture!!.commandWrites.get())
        main { owner.back() }
        assertNull(owner.state.value.composer)
    }
    @Test fun aPickerCancellationCannotRestoreItsSnapshotOverANewerEdit() {
        val owner = controller!!
        main { owner.pickFixtureDocument(null, "picker snapshot", "queue") }
        val token = owner.state.value.documentPicker!!.id
        main {
            owner.editFixtureComposer("newer foreground edit", "steer")
            owner.documentPicked(token, null)
        }
        assertNull(owner.state.value.documentPicker)
        assertEquals("newer foreground edit", owner.state.value.composer!!.value.text)
        assertEquals("steer", owner.state.value.composer!!.mode)
        assertTrue(owner.state.value.uploads!!.rows.isEmpty())
        assertEquals(0, fixture!!.commandWrites.get())
    }
    @Test fun aProviderResultUploadsAnonymouslyAndLinksAFileOnlyMessageAcrossReopen() {
        val owner = controller!!; val server = fixture!!
        main { owner.pickFixtureDocument(null, "", "queue") }
        val token = owner.state.value.documentPicker!!.id
        main { owner.foreground(false); owner.documentPicked(token, FixtureDocumentProvider.URI); owner.foreground(true) }
        await { owner.state.value.uploads?.let { !it.busy && it.rows.singleOrNull()?.phase == UploadPhase.SCANNING } == true }
        val original = owner.state.value.uploads!!.rows.single().stored
        assertEquals(FixtureDocumentProvider.NAME, original.intent.manifest.name)
        assertEquals(sha256(FixtureDocumentProvider.BYTES), original.intent.manifest.sha256)
        assertEquals(1, server.fileRegistrations.get()); assertEquals(1, server.filePuts.get())
        server.fileState = "clean"
        await { owner.state.value.uploads?.rows?.singleOrNull()?.phase == UploadPhase.WAITING }
        main { owner.toggleUpload(original.intent.requestId) }
        assertTrue(owner.state.value.uploads!!.selected.isEmpty())
        server.fileReady = true
        await { owner.state.value.uploads?.rows?.singleOrNull()?.ready() == true && owner.state.value.outbox?.connected == true }
        main { owner.toggleUpload(original.intent.requestId); owner.submitFixtureMessage("queue", "") }
        await { owner.state.value.outbox?.records?.singleOrNull()?.remote == RemoteCommandState.AGENT_QUEUED }
        val message = server.fileMessage.get()!!
        assertEquals(listOf(original.fileId), message.fileIds())
        assertEquals(1, message.payload.array("content").size)
        main { owner.foreground(false); owner.foreground(true) }
        await { owner.state.value.uploads?.rows?.singleOrNull()?.stored?.messageId == message.requestId }
        assertEquals(original.intent.requestId, owner.state.value.uploads!!.rows.single().stored.intent.requestId)
        assertTrue(owner.state.value.uploads!!.selected.isEmpty())
        assertEquals(1, server.filePuts.get()); assertEquals(1, server.commandWrites.get())
    }
    @Test fun aLatePickerResultAfterLocalExitCannotOpenAnyNewUploadContext() {
        val owner = controller!!
        main { owner.pickFixtureDocument(null, "old context", "queue") }
        val token = owner.state.value.documentPicker!!.id
        main { owner.cancel() }
        await { owner.state.value.phase == HomePhase.SIGNED_OUT }
        main { owner.documentPicked(token, Uri.parse("content://must-not-open/late")) }
        assertEquals(HomePhase.SIGNED_OUT, owner.state.value.phase)
        assertNull(owner.state.value.uploads); assertNull(owner.state.value.documentPicker); assertNull(owner.state.value.composer)
        assertNull(owner.state.value.presentationOwner)
    }
}
