package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import android.provider.DocumentsContract
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.network.SessionReadPhase
import org.junit.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FileExportSelectionTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private var fixture: AccountFixture? = null
    private var controller: LoginController? = null
    private fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
    private fun await(check: () -> Boolean) {
        val stop = android.os.SystemClock.elapsedRealtime() + 45_000
        while (android.os.SystemClock.elapsedRealtime() < stop) {
            fixture!!.failure.get()?.let { throw AssertionError(it) }
            if (check()) return
            Thread.sleep(25)
        }
        throw AssertionError("APK export selection fixture timed out")
    }
    private fun destination() = context.contentResolver.call(FixtureDocumentProvider.URI, "createExport", "normal", null)!!.getParcelable<android.net.Uri>("uri")!!
    private fun exists(uri: android.net.Uri) = runCatching { context.contentResolver.query(uri, arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID), null, null, null)?.use { it.moveToFirst() } == true }.getOrDefault(false)
    @Before fun setup() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        assertTrue(context.getSystemService(KeyguardManager::class.java).let { it.isDeviceSecure && !it.isDeviceLocked })
        fixture = AccountFixture(context).also { it.exportMode = true; it.seed() }
        main { controller = LoginController(context, fixture!!.http, fixture!!.environment()); controller!!.foreground(true) }
        await { controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing && it.runtimes.isNotEmpty() } }
        main { controller!!.openRuntime(fixture!!.runtimeId) }
        await { controller!!.state.value.let { !it.loadingSessions && it.sessions.isNotEmpty() } }
        main { controller!!.openSession(fixture!!.sessionId) }
        await { controller!!.state.value.let { it.reader?.phase == SessionReadPhase.READY && it.exports?.connected == true } }
        main { controller!!.browseExports() }
        await { controller!!.state.value.exports?.page != null }
        val source = controller!!.state.value.exports!!.page!!.items.single()
        main { controller!!.requestExport(source) }
        await { controller!!.state.value.exports?.rows?.singleOrNull()?.status?.downloadable() == true }
    }
    @After fun cleanup() {
        main { controller?.close() }; fixture?.close()
        context.contentResolver.call(FixtureDocumentProvider.URI, "resetExports", null, null)
    }
    @Test fun pickerReopenSavesThroughAuthenticatedTlsAndRealProviderWithoutReadmission() {
        val owner = controller!!; val original = owner.state.value.exports!!.rows.single().stored.intent.requestId
        val uri = destination()
        main { owner.chooseExportDestination(original) }
        val token = owner.state.value.exportSavePicker!!.id
        main { owner.foreground(false); owner.exportDestinationPicked(token, uri); owner.foreground(true) }
        await { owner.state.value.exportSaved }
        assertArrayEquals(fixture!!.exportBytes, context.contentResolver.openInputStream(uri)!!.use { it.readBytes() })
        assertEquals(1, fixture!!.exportSelections.get()); assertEquals(1, fixture!!.exportDownloads.get())
        assertEquals(original, owner.state.value.exports!!.rows.single().stored.intent.requestId)
        // A duplicate Activity Result must not delete an already saved document.
        main { owner.exportDestinationPicked(token, uri) }; assertTrue(exists(uri))
        main { owner.foreground(false); owner.foreground(true) }
        await { owner.state.value.exports?.rows?.singleOrNull()?.stored?.intent?.requestId == original }
        assertEquals(1, fixture!!.exportSelections.get()); assertEquals(1, fixture!!.exportDownloads.get())
    }
    @Test fun lateDestinationAfterExitIsCleanedWithoutOpeningANewAccountDownload() {
        val owner = controller!!; val original = owner.state.value.exports!!.rows.single().stored.intent.requestId
        main { owner.chooseExportDestination(original) }; val token = owner.state.value.exportSavePicker!!.id
        main { owner.cancel() }; await { owner.state.value.phase == HomePhase.SIGNED_OUT }
        val uri = destination()
        main { owner.exportDestinationPicked(token, uri) }
        await { !exists(uri) }; assertEquals(0, fixture!!.exportDownloads.get())
        assertNull(owner.state.value.exports); assertNull(owner.state.value.exportSavePicker)
    }
    @Test fun backgroundDuringDownloadCancelsAndRemovesTheTargetDocument() {
        val owner = controller!!; val original = owner.state.value.exports!!.rows.single().stored.intent.requestId
        fixture!!.exportSlow = true; val uri = destination()
        main { owner.chooseExportDestination(original) }; val token = owner.state.value.exportSavePicker!!.id
        main { owner.exportDestinationPicked(token, uri) }
        await { fixture!!.exportDownloads.get() == 1 }
        main { owner.foreground(false) }
        await { !exists(uri) }
        assertFalse(owner.state.value.exportSaved); assertEquals(1, fixture!!.exportSelections.get())
    }
}
