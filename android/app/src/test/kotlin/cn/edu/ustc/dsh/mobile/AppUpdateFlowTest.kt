package cn.edu.ustc.dsh.mobile

import android.content.Intent
import cn.edu.ustc.dsh.auth.AppUpdateDeployment
import cn.edu.ustc.dsh.network.PrivateApkCandidate
import cn.edu.ustc.dsh.network.RemoteRequestException
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import org.junit.Assert.*
import org.junit.Test
import java.nio.file.Files
import java.util.UUID

class AppUpdateFlowTest {
    private val id = "11111111-1111-4111-8111-111111111111"
    private val hash = "a".repeat(64)
    private val name = "cn.edu.ustc.dsh.mobile"
    private val owner = LocalDataOwner(id, id, hash, id, id)
    private val config = AppUpdateDeployment.parse(JsonDocument.of(jsonObject("v" to 1L.json(), "deployment_sha256" to hash.json(), "package_name" to name.json(),
        "download_origins" to JsonArray(listOf("https://updates.example.invalid".json())))).canonicalBytes(), hash, name)
    private val baseline = AndroidApkVerifier.Installed(name, 1, "b".repeat(64))
    private val bytes = byteArrayOf(1, 2, 3)
    private fun release(revision: String = id) = AppRelease.parse(jsonObject("release_id" to revision.json(), "version_code" to 2L.json(), "version_name" to "fixture".json(),
        "package_name" to name.json(), "sha256" to sha256(bytes).json(), "size_bytes" to bytes.size.toLong().json(), "signing_cert_sha256" to baseline.signingCertificate.json(),
        "download_url" to "https://updates.example.invalid/app.apk".json(), "minimum_protocol_version" to 1L.json(), "maximum_protocol_version" to 1L.json(),
        "minimum_android_api" to 26L.json(), "rollout_basis_points" to 10000L.json(), "release_notes" to "fixture release notes".json()))
    private inner class Fixture : AppUpdateAccess, AutoCloseable {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val directory = Files.createTempDirectory("app-update-flow").toFile()
        val signals = MutableSharedFlow<Unit>(extraBufferCapacity = 16)
        override val changes: Flow<Unit> = signals
        var facts = baseline
        var publication: AppRelease? = release()
        var permission = true
        var stored: StoredAppInstallation? = null
        var session = false
        var promptReady = false
        var installedBytesMatch = false
        var emitPending = true
        var uncertainCommit = false
        var selects = 0; var downloads = 0; var preparations = 0; var commits = 0; var abandons = 0; var cleanups = 0
        var selectBarrier: CompletableDeferred<Unit>? = null
        var downloadBarrier: CompletableDeferred<Unit>? = null
        var verifierFailure: String? = null
        var corrupt = false
        var validActor = true
        private val flows = ArrayList<AppUpdateFlow>()
        fun open(actor: LocalDataOwner = owner, configuration: suspend () -> AppUpdateDeployment? = { config }, clock: () -> Long = System::nanoTime): AppUpdateFlow =
            AppUpdateFlow(actor, configuration, this, scope, { if (!validActor) throw CancellationException() }, dispatcher = Dispatchers.Unconfined, monotonicNanos = clock).also { flows += it }
        override suspend fun installed() = facts
        override fun canInstall() = permission
        override suspend fun read(): StoredAppInstallation? {
            if (corrupt) throw InstallStorageException(InstallStorageFailure.CORRUPT)
            return stored
        }
        override suspend fun hasSessions() = session
        override suspend fun reconcileInstalled(saved: StoredAppInstallation, current: () -> Unit): StoredAppInstallation? {
            current()
            if (!installedBytesMatch || facts.versionCode != saved.record.release.versionCode || facts.signingCertificate != saved.record.release.signingCertificate) return null
            return if (saved.record.phase == AppInstallPhase.INSTALLED) saved else save(saved.record.transition(AppInstallPhase.INSTALLED, 5000))
        }
        override suspend fun select(installed: AndroidApkVerifier.Installed, configuration: AppUpdateDeployment, current: () -> Unit): AppReleaseSelection {
            selects++; selectBarrier?.await(); current()
            return AppReleaseSelection.parse(jsonObject("v" to 1L.json(), "package_name" to name.json(), "protocol_version" to 1L.json(), "current_version_code" to installed.versionCode.json(),
                "current_supported" to JsonBoolean(true), "supported_client_versions" to jsonObject("minimum" to 1L.json(), "maximum" to 100L.json()),
                "release" to (publication?.takeIf { it.versionCode > installed.versionCode }?.document?.root ?: JsonNull)), name, installed.versionCode, 26, configuration.downloadOrigins)
        }
        override suspend fun download(release: AppRelease, configuration: AppUpdateDeployment, current: () -> Unit, progress: (Long) -> Unit): PrivateApkCandidate {
            downloads++
            val candidate = PrivateApkCandidate(directory, release)
            try {
                candidate.output().use { it.write(bytes) }; progress(bytes.size.toLong())
                downloadBarrier?.await(); current(); candidate.seal(current)
                return candidate
            } catch (error: Exception) { candidate.close(); throw error }
        }
        override suspend fun verify(candidate: PrivateApkCandidate, installed: AndroidApkVerifier.Installed, current: () -> Unit) {
            current(); verifierFailure?.let { throw RemoteRequestException(it) }
            assertEquals(baseline, installed)
        }
        override suspend fun prepare(id: String, owner: LocalDataOwner, configuration: AppUpdateDeployment, candidate: PrivateApkCandidate, installed: AndroidApkVerifier.Installed, current: () -> Unit): StoredAppInstallation {
            current(); preparations++; session = true
            return save(AppInstallationRecord.create(id, owner, configuration, installed, candidate.release, 77, "A".repeat(43), 1000).transition(AppInstallPhase.PREPARED, 2000))
        }
        override suspend fun commit(record: AppInstallationRecord, authorize: suspend (AppInstallationRecord) -> Unit, current: () -> Unit) {
            authorize(record); current(); commits++
            save(record.transition(AppInstallPhase.COMMITTING, 3000))
            if (uncertainCommit) throw RemoteRequestException("update.installation_unknown")
            if (emitPending) { promptReady = true; save(stored!!.record.transition(AppInstallPhase.WAITING_USER, 4000)) }
        }
        override suspend fun abandon(record: AppInstallationRecord) { abandons++; session = false; save(record.transition(AppInstallPhase.RETIRED, 6000)) }
        override suspend fun cleanup(current: () -> Unit) { current(); cleanups++; stored = null; session = false; corrupt = false; signals.tryEmit(Unit) }
        override fun prompt(record: AppInstallationRecord): (() -> Intent)? {
            if (!promptReady) return null
            promptReady = false
            return { throw AssertionError("JVM tests must never launch Android system UI") }
        }
        override fun permissionSettings(): () -> Intent = { throw AssertionError("JVM tests must never launch settings") }
        fun save(record: AppInstallationRecord): StoredAppInstallation = StoredAppInstallation((stored?.revision ?: 0) + 1, record).also { stored = it; signals.tryEmit(Unit) }
        fun seed(phase: AppInstallPhase, actor: LocalDataOwner = owner) {
            var record = AppInstallationRecord.create(UUID.randomUUID().toString(), actor, config, baseline, release(), 77, "A".repeat(43), 1000).transition(AppInstallPhase.PREPARED, 2000)
            if (phase in setOf(AppInstallPhase.COMMITTING, AppInstallPhase.WAITING_USER, AppInstallPhase.RESULT_REPORTED)) record = record.transition(AppInstallPhase.COMMITTING, 3000)
            if (phase in setOf(AppInstallPhase.WAITING_USER, AppInstallPhase.RESULT_REPORTED)) record = record.transition(phase, 4000)
            session = true; save(record)
        }
        override fun close() { flows.forEach { it.close() }; scope.cancel(); assertTrue(directory.listFiles()!!.isEmpty()); directory.delete() }
    }
    @Test fun metadataIsRecheckedBeforeDownloadAndAgainBeforeTheOnlyExplicitCommit(): Unit = runBlocking {
        Fixture().use { f ->
            val flow = f.open()
            assertEquals(AppUpdatePhase.AVAILABLE, flow.state.value.phase); assertEquals(1, f.selects)
            flow.download()
            assertEquals(2, f.selects); assertEquals(1, f.downloads); assertEquals(1, f.preparations); assertEquals(0, f.commits)
            assertEquals(AppUpdatePhase.PREPARED, flow.state.value.phase)
            flow.install()
            val event = withTimeout(1000) { flow.events.first() }
            assertEquals(AppUpdateLaunchKind.CONFIRMATION, event.kind)
            assertEquals(1, f.commits); assertTrue(f.selects >= 3)
            assertNotNull(flow.consume(event)); assertNull(flow.consume(event))
            assertEquals(AppUpdatePhase.WAITING_USER, flow.state.value.phase)
        }
    }
    @Test fun aChangedPublicationCannotSilentlySubstituteAnotherDownloadOrCommit(): Unit = runBlocking {
        Fixture().use { f ->
            val flow = f.open(); f.publication = release(UUID.randomUUID().toString()); flow.download()
            assertEquals("update.publication_changed", flow.state.value.error); assertEquals(0, f.downloads); assertEquals(0, f.preparations)
            flow.checkLatest(); flow.download(); assertEquals(AppUpdatePhase.PREPARED, flow.state.value.phase)
            f.publication = null; flow.install()
            assertEquals("update.publication_changed", flow.state.value.error); assertEquals(0, f.commits)
            assertEquals(AppInstallPhase.RETIRED, f.stored!!.record.phase); assertFalse(f.session)
        }
    }
    @Test fun sourcePermissionRequiresAnExplicitSingleUseEventAndNeverStartsADownload(): Unit = runBlocking {
        Fixture().use { f ->
            f.permission = false; val flow = f.open()
            assertFalse(flow.state.value.canInstall); assertEquals(0, f.downloads)
            flow.requestPermission(); val event = withTimeout(1000) { flow.events.first() }
            assertEquals(AppUpdateLaunchKind.PERMISSION, event.kind); assertNotNull(flow.consume(event)); assertNull(flow.consume(event))
            assertEquals(0, f.downloads); assertEquals(0, f.commits)
            flow.close(); assertNull(flow.consume(event))
            f.permission = true; val returned = f.open(); assertTrue(returned.state.value.canInstall)
            assertEquals(0, f.downloads); returned.download(); assertEquals(1, f.downloads)
        }
    }
    @Test fun leavingTheViewCancelsTheDownloadAndRejectsEveryLateResult(): Unit = runBlocking {
        Fixture().use { f ->
            f.downloadBarrier = CompletableDeferred(); val flow = f.open(); flow.download()
            assertEquals(AppUpdatePhase.DOWNLOADING, flow.state.value.phase)
            flow.close(); f.downloadBarrier!!.complete(Unit); yield()
            assertEquals(0, f.preparations); assertEquals(0, f.commits); assertTrue(f.directory.listFiles()!!.isEmpty())
        }
    }
    @Test fun aSignatureGateFailureCannotCreateAnInstallerSession(): Unit = runBlocking {
        Fixture().use { f ->
            val flow = f.open(); f.verifierFailure = "update.apk_invalid"; flow.download()
            assertEquals("update.apk_invalid", flow.state.value.error); assertEquals(0, f.preparations); assertEquals(0, f.commits)
            assertTrue(f.directory.listFiles()!!.isEmpty())
        }
    }
    @Test fun aQueuedLaunchFromARetiredViewCannotBeConsumedByItsReplacement(): Unit = runBlocking {
        Fixture().use { f ->
            val original = f.open(); original.download(); original.install()
            val event = withTimeout(1000) { original.events.first() }; original.close()
            val reopened = f.open()
            assertEquals(AppUpdatePhase.WAITING_USER, reopened.state.value.phase)
            assertNull(original.consume(event)); assertNull(reopened.consume(event)); assertEquals(1, f.commits)
        }
    }
    @Test fun pendingAndUnknownRecordsDoNotAutomaticallyReplayDuringReconstructionOrReadOnlyQueries(): Unit = runBlocking {
        for (phase in listOf(AppInstallPhase.COMMITTING, AppInstallPhase.WAITING_USER, AppInstallPhase.RESULT_REPORTED)) Fixture().use { f ->
            f.seed(phase); val flow = f.open(); flow.checkLatest()
            assertEquals(0, f.commits); assertEquals(0, f.selects); assertEquals(0, f.downloads)
            assertEquals(if (phase == AppInstallPhase.WAITING_USER) AppUpdatePhase.WAITING_USER else AppUpdatePhase.UNKNOWN, flow.state.value.phase)
        }
    }
    @Test fun anUncertainCommitPreservesTheOriginalSessionAndCannotBeRepeatedAsAPoll(): Unit = runBlocking {
        Fixture().use { f ->
            val flow = f.open(); flow.download(); f.uncertainCommit = true; flow.install()
            val session = f.stored!!.record.sessionId
            assertEquals(1, f.commits); assertTrue(f.session); assertEquals(0, f.abandons)
            assertEquals(AppUpdatePhase.UNKNOWN, flow.state.value.phase)
            flow.checkLatest(); flow.install()
            assertEquals(1, f.commits); assertEquals(session, f.stored!!.record.sessionId)
        }
    }
    @Test fun aSuccessHintAndVersionAloneCannotConfirmInstalledBytes(): Unit = runBlocking {
        Fixture().use { f ->
            f.seed(AppInstallPhase.RESULT_REPORTED); val flow = f.open()
            assertEquals(AppUpdatePhase.UNKNOWN, flow.state.value.phase)
            f.facts = baseline.copy(versionCode = 2); flow.checkLatest()
            assertEquals(AppUpdatePhase.UNKNOWN, flow.state.value.phase)
            f.installedBytesMatch = true; flow.checkLatest()
            assertEquals(AppUpdatePhase.INSTALLED, flow.state.value.phase); assertEquals(2L, flow.state.value.installedVersion)
            assertEquals(0, f.commits)
        }
    }
    @Test fun foreignOrUnreadableRecordsHidePublicationDetailsUntilExplicitCleanup(): Unit = runBlocking {
        for (broken in listOf(false, true)) Fixture().use { f ->
            f.seed(AppInstallPhase.WAITING_USER); f.corrupt = broken
            val other = LocalDataOwner(UUID.randomUUID().toString(), id, hash, id, id)
            val flow = f.open(actor = if (broken) owner else other)
            assertEquals(AppUpdatePhase.BLOCKED, flow.state.value.phase); assertNull(flow.state.value.release)
            assertEquals(0, f.selects); assertEquals(0, f.commits); assertTrue(flow.state.value.canCleanup)
            flow.cleanup(); assertEquals(1, f.cleanups); assertEquals(AppUpdatePhase.IDLE, flow.state.value.phase)
        }
    }
    @Test fun absentConfigurationNeverQueriesMetadataOrCreatesAnInstallation(): Unit = runBlocking {
        Fixture().use { f ->
            val flow = f.open(configuration = { null })
            assertEquals(AppUpdatePhase.UNCONFIGURED, flow.state.value.phase); assertEquals(0, f.selects); assertEquals(0, f.downloads)
        }
    }
    @Test fun anImmediateLaunchConsumerAndAFailedLauncherBothLeaveTheViewUsable(): Unit = runBlocking {
        Fixture().use { f ->
            f.permission = false; val flow = f.open()
            val consumer = f.scope.launch { flow.events.collect { assertNotNull(flow.consume(it)) } }
            flow.requestPermission(); assertFalse(flow.state.value.launchPending)
            consumer.cancel()
            flow.requestPermission(); val event = withTimeout(1000) { flow.events.first() }
            flow.launchFailed(event)
            assertFalse(flow.state.value.launchPending); assertEquals("update.system_ui_unavailable", flow.state.value.error)
            flow.requestPermission(); val retry = withTimeout(1000) { flow.events.first() }
            assertNotNull(flow.consume(retry))
        }
    }
    @Test fun aRetiredActorCannotCommitEvenIfItsPreparedViewHasNotYetBeenDisposed(): Unit = runBlocking {
        Fixture().use { f ->
            val flow = f.open(); flow.download(); f.validActor = false; flow.install()
            assertEquals(0, f.commits); assertFalse(f.session); assertEquals(AppInstallPhase.RETIRED, f.stored!!.record.phase)
            assertTrue(f.directory.listFiles()!!.isEmpty())
        }
    }
    @Test fun aLateConsentHintRequiresAnotherUserActionBeforeOpeningTheOriginalPrompt(): Unit = runBlocking {
        Fixture().use { f ->
            var now = 0L
            val flow = f.open(clock = { now }); flow.download(); f.emitPending = false; flow.install()
            now = 31_000_000_000L; f.promptReady = true
            f.save(f.stored!!.record.transition(AppInstallPhase.WAITING_USER, 4000))
            assertEquals(AppUpdatePhase.WAITING_USER, flow.state.value.phase); assertFalse(flow.state.value.launchPending)
            assertNull(withTimeoutOrNull(30) { flow.events.first() })
            flow.install(); val event = withTimeout(1000) { flow.events.first() }
            assertNotNull(flow.consume(event)); assertEquals(1, f.commits)
        }
    }
    @Test fun aButtonForAnOlderPublicationCannotDownloadTheNewlyDisplayedPublication(): Unit = runBlocking {
        Fixture().use { f ->
            val flow = f.open(); val previous = flow.state.value.release!!.document.sha256()
            f.publication = release(UUID.randomUUID().toString()); flow.checkLatest(); flow.download(previous)
            assertEquals("update.publication_changed", flow.state.value.error); assertEquals(0, f.downloads); assertEquals(0, f.preparations)
        }
    }
    @Test fun anInstallButtonForAnotherAttemptCannotCommitTheCurrentAttempt(): Unit = runBlocking {
        Fixture().use { f ->
            f.seed(AppInstallPhase.WAITING_USER); val flow = f.open(); val previous = flow.state.value.attemptId
            val publication = flow.state.value.release!!.document.sha256()
            f.seed(AppInstallPhase.WAITING_USER); val replacement = f.stored!!.record.id
            flow.install(previous, publication)
            assertEquals(0, f.commits); assertEquals(0, f.selects); assertEquals(replacement, f.stored!!.record.id)
        }
    }
    @Test fun cleanupConfirmationCannotBeTransferredToAReplacementAttempt(): Unit = runBlocking {
        Fixture().use { f ->
            f.seed(AppInstallPhase.WAITING_USER); val flow = f.open()
            val previous = flow.state.value.cleanupToken; val previousAttempt = flow.state.value.attemptId
            val publication = flow.state.value.release!!.document.sha256()
            flow.cleanup(previous); flow.checkLatest(); flow.download()
            val replacement = f.stored!!.record.id; val revision = f.stored!!.revision
            flow.cleanup(previous)
            flow.install(previousAttempt, publication)
            assertEquals(1, f.cleanups); assertEquals(0, f.commits); assertEquals(replacement, f.stored!!.record.id); assertEquals(revision, f.stored!!.revision)
            assertEquals(AppInstallPhase.PREPARED, f.stored!!.record.phase); assertTrue(f.session); assertFalse(f.directory.listFiles()!!.isEmpty())
            assertEquals("update.installation_changed", flow.state.value.error)
        }
    }
}
