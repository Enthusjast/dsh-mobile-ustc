package cn.edu.ustc.dsh.mobile

import android.content.Intent
import cn.edu.ustc.dsh.auth.AppUpdateDeployment
import cn.edu.ustc.dsh.network.PrivateApkCandidate
import cn.edu.ustc.dsh.network.RemoteRequestException
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import java.util.UUID

enum class AppUpdatePhase { LOADING, UNCONFIGURED, IDLE, CHECKING, CURRENT, AVAILABLE, DOWNLOADING, VERIFYING, PREPARED, REPREPARE, WAITING_USER, UNKNOWN, INSTALLED, FAILED, BLOCKED, ERROR }
data class AppUpdateUiState(
    val viewId: String = "", val phase: AppUpdatePhase = AppUpdatePhase.LOADING, val busy: Boolean = false,
    val installedVersion: Long? = null, val release: AppRelease? = null, val currentSupported: Boolean? = null,
    val downloadedBytes: Long = 0, val canInstall: Boolean = false, val canCleanup: Boolean = false,
    val launchPending: Boolean = false, val error: String? = null,
    val attemptId: String? = null, val cleanupToken: String? = null,
)
enum class AppUpdateLaunchKind { PERMISSION, CONFIRMATION }
class AppUpdateLaunch internal constructor(internal val viewId: String, val kind: AppUpdateLaunchKind, internal val intent: () -> Intent) {
    override fun toString() = "AppUpdateLaunch($kind)"
}

/** Narrow platform boundary: the coordinator never gains a generic package installer or arbitrary URL API. */
internal interface AppUpdateAccess {
    val changes: Flow<Unit>
    suspend fun installed(): AndroidApkVerifier.Installed
    fun canInstall(): Boolean
    suspend fun read(): StoredAppInstallation?
    suspend fun hasSessions(): Boolean
    suspend fun reconcileInstalled(saved: StoredAppInstallation, current: () -> Unit): StoredAppInstallation?
    suspend fun select(installed: AndroidApkVerifier.Installed, configuration: AppUpdateDeployment, current: () -> Unit): AppReleaseSelection
    suspend fun download(release: AppRelease, configuration: AppUpdateDeployment, current: () -> Unit, progress: (Long) -> Unit): PrivateApkCandidate
    suspend fun verify(candidate: PrivateApkCandidate, installed: AndroidApkVerifier.Installed, current: () -> Unit)
    suspend fun prepare(id: String, owner: LocalDataOwner, configuration: AppUpdateDeployment, candidate: PrivateApkCandidate, installed: AndroidApkVerifier.Installed, current: () -> Unit): StoredAppInstallation
    suspend fun commit(record: AppInstallationRecord, authorize: suspend (AppInstallationRecord) -> Unit, current: () -> Unit)
    suspend fun abandon(record: AppInstallationRecord)
    suspend fun cleanup(current: () -> Unit)
    fun prompt(record: AppInstallationRecord): (() -> Intent)?
    fun permissionSettings(): () -> Intent
}

/** One foreground account/view. Installer hints trigger reads; only explicit actions arm system UI. */
internal class AppUpdateFlow(
    private val owner: LocalDataOwner, private val loadConfiguration: suspend () -> AppUpdateDeployment?,
    private val access: AppUpdateAccess, parent: CoroutineScope, private val current: () -> Unit,
    private val authorityFailure: (String) -> Unit = {}, dispatcher: CoroutineDispatcher = Dispatchers.Main.immediate,
    private val monotonicNanos: () -> Long = System::nanoTime,
    private val diagnosticFailure: ((Exception) -> Unit)? = null,
) : AutoCloseable {
    private val scope = CoroutineScope(SupervisorJob(parent.coroutineContext[Job]) + dispatcher)
    private val id = UUID.randomUUID().toString()
    private val mutable = MutableStateFlow(AppUpdateUiState(viewId = id))
    val state = mutable.asStateFlow()
    private val launches = Channel<AppUpdateLaunch>(1)
    val events = launches.receiveAsFlow()
    private var liveLaunch: AppUpdateLaunch? = null
    private var configuration: AppUpdateDeployment? = null
    private var configurationInvalid = false
    private var publicationChecked = false
    private var action: Job? = null
    private var candidate: PrivateApkCandidate? = null
    private var unsubmittedId: String? = null
    private var saved: StoredAppInstallation? = null
    private var signalPending = false
    private var closed = false
    private class Armed(val recordId: String, val at: Long)
    private class StaleAction(val code: String) : IllegalStateException(code)
    private var armed: Armed? = null
    init {
        scope.launch { access.changes.collect { if (action?.isActive == true) signalPending = true else perform(clearError = false) {} } }
        perform(reconcileAfter = false) {
            try { configuration = loadConfiguration() }
            catch (_: ProtocolException) { configurationInvalid = true }
            reconcile()
            if (configuration != null && saved == null && mutable.value.phase != AppUpdatePhase.BLOCKED) { select(); reconcile() }
        }
    }
    private fun check() { current(); if (closed || !scope.isActive) throw CancellationException() }
    private fun config() = configuration ?: fail("update.not_configured")
    private fun dropCandidate() { candidate?.close(); candidate = null }
    private fun owned(record: AppInstallationRecord) = configuration?.let { record.belongsTo(owner, it) } == true
    private fun perform(reconcileAfter: Boolean = true, clearError: Boolean = true, block: suspend () -> Unit) {
        if (closed || !scope.isActive || action?.isActive == true || liveLaunch != null) return
        mutable.update { it.copy(busy = true, error = if (clearError) null else it.error) }
        val next = scope.launch(start = CoroutineStart.LAZY) {
            try { check(); block(); check(); if (reconcileAfter) reconcile() }
            catch (error: CancellationException) {
                armed = null; dropCandidate()
                withContext(NonCancellable) { retireUnsubmitted() }
                throw error
            }
            catch (error: Exception) {
                diagnosticFailure?.let { runCatching { it(error) } }
                val stale = error is StaleAction
                if (!stale) {
                    armed = null; dropCandidate()
                    withContext(NonCancellable) { retireUnsubmitted() }
                }
                if (!closed && scope.isActive) {
                    val code = code(error)
                    try { reconcile() } catch (_: Exception) { mutable.update { it.copy(phase = AppUpdatePhase.ERROR) } }
                    mutable.update { it.copy(error = code, phase = if (stale || saved?.record?.phase?.terminal == false) it.phase else AppUpdatePhase.ERROR) }
                    if (code in AUTHORITY_ERRORS) authorityFailure(code)
                }
            } finally {
                if (!closed && scope.isActive) {
                    action = null
                    mutable.update { it.copy(busy = false) }
                    if (signalPending) { signalPending = false; perform(clearError = false) {} }
                }
            }
        }
        action = next; next.start()
    }
    private suspend fun retireUnsubmitted() {
        val original = unsubmittedId ?: return
        val record = runCatching { access.read()?.record }.getOrNull()
        if (record?.id == original && record.phase in setOf(AppInstallPhase.PREPARING, AppInstallPhase.PREPARED)) runCatching { access.abandon(record) }
        unsubmittedId = null
    }
    private suspend fun reconcile() {
        check()
        val installed = access.installed(); check()
        mutable.update { it.copy(installedVersion = installed.versionCode, canInstall = access.canInstall()) }
        val record = try { access.read() } catch (error: InstallStorageException) {
            saved = null
            mutable.update { it.copy(phase = AppUpdatePhase.BLOCKED, release = null, attemptId = null, cleanupToken = "unreadable", canCleanup = true, error = "update.storage_unavailable") }
            return
        }
        check(); saved = record
        val hasSessions = access.hasSessions(); check()
        mutable.update { it.copy(attemptId = record?.record?.takeIf(::owned)?.id, cleanupToken = cleanupContext(record, hasSessions)) }
        if (configuration == null) {
            mutable.update { it.copy(phase = if (configurationInvalid) AppUpdatePhase.ERROR else AppUpdatePhase.UNCONFIGURED, release = null,
                canCleanup = record != null || hasSessions, error = if (configurationInvalid) "update.configuration" else null) }
            return
        }
        if (record != null && !owned(record.record)) {
            mutable.update { it.copy(phase = AppUpdatePhase.BLOCKED, release = null, canCleanup = true, error = "update.other_context") }
            return
        }
        if (record == null) {
            if (hasSessions) mutable.update { it.copy(phase = AppUpdatePhase.BLOCKED, release = null, canCleanup = true, error = "update.installation_unknown") }
            else mutable.update { it.copy(phase = if (it.release != null) AppUpdatePhase.AVAILABLE else if (publicationChecked) AppUpdatePhase.CURRENT else AppUpdatePhase.IDLE, canCleanup = false) }
            return
        }
        val original = record.record
        if (original.phase != AppInstallPhase.RETIRED) {
            access.reconcileInstalled(record, ::check)?.let { confirmed ->
                check(); saved = confirmed; unsubmittedId = null; dropCandidate(); armed = null
                mutable.update { it.copy(phase = if (it.release?.versionCode?.let { version -> version > confirmed.record.release.versionCode } == true) AppUpdatePhase.AVAILABLE else AppUpdatePhase.INSTALLED,
                    installedVersion = confirmed.record.release.versionCode, release = it.release?.takeIf { release -> release.versionCode > confirmed.record.release.versionCode }, canCleanup = hasSessions) }
                return
            }
        }
        check()
        val phase = when (original.phase) {
            AppInstallPhase.PREPARING, AppInstallPhase.PREPARED -> if (unsubmittedId == original.id && candidate != null) AppUpdatePhase.PREPARED else AppUpdatePhase.REPREPARE
            AppInstallPhase.WAITING_USER -> AppUpdatePhase.WAITING_USER
            AppInstallPhase.COMMITTING, AppInstallPhase.RESULT_REPORTED -> AppUpdatePhase.UNKNOWN
            AppInstallPhase.FAILED -> if (publicationChecked) { if (mutable.value.release == null) AppUpdatePhase.CURRENT else AppUpdatePhase.AVAILABLE } else AppUpdatePhase.FAILED
            AppInstallPhase.INSTALLED, AppInstallPhase.RETIRED -> if (mutable.value.release != null) AppUpdatePhase.AVAILABLE else if (publicationChecked) AppUpdatePhase.CURRENT else AppUpdatePhase.IDLE
        }
        mutable.update { it.copy(phase = phase, release = if (!original.phase.terminal) original.release else it.release,
            canCleanup = !original.phase.terminal || hasSessions) }
        val request = armed
        if (original.phase == AppInstallPhase.WAITING_USER && request?.recordId == original.id) {
            if (monotonicNanos() - request.at !in 0..PROMPT_WAIT_NANOS) { armed = null; return }
            authorize(original)
            access.prompt(original)?.let { launch(AppUpdateLaunchKind.CONFIRMATION, it); armed = null }
        }
    }
    private suspend fun select(): AppReleaseSelection {
        check()
        mutable.update { it.copy(phase = AppUpdatePhase.CHECKING) }
        val installed = access.installed(); val selected = access.select(installed, config(), ::check); check()
        publicationChecked = true
        mutable.update { it.copy(installedVersion = installed.versionCode, currentSupported = selected.currentSupported, release = selected.release,
            downloadedBytes = 0, canInstall = access.canInstall()) }
        return selected
    }
    private suspend fun authorize(record: AppInstallationRecord) {
        check()
        if (!owned(record) || access.installed() != record.expected) fail("update.installed_changed")
        val selected = access.select(record.expected, config(), ::check); check()
        if (selected.release?.document?.sha256() != record.release.document.sha256()) fail("update.publication_changed")
        mutable.update { it.copy(currentSupported = selected.currentSupported) }
    }
    fun checkLatest() {
        armed = null
        perform(reconcileAfter = false) {
            reconcile()
            val original = saved?.record
            if (original != null && owned(original) && original.phase in setOf(AppInstallPhase.PREPARING, AppInstallPhase.PREPARED) && candidate == null) {
                access.abandon(original); saved = null
            } else if (original?.phase?.terminal == false || mutable.value.phase == AppUpdatePhase.BLOCKED) return@perform
            select(); reconcile()
        }
    }
    fun download(expectedPublication: String? = mutable.value.release?.document?.sha256()) {
        if (mutable.value.phase != AppUpdatePhase.AVAILABLE) return
        perform {
            val expected = mutable.value.release ?: fail("update.publication_changed")
            if (expectedPublication != expected.document.sha256()) throw StaleAction("update.publication_changed")
            armed = null
            val old = access.read()
            if (old?.record?.phase?.terminal == false || access.hasSessions()) fail("update.pending_installation")
            val selected = select()
            if (selected.release?.document?.sha256() != expected.document.sha256()) fail("update.publication_changed")
            if (!access.canInstall()) fail("update.install_permission_required")
            val installed = access.installed()
            publicationChecked = false
            mutable.update { it.copy(phase = AppUpdatePhase.DOWNLOADING) }
            var nextProgress = 0L
            candidate = access.download(expected, config(), ::check) { count ->
                check()
                val now = monotonicNanos()
                if (count == expected.sizeBytes || now >= nextProgress) {
                    nextProgress = now + 250_000_000
                    mutable.update { it.copy(downloadedBytes = count) }
                }
            }
            check(); val downloaded = candidate ?: fail("update.prepare_again")
            mutable.update { it.copy(phase = AppUpdatePhase.VERIFYING) }
            access.verify(downloaded, installed, ::check); check()
            val attempt = UUID.randomUUID().toString(); unsubmittedId = attempt
            saved = access.prepare(attempt, owner, config(), downloaded, installed, ::check)
        }
    }
    fun install(expectedAttempt: String? = mutable.value.attemptId, expectedPublication: String? = mutable.value.release?.document?.sha256()) {
        if (mutable.value.phase !in setOf(AppUpdatePhase.PREPARED, AppUpdatePhase.WAITING_USER)) return
        perform {
        val original = access.read()?.record ?: fail("update.installation_unknown")
        if (!owned(original)) fail("update.other_context")
        if (original.id != expectedAttempt || original.release.document.sha256() != expectedPublication ||
            original.phase !in setOf(AppInstallPhase.PREPARED, AppInstallPhase.WAITING_USER)) throw StaleAction("update.installation_changed")
        armed = Armed(original.id, monotonicNanos())
        if (original.phase == AppInstallPhase.WAITING_USER) {
            authorize(original)
            access.prompt(original)?.let { launch(AppUpdateLaunchKind.CONFIRMATION, it); armed = null; return@perform }
        }
        access.commit(original, ::authorize, ::check)
        unsubmittedId = null; dropCandidate()
        }
    }
    fun requestPermission() {
        if (closed || action?.isActive == true || liveLaunch != null || configuration == null || mutable.value.phase !in setOf(AppUpdatePhase.AVAILABLE, AppUpdatePhase.PREPARED, AppUpdatePhase.WAITING_USER)) return
        perform(reconcileAfter = false) { armed = null; launch(AppUpdateLaunchKind.PERMISSION, access.permissionSettings()) }
    }
    private fun launch(kind: AppUpdateLaunchKind, intent: () -> Intent) {
        check()
        val event = AppUpdateLaunch(id, kind, intent)
        liveLaunch = event
        mutable.update { it.copy(launchPending = true) }
        if (!launches.trySend(event).isSuccess) {
            liveLaunch = null; mutable.update { it.copy(launchPending = false) }; fail("update.system_ui_unavailable")
        }
    }
    fun consume(event: AppUpdateLaunch): (() -> Intent)? {
        if (closed || !scope.isActive || event !== liveLaunch || event.viewId != id) return null
        try { check() }
        catch (_: CancellationException) { return null }
        catch (error: RemoteRequestException) { if (error.code in AUTHORITY_ERRORS) authorityFailure(error.code); return null }
        liveLaunch = null; mutable.update { it.copy(launchPending = false) }
        return event.intent
    }
    fun launchFailed(event: AppUpdateLaunch) {
        if (!closed && event.viewId == id && (liveLaunch == null || liveLaunch === event)) {
            liveLaunch = null; armed = null; mutable.update { it.copy(launchPending = false, error = "update.system_ui_unavailable") }
        }
    }
    fun cleanup(expectedContext: String? = mutable.value.cleanupToken) {
        perform {
            var unreadable = false
            val latest = try { access.read() } catch (_: InstallStorageException) { unreadable = true; null }
            val context = if (unreadable) "unreadable" else cleanupContext(latest, access.hasSessions())
            if (expectedContext == null || expectedContext != context) throw StaleAction("update.installation_changed")
            check(); armed = null; dropCandidate(); access.cleanup(::check); unsubmittedId = null; saved = null; publicationChecked = false
            mutable.update { it.copy(release = null, currentSupported = null) }
        }
    }
    fun cancelDownload() {
        if (closed || mutable.value.phase !in setOf(AppUpdatePhase.DOWNLOADING, AppUpdatePhase.VERIFYING)) return
        val previous = action ?: return
        previous.cancel(); dropCandidate(); armed = null
        scope.launch { previous.join(); retireUnsubmitted(); if (!closed) perform {} }
    }
    override fun close() {
        if (closed) return
        closed = true; armed = null; liveLaunch = null; dropCandidate(); launches.close()
        val previous = action
        scope.launch(start = CoroutineStart.UNDISPATCHED) { withContext(NonCancellable) { previous?.cancelAndJoin(); retireUnsubmitted() } }
        scope.cancel()
    }
    companion object {
        private const val PROMPT_WAIT_NANOS = 30_000_000_000L
        private val AUTHORITY_ERRORS = setOf("auth.expired", "auth.proof_invalid", "auth.identity_mismatch", "auth.reauthentication_required", "access.denied", "access.revoked", "device.invalid", "access.organization_missing")
        private fun fail(code: String): Nothing = throw RemoteRequestException(code)
        private fun cleanupContext(saved: StoredAppInstallation?, hasSessions: Boolean): String? = saved?.record?.let {
            sha256("dsh/app-update-cleanup/v1\u0000${it.id}\u0000${it.sessionId}\u0000${it.nonce}\u0000${it.owner.fingerprint}".toByteArray(Charsets.UTF_8))
        } ?: if (hasSessions) "orphan" else null
        private fun code(error: Exception) = when (error) {
            is StaleAction -> error.code
            is RemoteRequestException -> error.code
            is InstallStorageException -> "update.storage_unavailable"
            is ProtocolException -> "update.invalid_response"
            else -> "update.unavailable"
        }
    }
}
