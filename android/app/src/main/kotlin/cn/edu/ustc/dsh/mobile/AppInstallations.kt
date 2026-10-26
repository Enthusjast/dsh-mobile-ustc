package cn.edu.ustc.dsh.mobile

import android.annotation.TargetApi
import android.app.PendingIntent
import android.content.Context
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import cn.edu.ustc.dsh.auth.AppUpdateDeployment
import cn.edu.ustc.dsh.network.PrivateApkCandidate
import cn.edu.ustc.dsh.network.RemoteRequestException
import cn.edu.ustc.dsh.protocol.*
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

internal class AppInstallPrompt(val recordId: String, val sessionId: Int, val nonce: String, val intent: Intent) {
    override fun toString() = "AppInstallPrompt"
}

/** Own-package installer only. Callers provide fresh actor/publication checks before every commit. */
@Singleton
internal class AppInstallations @Inject constructor(@param:ApplicationContext private val context: Context) {
    private val packages get() = context.packageManager
    private val installer get() = packages.packageInstaller
    private val verifier = AndroidApkVerifier(context)
    private val mutableChanges = MutableSharedFlow<String>(extraBufferCapacity = 16)
    val changes = mutableChanges.asSharedFlow()
    private val prompts = ConcurrentHashMap<String, AppInstallPrompt>()
    private class Prepared(val record: AppInstallationRecord, val candidate: PrivateApkCandidate)
    private val prepared = ConcurrentHashMap<String, Prepared>()
    private fun forgetPrepared(slot: String, id: String) { prepared[slot]?.takeIf { it.record.id == id }?.let { prepared.remove(slot, it) } }
    private fun journal(slot: String) = AppInstallationStorage(context, slot)
    fun canInstall() = packages.canRequestPackageInstalls()
    suspend fun read(slot: String): StoredAppInstallation? = withContext(Dispatchers.IO) { journal(slot).read() }
    suspend fun ownSession(id: Int): PackageInstaller.SessionInfo? = withContext(Dispatchers.IO) { ownSessionLocked(id) }
    private fun ownSessionLocked(id: Int) = installer.mySessions.firstOrNull { it.sessionId == id && (it.appPackageName == null || it.appPackageName == context.packageName) }
    private fun relevantSessions() = installer.mySessions.filter { it.appPackageName == null || it.appPackageName == context.packageName }

    suspend fun prepare(slot: String, id: String, owner: LocalDataOwner, configuration: AppUpdateDeployment, candidate: PrivateApkCandidate,
        expected: AndroidApkVerifier.Installed, current: () -> Unit): StoredAppInstallation = mutations.withLock {
        var created: Int? = null
        try {
            withContext(Dispatchers.IO) {
                val lifetime = currentCoroutineContext()
                val check = { lifetime.ensureActive(); current() }
                check()
                verifier.verify(candidate, expected, check)
                if (!canInstall()) fail("update.install_permission_required")
                val storage = journal(slot); val previous = storage.read()
                if (previous?.record?.phase?.terminal == false || relevantSessions().isNotEmpty()) fail("update.pending_installation")
                val release = candidate.release
                val parameters = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
                    setAppPackageName(context.packageName); setSize(release.sizeBytes); setInstallReason(PackageManager.INSTALL_REASON_USER)
                    setOriginatingUri(Uri.parse(release.downloadUrl))
                    if (Build.VERSION.SDK_INT >= 31) Api31.requireUser(this)
                    if (Build.VERSION.SDK_INT >= 33) Api33.downloaded(this)
                }
                check(); val session = installer.createSession(parameters); created = session
                val nonce = Contract.base64url(ByteArray(32).also(SecureRandom()::nextBytes))
                var saved = storage.save(AppInstallationRecord.create(id, owner, configuration, expected, release, session, nonce, System.currentTimeMillis()), previous?.revision ?: 0)
                installer.openSession(session).use { opened ->
                    opened.openWrite("base.apk", 0, release.sizeBytes).use { output -> candidate.copyVerifiedTo(output, check); opened.fsync(output) }
                    if (opened.names.toSet() != setOf("base.apk")) fail("update.integrity_mismatch")
                }
                check()
                verifier.verify(candidate, expected, check)
                saved = storage.save(saved.record.transition(AppInstallPhase.PREPARED, System.currentTimeMillis()), saved.revision)
                prepared[slot] = Prepared(saved.record, candidate)
                check()
                saved
            }
        } catch (error: Exception) {
            forgetPrepared(slot, id)
            withContext(NonCancellable + Dispatchers.IO) {
                created?.let { session -> runCatching { installer.abandonSession(session) } }
                created?.let { session -> runCatching { retireUncommitted(slot, id, session, false) } }
            }
            throw normalize(error)
        }
    }

    /** Reuses the original session. Unknown results never create a second session here. */
    suspend fun commit(slot: String, id: String, authorize: suspend (AppInstallationRecord) -> Unit, current: () -> Unit): Unit = mutations.withLock {
        var attempted = false
        var originallyPrepared: Int? = null
        try {
            withContext<Unit>(Dispatchers.IO) {
                val lifetime = currentCoroutineContext()
                val check = { lifetime.ensureActive(); current() }
                check()
                val storage = journal(slot); var saved = storage.read() ?: fail("update.installation_unknown")
                if (saved.record.id != id || saved.record.phase !in setOf(AppInstallPhase.PREPARED, AppInstallPhase.COMMITTING, AppInstallPhase.WAITING_USER)) fail("update.installation_unknown")
                if (saved.record.phase == AppInstallPhase.PREPARED) originallyPrepared = saved.record.sessionId
                val information = ownSessionLocked(saved.record.sessionId) ?: fail("update.installation_unknown")
                if (!canInstall()) fail("update.install_permission_required")
                if (information.isSealed) {
                    // Committed sessions prohibit openRead on supported SDKs.
                    // Their immutable content is bound by the durable precommit
                    // digest, exact owned session and original actor/callback.
                    if (saved.record.phase != AppInstallPhase.WAITING_USER || saved.record.preparedSHA256 != saved.record.release.sha256 ||
                        information.appPackageName != context.packageName || verifier.installed() != saved.record.expected) fail("update.installation_unknown")
                } else {
                    // Some API 26 SELinux policies reject returning the staged
                    // read FD to an ordinary installer. Bind the exact verified
                    // write/fsync to this process's still-live private candidate.
                    // After process death an unsubmitted session needs new
                    // preparation; a disk record alone cannot recreate this proof.
                    val receipt = prepared[slot]?.takeIf { it.record.sameAttempt(saved.record) } ?: fail("update.prepare_again")
                    if (information.appPackageName != context.packageName || saved.record.preparedSHA256 != saved.record.release.sha256) fail("update.installation_unknown")
                    verifier.verify(receipt.candidate, saved.record.expected, check)
                    installer.openSession(saved.record.sessionId).use { session ->
                        if (session.names.toSet() != setOf("base.apk")) fail("update.integrity_mismatch")
                    }
                }
                authorize(saved.record)
                check()
                val latest = storage.read() ?: fail("update.installation_unknown")
                if (!latest.record.sameAttempt(saved.record)) fail("update.installation_unknown")
                saved = storage.save(latest.record.transition(AppInstallPhase.COMMITTING, System.currentTimeMillis()), latest.revision)
                check()
                installer.openSession(saved.record.sessionId).use { session ->
                    // Persist the original context before crossing the Binder
                    // boundary. An exception after this point is uncertain.
                    attempted = true
                    forgetPrepared(slot, id)
                    session.commit(resultSender(slot, saved.record).intentSender)
                }
                mutableChanges.tryEmit(slot)
            }
        } catch (error: Exception) {
            if (!attempted) originallyPrepared?.let { session -> withContext(NonCancellable + Dispatchers.IO) { runCatching { retireUncommitted(slot, id, session, true) } } }
            throw normalize(error)
        }
    }
    private fun retireUncommitted(slot: String, id: String, sessionId: Int, allowPlannedCommit: Boolean) {
        val storage = journal(slot); val saved = storage.read() ?: return
        val allowed = setOf(AppInstallPhase.PREPARING, AppInstallPhase.PREPARED) + if (allowPlannedCommit) setOf(AppInstallPhase.COMMITTING) else emptySet()
        if (saved.record.id != id || saved.record.sessionId != sessionId || saved.record.phase !in allowed) return
        runCatching { ownSessionLocked(saved.record.sessionId)?.let { installer.abandonSession(it.sessionId) } }
        storage.save(saved.record.transition(AppInstallPhase.RETIRED, System.currentTimeMillis()), saved.revision)
        forgetPrepared(slot, id)
        prompts.remove(slot); mutableChanges.tryEmit(slot)
    }
    suspend fun cancel(slot: String, id: String): Unit = mutations.withLock { withContext<Unit>(Dispatchers.IO) {
        val saved = journal(slot).read() ?: return@withContext
        if (saved.record.id != id) fail("update.installation_unknown")
        ownSessionLocked(saved.record.sessionId)?.let { installer.abandonSession(it.sessionId) }
        if (!saved.record.phase.terminal) journal(slot).save(saved.record.transition(AppInstallPhase.RETIRED, System.currentTimeMillis()), saved.revision)
        forgetPrepared(slot, id)
        prompts.remove(slot); mutableChanges.tryEmit(slot)
    } }
    /** Explicit recovery for unreadable state; never an uninstall or a downgrade. */
    suspend fun cleanupOrphans(slot: String, current: () -> Unit = {}): Unit = mutations.withLock { withContext<Unit>(Dispatchers.IO) {
        val lifetime = currentCoroutineContext()
        fun check() { lifetime.ensureActive(); current() }
        check()
        for (session in relevantSessions()) { check(); installer.abandonSession(session.sessionId) }
        check()
        if (relevantSessions().isNotEmpty()) fail("update.pending_installation")
        check()
        journal(slot).resetAfterSessionCleanup(); prepared.remove(slot); prompts.remove(slot); mutableChanges.tryEmit(slot)
    } }
    suspend fun installedArtifact(record: AppInstallationRecord, current: () -> Unit = {}): Boolean = withContext(Dispatchers.IO) {
        val lifetime = currentCoroutineContext()
        val check = { lifetime.ensureActive(); current() }
        check()
        val installed = verifier.installed()
        if (installed.packageName != record.release.packageName || installed.versionCode != record.release.versionCode || installed.signingCertificate != record.release.signingCertificate) return@withContext false
        @Suppress("DEPRECATION") val info = packages.getPackageInfo(context.packageName, 0)
        val path = info.applicationInfo?.sourceDir ?: fail("update.installation_unknown")
        File(path).inputStream().use { verifyStream(it, record.release, check) }
        check()
        @Suppress("DEPRECATION") val after = packages.getPackageInfo(context.packageName, 0).applicationInfo?.sourceDir
        verifier.installed() == installed && after == path
    }
    suspend fun confirmInstalled(slot: String, id: String, current: () -> Unit): StoredAppInstallation = mutations.withLock { withContext(Dispatchers.IO) {
        val storage = journal(slot); val saved = storage.read() ?: fail("update.installation_unknown")
        if (saved.record.id != id || saved.record.phase == AppInstallPhase.RETIRED || !installedArtifact(saved.record, current)) fail("update.installation_unknown")
        current(); storage.save(saved.record.transition(AppInstallPhase.INSTALLED, System.currentTimeMillis()), saved.revision).also { prompts.remove(slot); mutableChanges.tryEmit(slot) }
    } }
    fun takePrompt(slot: String, record: AppInstallationRecord): Intent? {
        val pending = prompts[slot] ?: return null
        if (pending.recordId != record.id || pending.sessionId != record.sessionId || pending.nonce != record.nonce) return null
        return if (prompts.remove(slot, pending)) Intent(pending.intent) else null
    }
    /** Receiver persists hints only. Foreground reconciliation proves the installed package separately. */
    suspend fun receive(intent: Intent) = withContext(Dispatchers.IO) {
        if (intent.action != ACTION || intent.dataString?.length !in 1..256) return@withContext
        val uri = intent.data ?: return@withContext
        val slot = uri.host ?: return@withContext
        if (uri.scheme != SCHEME || uri.authority != slot || uri.query != null || uri.fragment != null || !Regex("[a-z0-9-]{1,64}").matches(slot) || uri.pathSegments.size != 2) return@withContext
        val session = uri.pathSegments[0].toIntOrNull() ?: return@withContext
        if (session < 1 || session.toString() != uri.pathSegments[0]) return@withContext
        val nonce = uri.pathSegments[1]
        if (nonce.length != 43) return@withContext
        val storage = journal(slot); val saved = storage.read() ?: return@withContext
        if (saved.record.phase.terminal || saved.record.sessionId != session || !MessageDigest.isEqual(nonce.toByteArray(), saved.record.nonce.toByteArray()) ||
            intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1) != session) return@withContext
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, Int.MIN_VALUE)
        val next = when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> AppInstallPhase.WAITING_USER
            PackageInstaller.STATUS_SUCCESS -> AppInstallPhase.RESULT_REPORTED
            in PackageInstaller.STATUS_FAILURE..PackageInstaller.STATUS_FAILURE_TIMEOUT -> AppInstallPhase.FAILED
            else -> return@withContext
        }
        val changed = try { saved.record.transition(next, System.currentTimeMillis()) } catch (_: ProtocolException) { return@withContext }
        val action = if (next == AppInstallPhase.WAITING_USER) systemPrompt(intent) ?: return@withContext else null
        storage.save(changed, saved.revision)
        if (action != null) {
            if (prompts.size >= 8) prompts.clear()
            prompts[slot] = AppInstallPrompt(saved.record.id, session, nonce, action)
        } else prompts.remove(slot)
        mutableChanges.tryEmit(slot)
    }
    private fun systemPrompt(intent: Intent): Intent? {
        val action = if (Build.VERSION.SDK_INT >= 33) Api33.intent(intent) else @Suppress("DEPRECATION") (intent.getParcelableExtra<android.os.Parcelable>(Intent.EXTRA_INTENT) as? Intent)
        action ?: return null
        @Suppress("DEPRECATION") val resolved = packages.resolveActivity(action, PackageManager.MATCH_DEFAULT_ONLY or PackageManager.MATCH_SYSTEM_ONLY) ?: return null
        val activity = resolved.activityInfo ?: return null
        val flags = activity.applicationInfo?.flags ?: return null
        if (flags.and(android.content.pm.ApplicationInfo.FLAG_SYSTEM or android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0) return null
        return Intent(action).setComponent(ComponentName(activity.packageName, activity.name))
    }
    private fun resultSender(slot: String, record: AppInstallationRecord): PendingIntent {
        val uri = Uri.Builder().scheme(SCHEME).authority(slot).appendPath(record.sessionId.toString()).appendPath(record.nonce).build()
        val intent = Intent(context, AppInstallResultReceiver::class.java).setAction(ACTION).setData(uri)
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0
        return PendingIntent.getBroadcast(context, record.sessionId, intent, flags)
    }
    private fun copyBounded(input: InputStream, output: OutputStream, release: AppRelease, current: () -> Unit) {
        val buffer = ByteArray(64 * 1024); var count = 0L
        while (true) { current(); val size = input.read(buffer); if (size < 0) break; if (size == 0 || count + size > release.sizeBytes) fail("update.integrity_mismatch"); output.write(buffer, 0, size); count += size }
        if (count != release.sizeBytes) fail("update.integrity_mismatch")
    }
    private fun verifyStream(input: InputStream, release: AppRelease, current: () -> Unit) {
        val digest = MessageDigest.getInstance("SHA-256")
        copyBounded(input, object : OutputStream() {
            override fun write(value: Int) { digest.update(value.toByte()) }
            override fun write(bytes: ByteArray, offset: Int, length: Int) { digest.update(bytes, offset, length) }
        }, release, current)
        current()
        if (digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) } != release.sha256) fail("update.integrity_mismatch")
    }
    @TargetApi(31) private object Api31 { fun requireUser(parameters: PackageInstaller.SessionParams) { parameters.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED) } }
    @TargetApi(33) private object Api33 {
        fun downloaded(parameters: PackageInstaller.SessionParams) { parameters.setPackageSource(PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE) }
        fun intent(source: Intent): Intent? = source.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
    }
    companion object {
        private val mutations = Mutex()
        const val ACTION = "cn.edu.ustc.dsh.mobile.INSTALL_RESULT"
        const val SCHEME = "dsh-app-install-result"
        private fun fail(code: String): Nothing = throw RemoteRequestException(code)
        private fun normalize(error: Exception): Exception = when (error) {
            is CancellationException, is RemoteRequestException, is InstallStorageException -> error
            else -> RemoteRequestException("update.installation_unknown").also { it.initCause(error) }
        }
    }
}
