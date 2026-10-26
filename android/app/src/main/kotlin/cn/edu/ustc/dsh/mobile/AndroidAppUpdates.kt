package cn.edu.ustc.dsh.mobile

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import cn.edu.ustc.dsh.auth.AppUpdateDeployment
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.map
import java.io.File
import java.io.FileNotFoundException

internal suspend fun loadAppUpdateConfiguration(context: Context, owner: LocalDataOwner, source: (() -> ByteArray)?): AppUpdateDeployment? = withContext(Dispatchers.IO) {
    val raw = try { source?.invoke() ?: context.assets.open("app-update-deployment.json").use { it.readBytes() } }
    catch (_: FileNotFoundException) { return@withContext null }
    AppUpdateDeployment.parse(raw, owner.deploymentHash, context.packageName)
}

internal class AndroidAppUpdateAccess(
    private val context: Context, private val api: RemoteApi, private val http: LoginHttp,
    private val installations: AppInstallations, private val slot: String,
) : AppUpdateAccess {
    private val verifier = AndroidApkVerifier(context)
    override val changes = installations.changes.filter { it == slot }.map { Unit }
    override suspend fun installed() = withContext(Dispatchers.IO) { verifier.installed() }
    override fun canInstall() = installations.canInstall()
    override suspend fun read() = installations.read(slot)
    override suspend fun hasSessions() = withContext(Dispatchers.IO) {
        context.packageManager.packageInstaller.mySessions.any { it.appPackageName == null || it.appPackageName == context.packageName }
    }
    override suspend fun reconcileInstalled(saved: StoredAppInstallation, current: () -> Unit): StoredAppInstallation? {
        if (!installations.installedArtifact(saved.record, current)) return null
        return try { if (saved.record.phase == AppInstallPhase.INSTALLED) saved else installations.confirmInstalled(slot, saved.record.id, current) }
        catch (error: InstallStorageException) { if (error.failure == InstallStorageFailure.CONFLICT) null else throw error }
    }
    override suspend fun select(installed: AndroidApkVerifier.Installed, configuration: AppUpdateDeployment, current: () -> Unit) =
        api.appRelease(installed.packageName, installed.versionCode, Build.VERSION.SDK_INT.toLong(), configuration.downloadOrigins, current)
    override suspend fun download(release: AppRelease, configuration: AppUpdateDeployment, current: () -> Unit, progress: (Long) -> Unit) =
        http.downloadAppRelease(release, configuration.downloadOrigins, File(context.cacheDir, "apk-updates"), current, progress)
    override suspend fun verify(candidate: PrivateApkCandidate, installed: AndroidApkVerifier.Installed, current: () -> Unit): Unit = withContext(Dispatchers.IO) {
        val lifetime = currentCoroutineContext()
        verifier.verify(candidate, installed) { lifetime.ensureActive(); current() }
        Unit
    }
    override suspend fun prepare(id: String, owner: LocalDataOwner, configuration: AppUpdateDeployment, candidate: PrivateApkCandidate, installed: AndroidApkVerifier.Installed, current: () -> Unit) =
        installations.prepare(slot, id, owner, configuration, candidate, installed, current)
    override suspend fun commit(record: AppInstallationRecord, authorize: suspend (AppInstallationRecord) -> Unit, current: () -> Unit) = installations.commit(slot, record.id, authorize, current)
    override suspend fun abandon(record: AppInstallationRecord) { installations.cancel(slot, record.id) }
    override suspend fun cleanup(current: () -> Unit) { installations.cleanupOrphans(slot, current) }
    override fun prompt(record: AppInstallationRecord): (() -> Intent)? {
        val intent = installations.takePrompt(slot, record) ?: return null
        return { Intent(intent) }
    }
    override fun permissionSettings(): () -> Intent = {
        val intent = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.fromParts("package", context.packageName, null))
        @Suppress("DEPRECATION") val activity = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY or PackageManager.MATCH_SYSTEM_ONLY)?.activityInfo
            ?: throw RemoteRequestException("update.system_ui_unavailable")
        val flags = activity.applicationInfo?.flags ?: throw RemoteRequestException("update.system_ui_unavailable")
        if (flags.and(ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0) throw RemoteRequestException("update.system_ui_unavailable")
        intent.setComponent(ComponentName(activity.packageName, activity.name))
    }
}
