package cn.edu.ustc.dsh.mobile

import android.annotation.TargetApi
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.content.pm.SigningInfo
import android.os.Build
import cn.edu.ustc.dsh.network.PrivateApkCandidate
import cn.edu.ustc.dsh.network.RemoteRequestException
import cn.edu.ustc.dsh.protocol.APP_UPDATE_PROTOCOL
import cn.edu.ustc.dsh.protocol.MAX_SAFE_INTEGER
import kotlinx.coroutines.CancellationException
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest

/** The installed package supplies trust. Candidate metadata never supplies a new trust anchor. */
internal class AndroidApkVerifier(context: Context) {
    private val context = context.applicationContext
    private val packages = this.context.packageManager
    data class Installed(val packageName: String, val versionCode: Long, val signingCertificate: String) {
        override fun toString() = "InstalledApk($versionCode)"
    }
    data class Verification(val installed: Installed, val versionCode: Long, val signingCertificate: String) {
        override fun toString() = "VerifiedApk($versionCode)"
    }
    fun installed(): Installed = checked {
        val info = if (Build.VERSION.SDK_INT >= 33) Api33.installed(packages, context.packageName, flags())
            else @Suppress("DEPRECATION") packages.getPackageInfo(context.packageName, flags())
        if (info.packageName != context.packageName || info.sharedUserId != null || !info.splitNames.isNullOrEmpty()) invalid()
        Installed(info.packageName, version(info), signer(info))
    }
    /** Blocking file/package inspection. Run on an IO dispatcher; repeat before installation. */
    fun verify(candidate: PrivateApkCandidate, expected: Installed = installed(), current: () -> Unit = {}): Verification {
        try {
            return checked {
                current()
                val release = candidate.release
                if (installed() != expected || release.packageName != expected.packageName || release.signingCertificate != expected.signingCertificate ||
                    release.versionCode <= expected.versionCode) mismatch()
                if (APP_UPDATE_PROTOCOL !in release.minimumProtocolVersion..release.maximumProtocolVersion || release.minimumAndroidApi > Build.VERSION.SDK_INT || release.rolloutBasisPoints == 0L) incompatible()
                candidate.inspectVerified(current) { file ->
                    current()
                    val root = File(context.cacheDir, "apk-updates")
                    if (Files.isSymbolicLink(root.toPath()) || !file.canonicalFile.toPath().startsWith(root.canonicalFile.toPath())) throw RemoteRequestException("update.storage_unavailable")
                    val info = archive(file) ?: invalid()
                    val application = info.applicationInfo ?: invalid()
                    if (info.sharedUserId != null || !info.splitNames.isNullOrEmpty()) invalid()
                    if (info.packageName != expected.packageName || version(info) != release.versionCode || info.versionName != release.versionName ||
                        signer(info) != expected.signingCertificate) mismatch()
                    if (application.minSdkVersion != release.minimumAndroidApi.toInt() || application.minSdkVersion > Build.VERSION.SDK_INT) incompatible()
                    if (Build.VERSION.SDK_INT >= 36 && Api36.verifiedSigner(file) != expected.signingCertificate) mismatch()
                    current()
                    if (installed() != expected) mismatch()
                    Verification(expected, release.versionCode, expected.signingCertificate)
                }
            }
        } catch (error: Exception) { candidate.close(); throw error }
    }
    private fun archive(file: File): PackageInfo? = if (Build.VERSION.SDK_INT >= 33) Api33.archive(packages, file, flags())
        else @Suppress("DEPRECATION") packages.getPackageArchiveInfo(file.absolutePath, flags())
    // API 28/29 archive parsing needs GET_SIGNATURES to collect and verify
    // certificates. GET_SIGNING_CERTIFICATES alone is insufficient there.
    @Suppress("DEPRECATION") private fun flags(): Int = PackageManager.GET_SIGNATURES or
        (if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else 0)
    @Suppress("DEPRECATION") private fun version(info: PackageInfo): Long = (if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()).also {
        if (it !in 1..MAX_SAFE_INTEGER) invalid()
    }
    @Suppress("DEPRECATION") private fun signer(info: PackageInfo): String = if (Build.VERSION.SDK_INT >= 28) Api28.signer(info.signingInfo ?: invalid())
        else certificate(info.signatures?.singleOrNull() ?: invalid())

    @TargetApi(28) private object Api28 {
        fun signer(info: SigningInfo): String {
            if (info.hasMultipleSigners()) invalid()
            val history = info.signingCertificateHistory ?: invalid()
            if (history.size !in 1..64 || !info.hasPastSigningCertificates() && history.size != 1) invalid()
            // Only the current signer is trusted; a past-certificate overlap
            // cannot authorize a new current signing identity.
            return certificate(history.last())
        }
    }
    @TargetApi(33) private object Api33 {
        fun installed(manager: PackageManager, name: String, flags: Int): PackageInfo = manager.getPackageInfo(name, PackageManager.PackageInfoFlags.of(flags.toLong()))
        fun archive(manager: PackageManager, file: File, flags: Int): PackageInfo? = manager.getPackageArchiveInfo(file.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
    }
    @TargetApi(36) private object Api36 {
        fun verifiedSigner(file: File): String = Api28.signer(PackageManager.getVerifiedSigningInfo(file.absolutePath, SigningInfo.VERSION_SIGNING_BLOCK_V2))
    }
    companion object {
        private fun certificate(signature: Signature): String {
            val encoded = signature.toByteArray()
            if (encoded.isEmpty() || encoded.size > 32 * 1024) invalid()
            return MessageDigest.getInstance("SHA-256").digest(encoded).joinToString("") { "%02x".format(it.toInt() and 255) }
        }
        private fun <T> checked(action: () -> T): T = try { action() }
            catch (error: CancellationException) { throw error }
            catch (error: RemoteRequestException) { throw error }
            catch (_: Exception) { invalid() }
        private fun invalid(): Nothing = throw RemoteRequestException("update.apk_invalid")
        private fun mismatch(): Nothing = throw RemoteRequestException("update.identity_mismatch")
        private fun incompatible(): Nothing = throw RemoteRequestException("update.incompatible")
    }
}
