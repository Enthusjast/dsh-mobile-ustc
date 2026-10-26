package cn.edu.ustc.dsh.protocol

import java.net.URI

const val MAX_APK_BYTES = 512L * 1024 * 1024
const val APP_UPDATE_PROTOCOL = 1L

class ClientVersionWindow private constructor(val minimum: Long, val maximum: Long) {
    fun contains(version: Long) = version in minimum..maximum
    companion object {
        fun parse(root: JsonObject): ClientVersionWindow {
            root.exactKeys("minimum", "maximum")
            val minimum = root.integer("minimum")
            return ClientVersionWindow(minimum, root.integer("maximum", minimum))
        }
    }
}

/** Metadata fixes the candidate bytes; it cannot establish a new signing trust anchor. */
class AppRelease private constructor(val document: JsonDocument) {
    private val root get() = document.root
    val id = root.string("release_id")
    val versionCode = root.integer("version_code")
    val versionName = root.string("version_name")
    val packageName = root.string("package_name")
    val sha256 = root.string("sha256")
    val sizeBytes = root.integer("size_bytes", 1, MAX_APK_BYTES)
    val signingCertificate = root.string("signing_cert_sha256")
    val downloadUrl = root.string("download_url")
    val downloadOrigin = appUpdateOrigin(downloadUrl)
    val minimumProtocolVersion = root.integer("minimum_protocol_version", 1, 32)
    val maximumProtocolVersion = root.integer("maximum_protocol_version", minimumProtocolVersion, 32)
    val minimumAndroidApi = root.integer("minimum_android_api", 26, 100)
    val rolloutBasisPoints = root.integer("rollout_basis_points", 0, 10000)
    val releaseNotes = root.string("release_notes")
    override fun toString() = "AppRelease($versionCode)"
    companion object {
        fun parse(root: JsonObject): AppRelease {
            root.exactKeys("release_id", "version_code", "version_name", "package_name", "sha256", "size_bytes", "signing_cert_sha256", "download_url",
                "minimum_protocol_version", "maximum_protocol_version", "minimum_android_api", "rollout_basis_points", "release_notes")
            Contract.uuid(root.string("release_id")); appPackage(root.string("package_name"))
            Contract.digest(root.string("sha256")); Contract.digest(root.string("signing_cert_sha256"))
            releaseText(root.string("version_name"), 64, false); releaseText(root.string("release_notes"), 8192, true)
            return AppRelease(JsonDocument.of(root))
        }
    }
}

class AppReleaseSelection private constructor(val currentSupported: Boolean, val clientWindow: ClientVersionWindow, val release: AppRelease?) {
    override fun toString() = "AppReleaseSelection"
    companion object {
        fun parse(root: JsonObject, packageName: String, installedVersion: Long, androidApi: Long, downloadOrigins: Set<String>): AppReleaseSelection {
            appPackage(packageName)
            if (installedVersion !in 1..MAX_SAFE_INTEGER || androidApi !in 26..100 || downloadOrigins.size !in 1..8) throw ProtocolException()
            downloadOrigins.forEach { if (appUpdateOrigin(it, originOnly = true) != it) throw ProtocolException() }
            root.exactKeys("v", "package_name", "protocol_version", "current_version_code", "current_supported", "supported_client_versions", "release")
            root.integer("v", 1, 1); root.integer("protocol_version", APP_UPDATE_PROTOCOL, APP_UPDATE_PROTOCOL)
            if (root.string("package_name") != packageName || root.integer("current_version_code") != installedVersion) throw ProtocolException()
            val window = ClientVersionWindow.parse(root.obj("supported_client_versions"))
            val supported = (root["current_supported"] as? JsonBoolean)?.value ?: throw ProtocolException()
            if (supported != window.contains(installedVersion)) throw ProtocolException()
            val release = when (val value = root["release"]) {
                JsonNull -> null
                is JsonObject -> AppRelease.parse(value).also {
                    if (it.packageName != packageName || it.versionCode <= installedVersion || !window.contains(it.versionCode) ||
                        APP_UPDATE_PROTOCOL !in it.minimumProtocolVersion..it.maximumProtocolVersion || androidApi < it.minimumAndroidApi ||
                        it.rolloutBasisPoints == 0L || it.downloadOrigin !in downloadOrigins) throw ProtocolException()
                }
                else -> throw ProtocolException()
            }
            return AppReleaseSelection(supported, window, release)
        }
    }
}

/** The allowlist is provisioned independently of downloaded metadata. */
fun appUpdateOrigin(value: String, originOnly: Boolean = false): String {
    if (value.length !in 1..2048 || value.any { it <= ' ' || it >= '\u007f' }) throw ProtocolException()
    val uri = try { URI(value) } catch (_: Exception) { throw ProtocolException() }
    if (uri.scheme != "https" || uri.host.isNullOrEmpty() || uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null ||
        uri.rawAuthority != uri.rawAuthority.lowercase(java.util.Locale.ROOT) || uri.rawPath != uri.path || uri.normalize() != uri || uri.toASCIIString() != value ||
        '\\' in value || (originOnly && !uri.path.isNullOrEmpty()) || (!originOnly && (uri.path.isNullOrEmpty() || uri.path == "/"))) throw ProtocolException()
    return "https://${uri.rawAuthority}"
}

private fun appPackage(value: String) {
    if (value.length > 255 || !Regex("[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+").matches(value)) throw ProtocolException()
}
private fun releaseText(value: String, limit: Int, multiline: Boolean) {
    requireText(value)
    if (value.toByteArray(Charsets.UTF_8).size > limit || value.isBlank() || value.any { it.isISOControl() && !(multiline && it in "\n\t") }) throw ProtocolException()
}
