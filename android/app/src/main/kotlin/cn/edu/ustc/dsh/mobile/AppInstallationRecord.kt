package cn.edu.ustc.dsh.mobile

import cn.edu.ustc.dsh.auth.AppUpdateDeployment
import cn.edu.ustc.dsh.protocol.*

internal enum class AppInstallPhase {
    PREPARING, PREPARED, COMMITTING, WAITING_USER, RESULT_REPORTED, INSTALLED, FAILED, RETIRED;
    val terminal get() = this in setOf(INSTALLED, FAILED, RETIRED)
}

/** Durable correlation facts, not proof of installation. INSTALLED requires a fresh platform/byte check. */
internal class AppInstallationRecord private constructor(val document: JsonDocument) {
    private val root get() = document.root
    val id = root.string("installation_id")
    val owner = root.obj("owner").let { LocalDataOwner(it.string("account_id"), it.string("organization_id"), it.string("deployment_sha256"), it.string("user_id"), it.string("device_id")) }
    val updateDeploymentHash = root.string("update_deployment_sha256")
    val expected = root.obj("expected_installed").let { AndroidApkVerifier.Installed(it.string("package_name"), it.integer("version_code"), it.string("signing_cert_sha256")) }
    val release = AppRelease.parse(root.obj("release"))
    val sessionId = root.integer("session_id", 1, Int.MAX_VALUE.toLong()).toInt()
    val nonce = root.string("nonce")
    val phase = AppInstallPhase.valueOf(root.string("phase"))
    val createdAt = root.integer("created_at_ms", 0)
    val updatedAt = root.integer("updated_at_ms", createdAt)
    val preparedSHA256 = when (val value = root["prepared_sha256"]) { JsonNull -> null; is JsonString -> Contract.digest(value.value); else -> throw ProtocolException() }
    private val immutableHash = JsonDocument.of(JsonObject(root.fields.filterKeys { it !in setOf("phase", "updated_at_ms", "prepared_sha256") })).sha256()
    fun sameAttempt(other: AppInstallationRecord) = immutableHash == other.immutableHash
    fun belongsTo(owner: LocalDataOwner, configuration: AppUpdateDeployment) = this.owner.fingerprint == owner.fingerprint &&
        configuration.deploymentHash == owner.deploymentHash && configuration.packageName == expected.packageName &&
        release.downloadOrigin in configuration.downloadOrigins && updateDeploymentHash == configuration.fingerprint
    fun transition(next: AppInstallPhase, now: Long): AppInstallationRecord {
        if (now !in 0..MAX_SAFE_INTEGER || !allows(next)) throw ProtocolException()
        val prepared = if (phase == AppInstallPhase.PREPARING && next == AppInstallPhase.PREPARED) release.sha256.json() else root["prepared_sha256"]
        return parse(root.with("phase" to next.name.json(), "updated_at_ms" to maxOf(updatedAt, now).json(), "prepared_sha256" to prepared))
    }
    private fun allows(next: AppInstallPhase): Boolean {
        if (next == phase) return true
        if (phase in setOf(AppInstallPhase.INSTALLED, AppInstallPhase.RETIRED)) return false
        // A verified installed package is an independent fact even if another
        // installer completed the exact same artifact. It does not prove origin.
        if (next == AppInstallPhase.INSTALLED || next == AppInstallPhase.RETIRED) return true
        if (phase == AppInstallPhase.FAILED) return false
        if (next == AppInstallPhase.FAILED) return true
        return when (phase) {
            AppInstallPhase.PREPARING -> next == AppInstallPhase.PREPARED
            AppInstallPhase.PREPARED -> next == AppInstallPhase.COMMITTING
            AppInstallPhase.COMMITTING -> next in setOf(AppInstallPhase.WAITING_USER, AppInstallPhase.RESULT_REPORTED)
            AppInstallPhase.WAITING_USER -> next in setOf(AppInstallPhase.COMMITTING, AppInstallPhase.RESULT_REPORTED)
            AppInstallPhase.RESULT_REPORTED -> false
            else -> false
        }
    }
    override fun toString() = "AppInstallationRecord($phase)"
    companion object {
        private const val DOMAIN = "dsh-mobile-ustc/app-installation"
        fun create(id: String, owner: LocalDataOwner, configuration: AppUpdateDeployment, expected: AndroidApkVerifier.Installed, release: AppRelease, session: Int, nonce: String, now: Long): AppInstallationRecord {
            if (configuration.deploymentHash != owner.deploymentHash || configuration.packageName != release.packageName || release.downloadOrigin !in configuration.downloadOrigins) throw ProtocolException()
            return parse(jsonObject("domain" to DOMAIN.json(), "v" to 1L.json(), "installation_id" to id.json(), "owner" to owner.root,
                "update_deployment_sha256" to configuration.fingerprint.json(), "expected_installed" to jsonObject("package_name" to expected.packageName.json(), "version_code" to expected.versionCode.json(), "signing_cert_sha256" to expected.signingCertificate.json()),
                "release" to release.document.root, "session_id" to session.toLong().json(), "nonce" to nonce.json(), "phase" to AppInstallPhase.PREPARING.name.json(), "prepared_sha256" to JsonNull, "created_at_ms" to now.json(), "updated_at_ms" to now.json()))
        }
        fun parse(root: JsonObject): AppInstallationRecord {
            root.exactKeys("domain", "v", "installation_id", "owner", "update_deployment_sha256", "expected_installed", "release", "session_id", "nonce", "phase", "prepared_sha256", "created_at_ms", "updated_at_ms")
            if (root.string("domain") != DOMAIN) throw ProtocolException()
            root.integer("v", 1, 1); Contract.uuid(root.string("installation_id")); Contract.digest(root.string("update_deployment_sha256"))
            root.obj("owner").exactKeys("account_id", "organization_id", "deployment_sha256", "user_id", "device_id")
            root.obj("expected_installed").exactKeys("package_name", "version_code", "signing_cert_sha256")
            if (Contract.base64url(root.string("nonce")).size != 32 || root.string("phase") !in AppInstallPhase.entries.map { it.name }) throw ProtocolException()
            val parsed = AppInstallationRecord(JsonDocument.of(root))
            Contract.digest(parsed.expected.signingCertificate)
            if (parsed.release.packageName != parsed.expected.packageName || parsed.release.signingCertificate != parsed.expected.signingCertificate || parsed.release.versionCode <= parsed.expected.versionCode) throw ProtocolException()
            if (parsed.preparedSHA256 != null && parsed.preparedSHA256 != parsed.release.sha256 ||
                parsed.phase == AppInstallPhase.PREPARING && parsed.preparedSHA256 != null ||
                parsed.phase in setOf(AppInstallPhase.PREPARED, AppInstallPhase.COMMITTING, AppInstallPhase.WAITING_USER, AppInstallPhase.RESULT_REPORTED) && parsed.preparedSHA256 == null) throw ProtocolException()
            return parsed
        }
    }
}
