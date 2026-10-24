package cn.edu.ustc.dsh.auth

import cn.edu.ustc.dsh.protocol.*

enum class EnrollmentCheckpoint { PENDING, REGISTERING, ACTIVE }
enum class RefreshCheckpoint { READY, REFRESHING, REAUTHENTICATE }

/** Immutable secret-bearing state. Persist a transition before its corresponding network effect. */
class AccountCheckpoint private constructor(
    val accountId: String, val organizationId: String, val userId: String, val session: LoginSession,
    val approvalKeyJkt: String?, val enrollment: EnrollmentCheckpoint, val deviceId: String?, val deviceName: String?,
    val refresh: RefreshCheckpoint, val updatedAt: Long,
) {
    fun withApprovalKey(jkt: String, now: Long): AccountCheckpoint {
        thumbprint(jkt)
        if (jkt == session.proofKeyThumbprint || approvalKeyJkt != null && jkt != approvalKeyJkt) invalid(LoginFailure.IDENTITY)
        return change(now, approvalKeyJkt = jkt)
    }
    fun beginEnrollment(name: String, now: Long): AccountCheckpoint {
        if (approvalKeyJkt == null || enrollment != EnrollmentCheckpoint.PENDING || refresh != RefreshCheckpoint.READY) invalid(LoginFailure.CANCELLED)
        session.accessTokenForRequest(now)
        deviceName(name)
        if (deviceName != null && deviceName != name) invalid(LoginFailure.IDENTITY)
        return change(now, enrollment = EnrollmentCheckpoint.REGISTERING, deviceName = name)
    }
    fun enrollmentNotFound(now: Long): AccountCheckpoint {
        if (enrollment == EnrollmentCheckpoint.ACTIVE) invalid(LoginFailure.IDENTITY)
        return change(now, enrollment = EnrollmentCheckpoint.PENDING)
    }
    fun deviceAccepted(id: String, version: Long, now: Long): AccountCheckpoint {
        if (approvalKeyJkt == null || version != 1L || deviceId != null && deviceId != id) invalid(LoginFailure.IDENTITY)
        Contract.uuid(id)
        return change(now, enrollment = EnrollmentCheckpoint.ACTIVE, deviceId = id)
    }
    fun beginRefresh(now: Long): AccountCheckpoint {
        if (refresh != RefreshCheckpoint.READY || !session.hasRefreshToken()) invalid(LoginFailure.REAUTHENTICATION)
        return change(now, refresh = RefreshCheckpoint.REFRESHING)
    }
    fun requireReauthentication(now: Long): AccountCheckpoint = change(now, refresh = RefreshCheckpoint.REAUTHENTICATE)
    fun refreshed(verified: LoginSession, now: Long): AccountCheckpoint {
        if (refresh != RefreshCheckpoint.REFRESHING || verified.verificationOrigin != VerificationOrigin.REFRESH) invalid(LoginFailure.CANCELLED)
        return replaceSession(verified, userId, now)
    }
    fun authorized(verified: LoginSession, authoritativeUserId: String, now: Long): AccountCheckpoint {
        if (verified.verificationOrigin != VerificationOrigin.AUTHORIZATION_CODE) invalid(LoginFailure.IDENTITY)
        if (verified.identityNonce == session.identityNonce || verified.verifiedAt < updatedAt) invalid(LoginFailure.REAUTHENTICATION)
        return replaceSession(verified, authoritativeUserId, now)
    }
    fun revalidated(verified: LoginSession, authoritativeUserId: String, now: Long): AccountCheckpoint {
        if (refresh != RefreshCheckpoint.READY || verified.verificationOrigin != VerificationOrigin.CACHED_ACCESS) invalid(LoginFailure.REAUTHENTICATION)
        return replaceSession(verified, authoritativeUserId, now)
    }
    private fun replaceSession(verified: LoginSession, authoritativeUserId: String, now: Long): AccountCheckpoint {
        if (authoritativeUserId != userId || verified.issuer != session.issuer || verified.subject != session.subject ||
            verified.clientId != session.clientId || verified.deploymentFingerprint != session.deploymentFingerprint || verified.proofKeyThumbprint != session.proofKeyThumbprint) invalid(LoginFailure.IDENTITY)
        verified.accessTokenForRequest(now)
        return change(now, session = verified, refresh = RefreshCheckpoint.READY)
    }
    fun authenticatedStorageBytes(): ByteArray = JsonDocument.of(jsonObject(
        "v" to 1L.json(), "account_id" to accountId.json(), "organization_id" to organizationId.json(), "user_id" to userId.json(),
        "session" to JsonDocument.parse(session.authenticatedStorageBytes()).root, "approval_key_jkt" to (approvalKeyJkt?.json() ?: JsonNull),
        "enrollment" to enrollment.name.lowercase().json(), "device_id" to (deviceId?.json() ?: JsonNull), "device_name" to (deviceName?.json() ?: JsonNull),
        "refresh" to refresh.name.lowercase().json(), "updated_at" to updatedAt.json(),
    )).canonicalBytes()

    private fun change(now: Long, session: LoginSession = this.session, approvalKeyJkt: String? = this.approvalKeyJkt,
        enrollment: EnrollmentCheckpoint = this.enrollment, deviceId: String? = this.deviceId, deviceName: String? = this.deviceName, refresh: RefreshCheckpoint = this.refresh): AccountCheckpoint {
        if (now < updatedAt || now !in 0..9_007_199_254_740_991) invalid(LoginFailure.EXPIRED)
        return AccountCheckpoint(accountId, organizationId, userId, session, approvalKeyJkt, enrollment, deviceId, deviceName, refresh, now)
    }
    companion object {
        fun create(accountId: String, config: LoginConfiguration, userId: String, session: LoginSession, now: Long): AccountCheckpoint = loginCheck(LoginFailure.IDENTITY) {
            Contract.uuid(accountId); Contract.uuid(userId)
            if (session.deploymentFingerprint != config.fingerprint || session.verificationOrigin != VerificationOrigin.AUTHORIZATION_CODE) invalid(LoginFailure.IDENTITY)
            session.accessTokenForRequest(now)
            AccountCheckpoint(accountId, config.organizationId, userId, session, null, EnrollmentCheckpoint.PENDING, null, null, RefreshCheckpoint.READY, now)
        }
        /** Only authenticated vault plaintext may reach this method. No network effects occur while parsing. */
        fun parseAuthenticated(raw: ByteArray, config: LoginConfiguration, proofKeyJKT: String, now: Long, expectedAccountId: String): AccountCheckpoint = loginCheck(LoginFailure.IDENTITY) {
            val root = JsonDocument.parse(raw).root
            root.exactKeys("v", "account_id", "organization_id", "user_id", "session", "approval_key_jkt", "enrollment", "device_id", "device_name", "refresh", "updated_at")
            root.integer("v", 1, 1)
            val accountId = Contract.uuid(root.string("account_id")); val organization = Contract.uuid(root.string("organization_id")); val userId = Contract.uuid(root.string("user_id"))
            if (organization != config.organizationId || accountId != expectedAccountId) invalid(LoginFailure.IDENTITY)
            val session = StoredLogin.parseAuthenticated(JsonDocument.of(root.obj("session")).canonicalBytes(), config, proofKeyJKT, now)
            val approval = if (root["approval_key_jkt"] == JsonNull) null else root.string("approval_key_jkt").also(::thumbprint)
            if (approval == proofKeyJKT) invalid(LoginFailure.IDENTITY)
            val enrollment = EnrollmentCheckpoint.entries.firstOrNull { it.name.lowercase() == root.string("enrollment") } ?: invalid(LoginFailure.IDENTITY)
            val refresh = RefreshCheckpoint.entries.firstOrNull { it.name.lowercase() == root.string("refresh") } ?: invalid(LoginFailure.IDENTITY)
            val deviceId = if (root["device_id"] == JsonNull) null else Contract.uuid(root.string("device_id"))
            val name = if (root["device_name"] == JsonNull) null else root.string("device_name").also(::deviceName)
            val updated = root.integer("updated_at", session.verifiedAt, 9_007_199_254_740_991)
            if (updated > now) invalid(LoginFailure.EXPIRED)
            if ((enrollment == EnrollmentCheckpoint.ACTIVE) != (deviceId != null) || enrollment != EnrollmentCheckpoint.PENDING && approval == null ||
                name != null && approval == null || enrollment == EnrollmentCheckpoint.REGISTERING && name == null || refresh == RefreshCheckpoint.REFRESHING && !session.hasRefreshToken()) invalid(LoginFailure.IDENTITY)
            AccountCheckpoint(accountId, organization, userId, session, approval, enrollment, deviceId, name, refresh, updated)
        }
        private fun thumbprint(value: String) { if (Contract.base64url(value).size != 32) invalid(LoginFailure.IDENTITY) }
        private fun deviceName(value: String) { Contract.boundedText(value, 160); if (value != value.trim()) invalid(LoginFailure.IDENTITY) }
    }
}
