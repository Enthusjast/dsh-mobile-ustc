package cn.edu.ustc.dsh.auth

import cn.edu.ustc.dsh.protocol.*

/** Secret bytes for authenticated encryption only. Never a log, UI or SavedState value. */
fun LoginSession.authenticatedStorageBytes(): ByteArray = JsonDocument.of(jsonObject(
    "v" to 1L.json(), "deployment_sha256" to deploymentFingerprint.json(), "issuer" to issuer.json(), "subject" to subject.json(),
    "client_id" to clientId.json(), "proof_key_jkt" to proofKeyThumbprint.json(), "verified_at" to verifiedAt.json(), "access_expires_at" to accessExpiresAt.json(),
    "scopes" to JsonArray(scopes.sorted().map(String::json)), "access_token" to accessToken.json(), "refresh_token" to (refreshToken?.json() ?: JsonNull),
    "identity" to jsonObject("nonce" to identityNonce.json(), "audiences" to JsonArray(identityAudiences.sorted().map(String::json)),
        "azp" to (identityAuthorizedParty?.json() ?: JsonNull), "auth_time" to (authenticationTime?.json() ?: JsonNull)),
)).canonicalBytes()

object StoredLogin {
    /** Call only after AEAD authentication. Returned credentials cannot call resource APIs until reverified. */
    fun parseAuthenticated(raw: ByteArray, config: LoginConfiguration, proofJKT: String, now: Long): LoginSession = loginCheck(LoginFailure.IDENTITY) {
        val root = JsonDocument.parse(raw).root
        root.exactKeys("v", "deployment_sha256", "issuer", "subject", "client_id", "proof_key_jkt", "verified_at", "access_expires_at", "scopes", "access_token", "refresh_token", "identity")
        root.integer("v", 1, 1)
        if (root.string("deployment_sha256") != config.fingerprint || root.string("issuer") != config.issuer || root.string("client_id") != config.clientId || root.string("proof_key_jkt") != proofJKT || Contract.base64url(proofJKT).size != 32) invalid(LoginFailure.IDENTITY)
        val subject = Contract.boundedText(root.string("subject"), 2048)
        val verified = root.integer("verified_at", 0, 9_007_199_254_740_991)
        val expiry = root.integer("access_expires_at", 0, 9_007_199_254_740_991)
        if (verified > now || expiry <= verified || expiry - verified > 3_600_000) invalid(LoginFailure.EXPIRED)
        val scopes = LoginConfiguration.strings(root.array("scopes"), 64)
        scopes.forEach { Contract.boundedText(it, 128) }
        if (!scopes.containsAll(config.scopes - setOf("openid", "offline_access"))) invalid(LoginFailure.IDENTITY)
        fun credential(name: String): String = root.string(name).also { value -> if (value.length !in 1..64 * 1024 || value.any { it <= ' ' || it >= '\u007f' }) invalid(LoginFailure.IDENTITY) }
        val access = credential("access_token")
        val refresh = if (root["refresh_token"] == JsonNull) null else credential("refresh_token")
        val identity = root.obj("identity"); identity.exactKeys("nonce", "audiences", "azp", "auth_time")
        val nonce = identity.string("nonce")
        if (Contract.base64url(nonce).size != 32) invalid(LoginFailure.IDENTITY)
        val audiences = LoginConfiguration.strings(identity.array("audiences"), 32)
        if (config.clientId !in audiences) invalid(LoginFailure.IDENTITY)
        val azp = if (identity["azp"] == JsonNull) null else identity.string("azp")
        if (audiences.size > 1 && azp != config.clientId || azp != null && azp != config.clientId) invalid(LoginFailure.IDENTITY)
        val authenticationTime = if (identity["auth_time"] == JsonNull) null else identity.integer("auth_time", 0, verified / 1000 + 30)
        LoginSession(config.issuer, subject, config.clientId, proofJKT, expiry, scopes, access, refresh, verified, nonce, audiences, azp, authenticationTime, config.fingerprint, false, VerificationOrigin.STORED)
    }
}
