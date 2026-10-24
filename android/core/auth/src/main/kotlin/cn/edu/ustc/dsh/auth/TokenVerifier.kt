package cn.edu.ustc.dsh.auth

import cn.edu.ustc.dsh.protocol.*
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import java.security.MessageDigest

/** Download only from the already validated discovery's JWKS URI, with bounded HTTPS transport. */
class IssuerKeys private constructor(private val keys: List<JWK>) {
    internal fun verify(compact: String, header: JsonObject): Boolean {
        val alg = header.string("alg"); val kid = header.string("kid")
        val matching = keys.filter { it.keyID == kid && (it.algorithm == null || it.algorithm.name == alg) &&
            ((alg == "ES256" && it is ECKey) || (alg == "RS256" && it is RSAKey)) }
        if (matching.size != 1) return false
        val verifier = when (val key = matching.single()) {
            is ECKey -> ECDSAVerifier(key)
            is RSAKey -> RSASSAVerifier(key)
            else -> return false
        }
        return JWSObject.parse(compact).verify(verifier)
    }

    companion object {
        fun parse(raw: ByteArray): IssuerKeys = loginCheck(LoginFailure.IDENTITY) {
            val root = JsonDocument.parse(raw).root
            root.exactKeys("keys")
            val values = root.array("keys")
            if (values.isEmpty() || values.size > 32) invalid(LoginFailure.IDENTITY)
            val keys = values.mapNotNull { value ->
                val item = value as? JsonObject ?: invalid(LoginFailure.IDENTITY)
                if (item.fields.keys.any { it in setOf("d", "p", "q", "dp", "dq", "qi", "oth", "k") }) invalid(LoginFailure.IDENTITY)
                if (item.fields["use"]?.let { it != "sig".json() } == true) return@mapNotNull null
                if ("key_ops" in item.fields && item.array("key_ops") != listOf("verify".json())) return@mapNotNull null
                if (item.fields["alg"]?.let { it !in listOf("RS256".json(), "ES256".json()) } == true) return@mapNotNull null
                if (item.string("kty") !in setOf("RSA", "EC")) return@mapNotNull null
                val key = JWK.parse(JsonDocument.of(item).canonicalText())
                if (key.isPrivate || key.keyID.isNullOrEmpty() || key.keyID.toByteArray(Charsets.UTF_8).size > 256) invalid(LoginFailure.IDENTITY)
                when (key) {
                    is ECKey -> if (key.curve.name != "P-256") return@mapNotNull null
                    is RSAKey -> if (key.size() !in 2048..8192) invalid(LoginFailure.IDENTITY)
                }
                key
            }
            if (keys.isEmpty()) invalid(LoginFailure.IDENTITY)
            IssuerKeys(keys)
        }
    }
}

internal enum class VerificationOrigin { AUTHORIZATION_CODE, REFRESH, CACHED_ACCESS, STORED }

/** Secret-bearing session values are never placed in Compose/SavedState or log messages. */
class LoginSession internal constructor(
    val issuer: String, val subject: String, val clientId: String, val proofKeyThumbprint: String,
    val accessExpiresAt: Long, val scopes: Set<String>, internal val accessToken: String, internal val refreshToken: String?,
    val verifiedAt: Long, internal val identityNonce: String, internal val identityAudiences: Set<String>,
    internal val identityAuthorizedParty: String?, internal val authenticationTime: Long?, val deploymentFingerprint: String,
    private val resourceValidated: Boolean = true, internal val verificationOrigin: VerificationOrigin = VerificationOrigin.AUTHORIZATION_CODE,
) {
    private val refreshSpent = java.util.concurrent.atomic.AtomicBoolean()
    fun accessTokenForRequest(now: Long): String {
        if (!resourceValidated) invalid(LoginFailure.IDENTITY)
        if (now < verifiedAt || now >= accessExpiresAt) invalid(LoginFailure.EXPIRED)
        return accessToken
    }
    fun hasRefreshToken(): Boolean = refreshToken != null
    /** The caller commits its durable in-flight marker first. Failed exchanges cannot reuse this instance. */
    fun consumeRefreshTokenForRequest(): String {
        if (refreshToken == null || !refreshSpent.compareAndSet(false, true)) invalid(LoginFailure.REAUTHENTICATION)
        return refreshToken
    }
}

object TokenVerifier {
    fun authorizationCodeResponse(raw: ByteArray, exchange: CodeExchange, keys: IssuerKeys, now: Long): LoginSession = loginCheck(LoginFailure.IDENTITY) {
        val login = exchange.login; val config = login.discovery.configuration
        if (now < exchange.callbackAt || now - login.startedAt > 600_000) invalid(LoginFailure.EXPIRED)
        val response = JsonDocument.parse(raw).root
        if ("error" in response.fields) invalid(LoginFailure.IDENTITY)
        val access = token(response.string("access_token"))
        val idToken = token(response.string("id_token"))
        if (!response.string("token_type").equals("DPoP", true)) invalid(LoginFailure.IDENTITY)
        val expiresIn = response.integer("expires_in", 1, 3600)
        val id = jwt(idToken, config, keys, false)
        val claims = jwt(access, config, keys, true)
        val idSubject = identity(id, config.issuer)
        val accessSubject = identity(claims, config.issuer)
        if (idSubject != accessSubject || !audience(id, config.clientId) || !audience(claims, config.audience) || claims.string("client_id") != config.clientId) invalid(LoginFailure.IDENTITY)
        val idAudienceCount = if (id["aud"] is JsonArray) id.array("aud").size else 1
        if ((idAudienceCount > 1 || "azp" in id.fields) && id.string("azp") != config.clientId) invalid(LoginFailure.IDENTITY)
        if (!constantEqual(id.string("nonce"), login.nonce)) invalid(LoginFailure.IDENTITY)
        if ("at_hash" in id.fields && !constantEqual(id.string("at_hash"), halfHash(access))) invalid(LoginFailure.IDENTITY)
        if ("c_hash" in id.fields && !constantEqual(id.string("c_hash"), exchange.codeHash())) invalid(LoginFailure.IDENTITY)
        times(id, now, login.startedAt, 86_400)
        val accessExpiry = times(claims, now, login.startedAt, 3600)
        if ("auth_time" in id.fields && id.integer("auth_time", 0) > now / 1000 + 30) invalid(LoginFailure.IDENTITY)
        Contract.boundedText(claims.string("jti"), 256)
        val cnf = claims.obj("cnf"); cnf.exactKeys("jkt")
        if (!constantEqual(cnf.string("jkt"), login.proofKeyThumbprint)) invalid(LoginFailure.IDENTITY)
        val scopes = scopes(claims.string("scope"))
        val required = config.scopes - setOf("openid", "offline_access")
        if (!scopes.containsAll(required)) invalid(LoginFailure.IDENTITY)
        if ("scope" in response.fields && !scopes(response.string("scope")).containsAll(config.scopes)) invalid(LoginFailure.IDENTITY)
        val refresh = response.fields["refresh_token"]?.let { token((it as? JsonString)?.value ?: invalid(LoginFailure.IDENTITY)) }
        // The signed JWT deadline and the token response deadline both constrain use.
        val deadline = minOf(accessExpiry, exchange.callbackAt + expiresIn * 1000)
        if (deadline <= now) invalid(LoginFailure.EXPIRED)
        LoginSession(config.issuer, idSubject, config.clientId, login.proofKeyThumbprint, deadline,
            java.util.Collections.unmodifiableSet(scopes), access, refresh, now, login.nonce, audiences(id),
            (id.fields["azp"] as? JsonString)?.value, if ("auth_time" in id.fields) id.integer("auth_time", 0) else null, config.fingerprint)
    }

    /** A decrypted snapshot alone cannot authorize resource calls. Reverify its access JWT first. */
    fun revalidateStored(previous: LoginSession, config: LoginConfiguration, keys: IssuerKeys, now: Long): LoginSession = loginCheck(LoginFailure.IDENTITY) {
        if (previous.issuer != config.issuer || previous.clientId != config.clientId || previous.deploymentFingerprint != config.fingerprint) invalid(LoginFailure.IDENTITY)
        if (now < previous.verifiedAt || now >= previous.accessExpiresAt) invalid(LoginFailure.EXPIRED)
        val claims = verifiedAccess(previous.accessToken, config, keys, previous.subject, previous.proofKeyThumbprint, now, 0)
        if (scopes(claims.string("scope")) != previous.scopes || previous.accessExpiresAt > claims.integer("exp", 0, Long.MAX_VALUE / 1000) * 1000) invalid(LoginFailure.IDENTITY)
        copy(previous, previous.accessToken, previous.refreshToken, previous.accessExpiresAt, previous.scopes, now, VerificationOrigin.CACHED_ACCESS)
    }

    /** ID tokens are optional during refresh. Any returned one must preserve the original OIDC identity. */
    fun refreshResponse(raw: ByteArray, previous: LoginSession, config: LoginConfiguration, keys: IssuerKeys, requestedAt: Long, now: Long): LoginSession = loginCheck(LoginFailure.IDENTITY) {
        if (previous.issuer != config.issuer || previous.clientId != config.clientId || previous.deploymentFingerprint != config.fingerprint) invalid(LoginFailure.IDENTITY)
        if (requestedAt < previous.verifiedAt || now < requestedAt || now - requestedAt > 120_000) invalid(LoginFailure.EXPIRED)
        val response = JsonDocument.parse(raw).root
        if ("error" in response.fields || !response.string("token_type").equals("DPoP", true)) invalid(LoginFailure.IDENTITY)
        val access = token(response.string("access_token"))
        val claims = verifiedAccess(access, config, keys, previous.subject, previous.proofKeyThumbprint, now, requestedAt)
        val granted = scopes(claims.string("scope"))
        if (!previous.scopes.containsAll(granted)) invalid(LoginFailure.IDENTITY)
        if ("scope" in response.fields) {
            val returned = scopes(response.string("scope"))
            if (!returned.containsAll(config.scopes - setOf("openid", "offline_access")) || !(config.scopes + previous.scopes).containsAll(returned)) invalid(LoginFailure.IDENTITY)
        }
        if ("id_token" in response.fields) {
            val id = jwt(token(response.string("id_token")), config, keys, false)
            if (identity(id, previous.issuer) != previous.subject || audiences(id) != previous.identityAudiences) invalid(LoginFailure.IDENTITY)
            val azp = (id.fields["azp"] as? JsonString)?.value
            if (audiences(id).size > 1 && azp != previous.clientId || "azp" in id.fields && (azp == null || azp != previous.identityAuthorizedParty)) invalid(LoginFailure.IDENTITY)
            if ("auth_time" in id.fields && id.integer("auth_time", 0) != previous.authenticationTime) invalid(LoginFailure.IDENTITY)
            if ("nonce" in id.fields && !constantEqual(id.string("nonce"), previous.identityNonce)) invalid(LoginFailure.IDENTITY)
            if ("at_hash" in id.fields && !constantEqual(id.string("at_hash"), halfHash(access))) invalid(LoginFailure.IDENTITY)
            if ("c_hash" in id.fields) invalid(LoginFailure.IDENTITY)
            times(id, now, requestedAt, 86_400)
        }
        val refresh = if ("refresh_token" in response.fields) token(response.string("refresh_token")) else previous.refreshToken
        val expiry = minOf(claims.integer("exp", 0, Long.MAX_VALUE / 1000) * 1000, requestedAt + response.integer("expires_in", 1, 3600) * 1000)
        if (expiry <= now) invalid(LoginFailure.EXPIRED)
        copy(previous, access, refresh, expiry, java.util.Collections.unmodifiableSet(granted), now, VerificationOrigin.REFRESH)
    }

    private fun copy(previous: LoginSession, access: String, refresh: String?, expiry: Long, scopes: Set<String>, now: Long, origin: VerificationOrigin) = LoginSession(
        previous.issuer, previous.subject, previous.clientId, previous.proofKeyThumbprint, expiry, scopes, access, refresh, now,
        previous.identityNonce, previous.identityAudiences, previous.identityAuthorizedParty, previous.authenticationTime, previous.deploymentFingerprint, true, origin,
    )

    private fun verifiedAccess(access: String, config: LoginConfiguration, keys: IssuerKeys, subject: String, proofJKT: String, now: Long, issuedFloor: Long): JsonObject {
        val claims = jwt(access, config, keys, true)
        if (identity(claims, config.issuer) != subject || !audience(claims, config.audience) || claims.string("client_id") != config.clientId) invalid(LoginFailure.IDENTITY)
        times(claims, now, issuedFloor, 3600)
        Contract.boundedText(claims.string("jti"), 256)
        val cnf = claims.obj("cnf"); cnf.exactKeys("jkt")
        if (!constantEqual(cnf.string("jkt"), proofJKT) || !scopes(claims.string("scope")).containsAll(config.scopes - setOf("openid", "offline_access"))) invalid(LoginFailure.IDENTITY)
        return claims
    }

    private fun token(value: String): String = value.also { if (it.length !in 1..64 * 1024 || it.any { c -> c <= ' ' || c >= '\u007f' }) invalid(LoginFailure.IDENTITY) }
    private fun jwt(compact: String, config: LoginConfiguration, keys: IssuerKeys, access: Boolean): JsonObject {
        val parts = compact.split('.')
        if (parts.size != 3) invalid(LoginFailure.IDENTITY)
        val bytes = parts.map { Contract.base64url(it) }
        val header = JsonDocument.parse(bytes[0]).root
        if (header.fields.keys.any { it !in setOf("alg", "kid", "typ") } || header.string("alg") !in config.signingAlgorithms) invalid(LoginFailure.IDENTITY)
        Contract.boundedText(header.string("kid"), 256)
        val typ = (header.fields["typ"] as? JsonString)?.value
        if (access && typ?.lowercase() !in setOf("at+jwt", "application/at+jwt")) invalid(LoginFailure.IDENTITY)
        if (!access && "typ" in header.fields && typ?.lowercase() !in setOf("jwt", "application/jwt")) invalid(LoginFailure.IDENTITY)
        if (!keys.verify(compact, header)) invalid(LoginFailure.IDENTITY)
        return JsonDocument.parse(bytes[1]).root
    }
    private fun identity(root: JsonObject, issuer: String): String {
        if (root.string("iss") != issuer) invalid(LoginFailure.IDENTITY)
        return Contract.boundedText(root.string("sub"), 2048)
    }
    private fun audience(root: JsonObject, expected: String): Boolean = when (val aud = root["aud"]) {
        is JsonString -> aud.value == expected
        is JsonArray -> {
            val values = LoginConfiguration.strings(aud.values, 32)
            expected in values
        }
        else -> false
    }
    private fun audiences(root: JsonObject): Set<String> = when (val value = root["aud"]) {
        is JsonString -> setOf(Contract.boundedText(value.value, 512))
        is JsonArray -> LoginConfiguration.strings(value.values, 32)
        else -> invalid(LoginFailure.IDENTITY)
    }
    private fun times(root: JsonObject, now: Long, startedAt: Long, maxLifetime: Long): Long {
        val issued = root.integer("iat", 0, Long.MAX_VALUE / 1000)
        val expires = root.integer("exp", 0, Long.MAX_VALUE / 1000)
        val seconds = now / 1000
        if (issued > seconds + 30 || issued < startedAt / 1000 - 30 || expires <= seconds || expires <= issued || expires - issued > maxLifetime) invalid(LoginFailure.IDENTITY)
        if ("nbf" in root.fields && root.integer("nbf", 0) > seconds + 30) invalid(LoginFailure.IDENTITY)
        return expires * 1000
    }
    private fun scopes(value: String): LinkedHashSet<String> {
        Contract.boundedText(value, 4096)
        val values = value.split(' ').filter { it.isNotEmpty() }
        if (values.size > 64) invalid(LoginFailure.IDENTITY)
        return LinkedHashSet(values)
    }
    private fun constantEqual(a: String, b: String): Boolean = MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))
}
