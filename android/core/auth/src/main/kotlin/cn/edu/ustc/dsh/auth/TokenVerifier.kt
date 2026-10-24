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

/** Secret-bearing session values are never placed in Compose/SavedState or log messages. */
class LoginSession internal constructor(
    val issuer: String, val subject: String, val clientId: String, val proofKeyThumbprint: String,
    val accessExpiresAt: Long, val scopes: Set<String>, private val accessToken: String, private val refreshToken: String?,
) {
    fun accessTokenForRequest(now: Long): String {
        if (now < 0 || now >= accessExpiresAt) invalid(LoginFailure.EXPIRED)
        return accessToken
    }
    fun refreshTokenForRequest(): String? = refreshToken
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
            java.util.Collections.unmodifiableSet(scopes), access, refresh)
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
