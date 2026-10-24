package cn.edu.ustc.dsh.auth

import cn.edu.ustc.dsh.crypto.DeviceProofs
import cn.edu.ustc.dsh.protocol.*
import java.net.URI
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest

enum class LoginFailure { CONFIGURATION, INVALID_RESPONSE, EXPIRED, CANCELLED, IDENTITY, REAUTHENTICATION, UNAVAILABLE }
class LoginException(val failure: LoginFailure) : IllegalArgumentException("login: ${failure.name.lowercase()}")

/** Public deployment configuration is provisioned with the app, never from an OAuth callback. */
class LoginConfiguration private constructor(
    val issuer: String, val clientId: String, val redirectUri: String, val resource: String,
    val audience: String, val remoteOrigin: String, val organizationId: String,
    val scopes: Set<String>, val endpointOrigins: Set<String>, val signingAlgorithms: Set<String>,
    val fingerprint: String,
) {
    companion object {
        const val REDIRECT_URI = "cn.edu.ustc.dsh.mobile:/oauth2redirect"
        fun parse(raw: ByteArray): LoginConfiguration = loginCheck(LoginFailure.CONFIGURATION) {
            val root = JsonDocument.parse(raw).root
            root.exactKeys("issuer", "client_id", "redirect_uri", "resource", "audience", "remote_origin", "organization_id", "scopes", "endpoint_origins", "signing_algorithms")
            val issuer = https(root.string("issuer"), false)
            val origins = strings(root.array("endpoint_origins"), 8).onEach { if (origin(https(it, false)) != it) invalid(LoginFailure.CONFIGURATION) }
            if (origin(issuer) !in origins || root.string("redirect_uri") != REDIRECT_URI) invalid(LoginFailure.CONFIGURATION)
            val remote = https(root.string("remote_origin"), false)
            if (origin(remote) != remote) invalid(LoginFailure.CONFIGURATION)
            val resource = root.string("resource")
            val resourceUri = URI(resource)
            if (!resourceUri.isAbsolute || resourceUri.fragment != null || resource.any { it <= ' ' || it >= '\u007f' }) invalid(LoginFailure.CONFIGURATION)
            val algorithms = strings(root.array("signing_algorithms"), 2)
            if (algorithms.isEmpty() || !setOf("RS256", "ES256").containsAll(algorithms)) invalid(LoginFailure.CONFIGURATION)
            val scopes = strings(root.array("scopes"), 32)
            if ("openid" !in scopes || scopes.none { it != "openid" && it != "offline_access" } || scopes.any { !Regex("[\\x21\\x23-\\x5b\\x5d-\\x7e]{1,128}").matches(it) }) invalid(LoginFailure.CONFIGURATION)
            LoginConfiguration(issuer, Contract.boundedText(root.string("client_id"), 256), REDIRECT_URI, resource,
                Contract.boundedText(root.string("audience"), 512), remote, Contract.uuid(root.string("organization_id")), scopes, origins, algorithms, JsonDocument.of(root).sha256())
        }
        internal fun strings(values: List<JsonValue>, max: Int): Set<String> {
            val strings = values.map { (it as? JsonString)?.value ?: invalid(LoginFailure.CONFIGURATION) }
            if (strings.size > max || strings.toSet().size != strings.size || strings.any { it.isEmpty() }) invalid(LoginFailure.CONFIGURATION)
            return java.util.Collections.unmodifiableSet(LinkedHashSet(strings))
        }
    }
}

class OidcDiscovery private constructor(
    val configuration: LoginConfiguration, val authorizationEndpoint: String, val tokenEndpoint: String, val jwksUri: String,
    val responseIssuerRequired: Boolean,
    val refreshAllowed: Boolean,
) {
    companion object {
        fun parse(raw: ByteArray, configuration: LoginConfiguration): OidcDiscovery = loginCheck(LoginFailure.CONFIGURATION) {
            val root = JsonDocument.parse(raw).root
            if (root.string("issuer") != configuration.issuer) invalid(LoginFailure.CONFIGURATION)
            fun endpoint(name: String, queryAllowed: Boolean): String = https(root.string(name), queryAllowed).also {
                if (origin(it) !in configuration.endpointOrigins) invalid(LoginFailure.CONFIGURATION)
            }
            fun supports(name: String, required: String, mandatory: Boolean = false) {
                if (name !in root.fields) { if (mandatory) invalid(LoginFailure.CONFIGURATION); return }
                if (required !in LoginConfiguration.strings(root.array(name), 64)) invalid(LoginFailure.CONFIGURATION)
            }
            supports("response_types_supported", "code", true)
            supports("code_challenge_methods_supported", "S256")
            supports("dpop_signing_alg_values_supported", "ES256")
            supports("token_endpoint_auth_methods_supported", "none")
            supports("grant_types_supported", "authorization_code")
            val advertised = LoginConfiguration.strings(root.array("id_token_signing_alg_values_supported"), 32)
            if (!advertised.containsAll(configuration.signingAlgorithms)) invalid(LoginFailure.CONFIGURATION)
            val responseIssuer = root.fields["authorization_response_iss_parameter_supported"]
            if (responseIssuer != null && responseIssuer !is JsonBoolean) invalid(LoginFailure.CONFIGURATION)
            val authorization = endpoint("authorization_endpoint", true)
            val token = endpoint("token_endpoint", true)
            fun noReservedQuery(url: String, reserved: Set<String>) {
                val seen = hashSetOf<String>()
                URI(url).rawQuery?.split('&')?.forEach { part ->
                    val name = decodeParameter(part.substringBefore('='))
                    if (name in reserved || !seen.add(name)) invalid(LoginFailure.CONFIGURATION)
                }
            }
            noReservedQuery(authorization, setOf("response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "resource", "dpop_jkt"))
            noReservedQuery(token, setOf("grant_type", "client_id", "redirect_uri", "code", "code_verifier", "resource", "refresh_token"))
            val refreshAllowed = "grant_types_supported" !in root.fields || "refresh_token" in LoginConfiguration.strings(root.array("grant_types_supported"), 64)
            OidcDiscovery(configuration, authorization, token, endpoint("jwks_uri", true), responseIssuer == JsonBoolean(true), refreshAllowed)
        }
    }
}

/** In-memory, single-use PKCE transaction. Never parcel verifier/code/token into UI state. */
class PendingLogin(val discovery: OidcDiscovery, val proofKeyThumbprint: String, val startedAt: Long) {
    val state: String = DeviceProofs.randomId()
    val nonce: String = DeviceProofs.randomId()
    private val verifier: String = DeviceProofs.randomId()
    private var ended = false
    private var lastTime = startedAt
    val codeChallenge: String = Contract.base64url(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)))
    init { if (startedAt < 0 || Contract.base64url(proofKeyThumbprint).size != 32) invalid(LoginFailure.CONFIGURATION) }

    fun authorizationParameters(): Map<String, String> = mapOf(
        "response_type" to "code", "client_id" to discovery.configuration.clientId, "redirect_uri" to discovery.configuration.redirectUri,
        "scope" to discovery.configuration.scopes.sorted().joinToString(" "), "state" to state, "nonce" to nonce,
        "code_challenge" to codeChallenge, "code_challenge_method" to "S256", "resource" to discovery.configuration.resource, "dpop_jkt" to proofKeyThumbprint,
    )

    /** For the trusted authorization SDK adapter only; never an Intent extra or SavedState value. */
    fun verifierForAuthorizationRequest(): String = verifier

    @Synchronized
    fun acceptCallback(uriText: String, now: Long): CodeExchange = loginCheck(LoginFailure.INVALID_RESPONSE) {
        ensureCurrent(now)
        val uri = URI(uriText)
        val expected = URI(discovery.configuration.redirectUri)
        if (uriText.length > 16 * 1024 || uri.scheme != expected.scheme || uri.rawAuthority != expected.rawAuthority || uri.rawPath != expected.rawPath || uri.rawFragment != null || uri.rawQuery.isNullOrEmpty()) invalid(LoginFailure.INVALID_RESPONSE)
        val parameters = linkedMapOf<String, String>()
        for (part in uri.rawQuery.split('&')) {
            val split = part.split('=', limit = 2)
            if (split.size != 2 || split[0].isEmpty()) invalid(LoginFailure.INVALID_RESPONSE)
            val name = decodeParameter(split[0])
            val value = decodeParameter(split[1])
            requireText(name); requireText(value)
            if (parameters.put(name, value) != null) invalid(LoginFailure.INVALID_RESPONSE)
        }
        if (!MessageDigest.isEqual(parameters["state"]?.toByteArray(Charsets.UTF_8) ?: byteArrayOf(), state.toByteArray(Charsets.US_ASCII))) invalid(LoginFailure.INVALID_RESPONSE)
        if ((discovery.responseIssuerRequired || "iss" in parameters) && parameters["iss"] != discovery.configuration.issuer) invalid(LoginFailure.IDENTITY)
        if (parameters.keys.any { it !in setOf("code", "state", "iss", "error", "error_description", "error_uri", "session_state") }) invalid(LoginFailure.INVALID_RESPONSE)
        if ("error" in parameters) { ended = true; invalid(LoginFailure.CANCELLED) }
        val code = parameters["code"] ?: invalid(LoginFailure.INVALID_RESPONSE)
        Contract.boundedText(code, 8192)
        if (code.any { it !in '!'..'~' }) invalid(LoginFailure.INVALID_RESPONSE)
        ended = true
        CodeExchange(this, code, verifier, now)
    }

    @Synchronized fun cancel() { ended = true }
    private fun ensureCurrent(now: Long) {
        if (ended) invalid(LoginFailure.CANCELLED)
        if (now < lastTime || now - startedAt !in 0..600_000) { ended = true; invalid(LoginFailure.EXPIRED) }
        lastTime = now
    }
}

class CodeExchange internal constructor(val login: PendingLogin, private val code: String, private val verifier: String, val callbackAt: Long) {
    fun form(): Map<String, String> = mapOf("grant_type" to "authorization_code", "client_id" to login.discovery.configuration.clientId,
        "redirect_uri" to login.discovery.configuration.redirectUri, "code" to code, "code_verifier" to verifier, "resource" to login.discovery.configuration.resource)
    internal fun codeHash(): String = halfHash(code)
}

internal fun halfHash(text: String): String = Contract.base64url(MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.US_ASCII)).copyOfRange(0, 16))
private fun decodeParameter(value: String): String {
    val bytes = ByteArrayOutputStream()
    var index = 0
    while (index < value.length) {
        val char = value[index++]
        when {
            char == '%' -> {
                if (index + 1 >= value.length) invalid(LoginFailure.INVALID_RESPONSE)
                val high = value[index++].digitToIntOrNull(16) ?: invalid(LoginFailure.INVALID_RESPONSE)
                val low = value[index++].digitToIntOrNull(16) ?: invalid(LoginFailure.INVALID_RESPONSE)
                bytes.write(high * 16 + low)
            }
            char == '+' -> bytes.write(32)
            char.code in 0x21..0x7e -> bytes.write(char.code)
            else -> invalid(LoginFailure.INVALID_RESPONSE)
        }
    }
    return Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes.toByteArray())).toString()
}
internal fun https(value: String, queryAllowed: Boolean): String {
    val uri = URI(value)
    if (value.length > 2048 || uri.scheme != "https" || uri.host.isNullOrEmpty() || uri.rawUserInfo != null || uri.rawFragment != null || (!queryAllowed && uri.rawQuery != null) || value.any { it <= ' ' || it >= '\u007f' } || uri.port !in -1..65535) invalid(LoginFailure.CONFIGURATION)
    return value
}
internal fun origin(value: String): String = URI(value).let { "${it.scheme}://${it.rawAuthority}" }
internal fun invalid(failure: LoginFailure): Nothing = throw LoginException(failure)
internal inline fun <T> loginCheck(failure: LoginFailure, block: () -> T): T = try { block() } catch (error: LoginException) { throw error } catch (_: Exception) { invalid(failure) }
