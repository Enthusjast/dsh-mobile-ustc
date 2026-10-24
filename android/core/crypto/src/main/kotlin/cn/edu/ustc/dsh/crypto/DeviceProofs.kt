package cn.edu.ustc.dsh.crypto

import cn.edu.ustc.dsh.protocol.*
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64URL
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom

class DeviceProofException : IllegalArgumentException("device proof: invalid value")

class PublicProofKey(jwk: JsonObject) {
    val document: JsonDocument
    internal val key: ECKey
    val thumbprint: String
    init {
        try {
            jwk.exactKeys("kty", "crv", "x", "y")
            if (jwk.string("kty") != "EC" || jwk.string("crv") != "P-256") throw DeviceProofException()
            for (name in listOf("x", "y")) if (jwk.string(name).length != 43 || Contract.base64url(jwk.string(name)).size != 32) throw DeviceProofException()
            document = JsonDocument.of(jwk)
            key = ECKey.parse(document.canonicalText())
            thumbprint = key.computeThumbprint().toString()
        } catch (_: Exception) { throw DeviceProofException() }
    }
}

/** Implementations keep the private proof key in their platform provider. */
interface DeviceProofSigner {
    val publicKey: PublicProofKey
    fun signJose(signingInput: ByteArray): ByteArray
}

class DpopProof internal constructor(val compact: String, val jti: String)

object DeviceProofs {
    private val random = SecureRandom()
    fun randomId(): String = Contract.base64url(ByteArray(32).also(random::nextBytes))

    /** Pass the actual HTTP client's normalized request URL; query/fragment are excluded by RFC 9449. */
    fun dpop(signer: DeviceProofSigner, method: String, requestUrl: String, now: Long, nonce: String? = null, accessToken: String? = null, jti: String = randomId()): DpopProof = proofCheck {
        if (!Regex("[A-Z][A-Z0-9_-]{0,31}").matches(method) || now < 0) throw DeviceProofException()
        val uri = URI(requestUrl)
        if (uri.scheme != "https" || uri.host.isNullOrEmpty() || uri.rawUserInfo != null || uri.port !in -1..65535 || uri.rawAuthority.any { it <= ' ' || it >= '\u007f' }) throw DeviceProofException()
        val htu = "https://${uri.rawAuthority}${uri.rawPath.ifEmpty { "/" }}"
        val claims = linkedMapOf<String, JsonValue>("htm" to method.json(), "htu" to htu.json(), "iat" to (now / 1000).json(), "jti" to proofId(jti).json())
        if (nonce != null) claims["nonce"] = nonce(nonce).json()
        if (accessToken != null) {
            if (accessToken.isEmpty() || accessToken.length > 64 * 1024 || accessToken.any { it <= ' ' || it >= '\u007f' }) throw DeviceProofException()
            claims["ath"] = hash(accessToken).json()
        }
        val header = jsonObject("alg" to "ES256".json(), "typ" to "dpop+jwt".json(), "jwk" to signer.publicKey.document.root)
        val input = compactInput(header, JsonObject(claims))
        DpopProof(finish(input, signer.signJose(input.toByteArray(Charsets.US_ASCII)), signer.publicKey), jti)
    }

    fun nonce(value: String): String = value.also { if (it.length !in 1..256 || it.any { c -> c !in '!'..'~' }) throw DeviceProofException() }
    internal fun proofId(value: String): String = Contract.boundedText(value, 256).also { if (it.length < 16) throw DeviceProofException() }
    internal fun hash(value: String): String = Contract.base64url(MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)))
    internal fun compactInput(header: JsonObject, claims: JsonObject): String = "${Contract.base64url(JsonDocument.of(header).canonicalBytes())}.${Contract.base64url(JsonDocument.of(claims).canonicalBytes())}"
    internal fun finish(input: String, signature: ByteArray, key: PublicProofKey): String {
        if (signature.size != 64 || !ECDSAVerifier(key.key).verify(JWSHeader(JWSAlgorithm.ES256), input.toByteArray(Charsets.US_ASCII), Base64URL.encode(signature))) throw DeviceProofException()
        return "$input.${Contract.base64url(signature)}"
    }
}

/** Only the library's immutable, purpose-specific requests can use this API. */
sealed interface PreparedUserSignature<T> {
    val keyThumbprint: String
    fun signingInput(): ByteArray
    fun finishDerSignature(der: ByteArray, now: Long): T
    fun cancel()
}

class DeviceRegistrationProof internal constructor(val compact: String, val dpopJti: String)

class PreparedDeviceRegistration private constructor(
    private val input: String, private val key: PublicProofKey, private val issuedAt: Long, private val dpopJti: String,
) : PreparedUserSignature<DeviceRegistrationProof> {
    private var ended = false
    override val keyThumbprint: String get() = key.thumbprint
    override fun signingInput(): ByteArray = input.toByteArray(Charsets.US_ASCII)
    @Synchronized override fun finishDerSignature(der: ByteArray, now: Long): DeviceRegistrationProof = proofCheck {
        if (ended) throw DeviceProofException()
        ended = true
        if (now < issuedAt || now - issuedAt > 30_000) throw DeviceProofException()
        DeviceRegistrationProof(DeviceProofs.finish(input, ECDSA.transcodeSignatureToConcat(der.copyOf(), 64), key), dpopJti)
    }
    @Synchronized override fun cancel() { ended = true }

    companion object {
        fun prepare(issuer: String, subject: String, name: String, approvalKey: PublicProofKey, proofKey: PublicProofKey, dpopJti: String, now: Long): PreparedDeviceRegistration = proofCheck {
            val url = URI(issuer)
            if (url.scheme != "https" || url.host.isNullOrEmpty() || url.rawUserInfo != null || url.rawQuery != null || url.rawFragment != null || now < 0 || approvalKey.thumbprint == proofKey.thumbprint) throw DeviceProofException()
            Contract.boundedText(subject, 2048)
            if (name != name.trim() || name.isEmpty() || name.toByteArray(Charsets.UTF_8).size > 160) throw DeviceProofException()
            Contract.boundedText(name, 160)
            val claims = jsonObject(
                "iss" to issuer.json(), "sub" to subject.json(), "aud" to "urn:dsh-mobile-ustc:device-registration".json(),
                "iat" to (now / 1000).json(), "jti" to DeviceProofs.randomId().json(),
                "approval_key_jkt" to approvalKey.thumbprint.json(), "proof_key_jkt" to proofKey.thumbprint.json(),
                "device_name_sha256" to DeviceProofs.hash(name).json(), "dpop_jti" to DeviceProofs.proofId(dpopJti).json(),
            )
            val input = DeviceProofs.compactInput(jsonObject("alg" to "ES256".json(), "typ" to "dsh-device-registration-proof+jwt".json()), claims)
            PreparedDeviceRegistration(input, approvalKey, now, dpopJti)
        }
    }
}

private inline fun <T> proofCheck(block: () -> T): T = try { block() } catch (_: Exception) { throw DeviceProofException() }
