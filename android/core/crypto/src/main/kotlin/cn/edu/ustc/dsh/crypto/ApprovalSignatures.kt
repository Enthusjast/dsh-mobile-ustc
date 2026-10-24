package cn.edu.ustc.dsh.crypto

import cn.edu.ustc.dsh.protocol.*
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.ECKey
import java.security.MessageDigest

class ApprovalSignatureException : IllegalArgumentException("approval: invalid signed decision")

/** Only a previously registered public key is accepted; no key URL is followed. */
class RegisteredApprovalKey private constructor(
    val userId: String,
    val deviceId: String,
    val keyVersion: Long,
    val thumbprint: String,
    val active: Boolean,
    val publicJwk: JsonObject,
    internal val ecKey: ECKey,
) {
    companion object {
        fun parse(root: JsonObject): RegisteredApprovalKey = signatureCheck {
            root.exactKeys("user_id", "device_id", "key_version", "approval_key_jkt", "public_jwk", "active")
            val userId = Contract.uuid(root.string("user_id"))
            val deviceId = Contract.uuid(root.string("device_id"))
            val version = root.integer("key_version")
            val active = (root["active"] as? JsonBoolean)?.value ?: throw ApprovalSignatureException()
            val public = root.obj("public_jwk")
            if (!setOf("kty", "crv", "x", "y").all { it in public.fields } ||
                !setOf("kty", "crv", "x", "y", "alg", "use", "key_ops", "kid", "ext").containsAll(public.fields.keys)) throw ApprovalSignatureException()
            if (public.string("kty") != "EC" || public.string("crv") != "P-256") throw ApprovalSignatureException()
            for (name in listOf("x", "y")) if (public.string(name).length != 43 || Contract.base64url(public.string(name)).size != 32) throw ApprovalSignatureException()
            if (public.fields["alg"]?.let { it != "ES256".json() } == true || public.fields["use"]?.let { it != "sig".json() } == true) throw ApprovalSignatureException()
            if ("key_ops" in public.fields && public.array("key_ops") != listOf("verify".json())) throw ApprovalSignatureException()
            if ("kid" in public.fields) {
                val kid = public.string("kid")
                requireText(kid)
                if (kid.toByteArray(Charsets.UTF_8).size > 128) throw ApprovalSignatureException()
            }
            if ("ext" in public.fields && public["ext"] !is JsonBoolean) throw ApprovalSignatureException()
            val minimal = JsonObject(public.fields.filterKeys { it in setOf("kty", "crv", "x", "y") })
            val ecKey = ECKey.parse(JsonDocument.of(minimal).canonicalText())
            val thumbprint = root.string("approval_key_jkt")
            if (!constantEqual(ecKey.computeThumbprint().toString(), thumbprint)) throw ApprovalSignatureException()
            RegisteredApprovalKey(userId, deviceId, version, thumbprint, active, minimal, ecKey)
        }
    }
}

class SignedApprovalDecision internal constructor(val compact: String, val decision: ApprovalDecision) {
    val payloadSha256: String = decision.document.sha256()
}

object ApprovalSignatures {
    /** Cryptographic/context verification; server authorization is still required. */
    fun verify(compact: String, key: RegisteredApprovalKey, context: ApprovalContext, now: Long): SignedApprovalDecision = signatureCheck {
        if (!key.active || now < 0 || compact.isEmpty() || compact.toByteArray(Charsets.UTF_8).size > 16 * 1024) throw ApprovalSignatureException()
        val parts = compact.split('.')
        if (parts.size != 3) throw ApprovalSignatureException()
        val decoded = parts.map { Contract.base64url(it) }
        if (decoded[2].size != 64) throw ApprovalSignatureException()
        val header = JsonDocument.parse(decoded[0])
        if (!MessageDigest.isEqual(header.canonicalBytes(), decoded[0])) throw ApprovalSignatureException()
        header.root.exactKeys("alg", "kid", "typ")
        if (header.root.string("alg") != "ES256" || header.root.string("typ") != APPROVAL_JWS_TYPE ||
            header.root.string("kid") != approvalKeyId(key.deviceId, key.keyVersion)) throw ApprovalSignatureException()
        val signed = JWSObject.parse(compact)
        if (!signed.verify(ECDSAVerifier(key.ecKey))) throw ApprovalSignatureException()
        val decision = ApprovalDecision.parse(decoded[1])
        if (!MessageDigest.isEqual(decision.document.canonicalBytes(), decoded[1]) || !decision.matches(context, now)) throw ApprovalSignatureException()
        if (decision.root.string("user_id") != key.userId || decision.root.string("device_id") != key.deviceId || decision.root.integer("key_version") != key.keyVersion) throw ApprovalSignatureException()
        SignedApprovalDecision(compact, decision)
    }

    /** Prepare complete bytes before opening the platform's per-use auth prompt. */
    fun prepare(context: ApprovalContext, choice: ApprovalChoice, key: RegisteredApprovalKey, now: Long): PreparedApprovalSignature = signatureCheck {
        if (!key.active) throw ApprovalSignatureException()
        val decision = ApprovalDecision.create(context, choice, key.userId, key.deviceId, key.keyVersion, now)
        val header = JsonDocument.of(jsonObject(
            "alg" to "ES256".json(), "kid" to approvalKeyId(key.deviceId, key.keyVersion).json(), "typ" to APPROVAL_JWS_TYPE.json(),
        ))
        val input = "${Contract.base64url(header.canonicalBytes())}.${Contract.base64url(decision.document.canonicalBytes())}"
        PreparedApprovalSignature(context, key, input)
    }
}

/** Ephemeral: never persist or restore a biometric prompt/signature operation. */
class PreparedApprovalSignature internal constructor(
    private val context: ApprovalContext,
    private val key: RegisteredApprovalKey,
    private val input: String,
) : PreparedUserSignature<SignedApprovalDecision> {
    private var ended = false
    override val keyThumbprint: String get() = key.thumbprint
    override fun signingInput(): ByteArray = input.toByteArray(Charsets.US_ASCII)

    /** Android's SHA256withECDSA returns DER; Nimbus converts it to JOSE r||s. */
    @Synchronized
    override fun finishDerSignature(der: ByteArray, now: Long): SignedApprovalDecision = signatureCheck {
        if (ended) throw ApprovalSignatureException()
        ended = true
        val signature = ECDSA.transcodeSignatureToConcat(der.copyOf(), 64)
        ApprovalSignatures.verify("$input.${Contract.base64url(signature)}", key, context, now)
    }

    @Synchronized
    override fun cancel() { ended = true }
}

private fun constantEqual(a: String, b: String): Boolean = MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))
private inline fun <T> signatureCheck(block: () -> T): T = try { block() } catch (_: Exception) { throw ApprovalSignatureException() }
