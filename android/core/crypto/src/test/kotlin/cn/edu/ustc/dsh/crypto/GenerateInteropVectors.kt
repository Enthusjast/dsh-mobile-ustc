package cn.edu.ustc.dsh.crypto

import cn.edu.ustc.dsh.protocol.*
import java.io.File
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** Explicit generator only. The private key is never serialized or printed. */
object GenerateInteropVectors {
    @JvmStatic fun main(args: Array<String>) {
        require(args.size == 2)
        val fixture = JsonDocument.parse(File(args[0]).readBytes()).root
        val context = ApprovalContext.from(JsonDocument.of(fixture.obj("context")))
        val now = Contract.utc(fixture.string("now"))
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val public = pair.public as ECPublicKey
        fun coordinate(value: java.math.BigInteger): JsonString {
            val bytes = value.toByteArray().takeLast(32).toByteArray()
            return Contract.base64url(ByteArray(32 - bytes.size) + bytes).json()
        }
        val jwk = jsonObject("kty" to "EC".json(), "crv" to "P-256".json(), "x" to coordinate(public.w.affineX), "y" to coordinate(public.w.affineY))
        val jkt = Contract.base64url(MessageDigest.getInstance("SHA-256").digest(JsonDocument.of(jwk).canonicalBytes()))
        val registered = fixture.obj("registered").with("public_jwk" to jwk, "approval_key_jkt" to jkt.json())
        val key = RegisteredApprovalKey.parse(registered)
        val vectors = arrayListOf<JsonValue>()
        for (choice in ApprovalChoice.entries) {
            val request = ApprovalSignatures.prepare(context, choice, key, now)
            val der = Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(request.signingInput()); sign() }
            val signed = request.finishDerSignature(der, now)
            vectors += jsonObject("name" to "kotlin-jca-${choice.wire}".json(), "compact" to signed.compact.json(), "decision" to choice.wire.json(), "payload_sha256" to signed.payloadSha256.json())
            if (choice == ApprovalChoice.ALLOW_ONCE) {
                val parts = signed.compact.split('.')
                val changed = JsonDocument.of(signed.decision.root.with("decision" to "reject".json()))
                vectors += jsonObject("name" to "kotlin-tampered-choice".json(), "compact" to "${parts[0]}.${Contract.base64url(changed.canonicalBytes())}.${parts[2]}".json(), "invalid" to JsonBoolean(true))
                vectors += jsonObject("name" to "kotlin-raw-der-denied".json(), "compact" to "${parts[0]}.${parts[1]}.${Contract.base64url(der)}".json(), "invalid" to JsonBoolean(true))
            }
        }
        val output = jsonObject("now" to fixture["now"], "context" to context.root, "binding_canonical" to context.document.canonicalText().json(),
            "binding_sha256" to context.bindingSha256.json(), "registered" to registered, "vectors" to JsonArray(vectors))
        File(args[1]).writeText(JsonDocument.of(output).canonicalText() + "\n")
        println("Generated ${vectors.size} public-only Kotlin/JCA approval vectors.")
    }
}
