package cn.edu.ustc.dsh.crypto

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class ApprovalSignaturesTest {
    private fun fixture(): JsonObject = JsonDocument.parse(File(System.getProperty("contracts.root"), "security/approval-signatures.json").readBytes()).root

    @Test fun `all shared signed decisions verify with exact canonical context`() {
        for (filename in listOf("approval-signatures.json", "approval-kotlin-signatures.json")) {
            val fixture = JsonDocument.parse(File(System.getProperty("contracts.root"), "security/$filename").readBytes()).root
            val context = ApprovalContext.from(JsonDocument.of(fixture.obj("context")))
            assertEquals(fixture.string("binding_canonical"), context.document.canonicalText())
            assertEquals(fixture.string("binding_sha256"), context.bindingSha256)
            val now = Contract.utc(fixture.string("now"))
            for (item in fixture.array("vectors")) {
                val vector = item as JsonObject
                val name = vector.string("name")
                val verify = {
                    ApprovalSignatures.verify(vector.string("compact"), RegisteredApprovalKey.parse((vector.fields["registered"] as? JsonObject) ?: fixture.obj("registered")), context, now)
                }
                if (vector.fields["invalid"] == JsonBoolean(true)) assertThrows(name, ApprovalSignatureException::class.java) { verify() }
                else {
                    val signed = verify()
                    assertEquals(name, vector.string("decision"), signed.decision.choice.wire)
                    assertEquals(name, vector.string("payload_sha256"), signed.payloadSha256)
                }
            }
        }
    }

    @Test fun `JCA DER signatures become canonical ES256 JOSE proofs for allow and reject`() {
        val fixture = fixture()
        val context = ApprovalContext.from(JsonDocument.of(fixture.obj("context")))
        val now = Contract.utc(fixture.string("now"))
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val public = pair.public as ECPublicKey
        fun coordinate(value: java.math.BigInteger): JsonString {
            val bytes = value.toByteArray().takeLast(32).toByteArray()
            return Contract.base64url(ByteArray(32 - bytes.size) + bytes).json()
        }
        val jwk = jsonObject("kty" to "EC".json(), "crv" to "P-256".json(), "x" to coordinate(public.w.affineX), "y" to coordinate(public.w.affineY))
        val jkt = Contract.base64url(java.security.MessageDigest.getInstance("SHA-256").digest(JsonDocument.of(jwk).canonicalBytes()))
        val key = RegisteredApprovalKey.parse(fixture.obj("registered").with("public_jwk" to jwk, "approval_key_jkt" to jkt.json()))
        for (choice in ApprovalChoice.entries) {
            val request = ApprovalSignatures.prepare(context, choice, key, now)
            val bytes = request.signingInput()
            val der = Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(bytes); sign() }
            bytes.fill(0) // caller mutation cannot alter the prepared payload
            val result = request.finishDerSignature(der, now)
            assertEquals(choice, result.decision.choice)
            assertEquals(64, Contract.base64url(result.compact.split('.')[2]).size)
            assertEquals(context.bindingSha256, result.decision.root.string("binding_sha256"))
            assertThrows(ApprovalSignatureException::class.java) { request.finishDerSignature(der, now) }
            assertEquals(result.payloadSha256, ApprovalSignatures.verify(result.compact, key, context, now).payloadSha256)
        }
        val cancelled = ApprovalSignatures.prepare(context, ApprovalChoice.ALLOW_ONCE, key, now)
        cancelled.cancel()
        assertThrows(ApprovalSignatureException::class.java) { cancelled.finishDerSignature(byteArrayOf(), now) }
    }

    @Test fun `expiry revocation changed execution and key purpose reject without exposing proofs`() {
        val fixture = fixture()
        val context = ApprovalContext.from(JsonDocument.of(fixture.obj("context")))
        val key = RegisteredApprovalKey.parse(fixture.obj("registered"))
        val now = Contract.utc(fixture.string("now"))
        val valid = (fixture.array("vectors").first() as JsonObject).string("compact")
        val changed = ApprovalContext.from(JsonDocument.of(context.root.with("arguments" to jsonObject("command" to "private-command-secret".json()))))
        assertThrows(ApprovalSignatureException::class.java) { ApprovalSignatures.verify(valid, key, changed, now) }
        val revoked = RegisteredApprovalKey.parse(fixture.obj("registered").with("active" to JsonBoolean(false)))
        assertThrows(ApprovalSignatureException::class.java) { ApprovalSignatures.verify(valid, revoked, context, now) }
        assertThrows(ApprovalSignatureException::class.java) { ApprovalSignatures.prepare(context, ApprovalChoice.ALLOW_ONCE, revoked, now) }
        assertThrows(ApprovalSignatureException::class.java) { ApprovalSignatures.prepare(context, ApprovalChoice.ALLOW_ONCE, key, context.expiresAt) }
        val error = assertThrows(ApprovalSignatureException::class.java) { ApprovalSignatures.verify("private-command-secret", key, context, now) }
        assertEquals("approval: invalid signed decision", error.message)
        assertNull(error.cause)
    }
}
