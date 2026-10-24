package cn.edu.ustc.dsh.crypto

import cn.edu.ustc.dsh.protocol.*
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import org.junit.Assert.*
import org.junit.Test
import java.security.Signature

class DeviceProofsTest {
    private val key = ECKeyGenerator(Curve.P_256).generate()
    private val public = PublicProofKey(JsonDocument.parse(key.toPublicJWK().toJSONString()).root)
    private val signer = object : DeviceProofSigner {
        override val publicKey = public
        override fun signJose(signingInput: ByteArray): ByteArray = ECDSASigner(key).sign(com.nimbusds.jose.JWSHeader(com.nimbusds.jose.JWSAlgorithm.ES256), signingInput).decode()
    }

    @Test fun dpopSeparatesTokenAndResourceProofsAndBindsActualUriWithoutQueryOrFragment() {
        val token = DeviceProofs.dpop(signer, "POST", "https://id.example.edu/token?tenant=school#ignored", 1000)
        val resource = DeviceProofs.dpop(signer, "GET", "https://remote.example.edu/v1/runtimes?q=private", 1000, "nonce", "access-secret")
        assertNotEquals(token.jti, resource.jti)
        for (proof in listOf(token, resource)) {
            val jws = JWSObject.parse(proof.compact)
            assertTrue(jws.verify(ECDSAVerifier(key.toPublicJWK())))
            assertEquals("dpop+jwt", jws.header.type.toString())
            assertEquals(public.thumbprint, jws.header.jwk.computeThumbprint().toString())
        }
        val tokenClaims = JsonDocument.parse(Contract.base64url(token.compact.split('.')[1])).root
        assertEquals("https://id.example.edu/token", tokenClaims.string("htu"))
        assertFalse("ath" in tokenClaims.fields)
        val resourceClaims = JsonDocument.parse(Contract.base64url(resource.compact.split('.')[1])).root
        assertEquals("https://remote.example.edu/v1/runtimes", resourceClaims.string("htu"))
        assertEquals(DeviceProofs.hash("access-secret"), resourceClaims.string("ath"))
        for (url in listOf("http://remote.example.edu/v1/me", "https://user:pass@remote.example.edu/v1/me", "file:///tmp/private"))
            assertThrows(DeviceProofException::class.java) { DeviceProofs.dpop(signer, "GET", url, 1000) }
        assertThrows(DeviceProofException::class.java) { DeviceProofs.dpop(signer, "get", "https://remote.example.edu/", 1000) }
        assertThrows(DeviceProofException::class.java) { DeviceProofs.dpop(signer, "GET", "https://remote.example.edu/", 1000, "bad\nnonce") }
    }

    @Test fun registrationProvesApprovalKeyPossessionForCurrentIdentityNameKeysAndDpopRequest() {
        val proofKey = PublicProofKey(JsonDocument.parse(ECKeyGenerator(Curve.P_256).generate().toPublicJWK().toJSONString()).root)
        val jti = DeviceProofs.randomId()
        val pending = PreparedDeviceRegistration.prepare("https://id.example.edu", "school-user", "手机", public, proofKey, jti, 1000)
        val der = Signature.getInstance("SHA256withECDSA").run { initSign(key.toECPrivateKey()); update(pending.signingInput()); sign() }
        val result = pending.finishDerSignature(der, 2000)
        assertEquals(jti, result.dpopJti)
        val jws = JWSObject.parse(result.compact)
        assertTrue(jws.verify(ECDSAVerifier(key)))
        val claims = JsonDocument.parse(jws.payload.toBytes()).root
        assertEquals("urn:dsh-mobile-ustc:device-registration", claims.string("aud"))
        assertEquals(DeviceProofs.hash("手机"), claims.string("device_name_sha256"))
        assertEquals(public.thumbprint, claims.string("approval_key_jkt"))
        assertEquals(proofKey.thumbprint, claims.string("proof_key_jkt"))
        assertThrows(DeviceProofException::class.java) { pending.finishDerSignature(der, 2000) }
        val expired = PreparedDeviceRegistration.prepare("https://id.example.edu", "school-user", "Phone", public, proofKey, jti, 1000)
        assertThrows(DeviceProofException::class.java) { expired.finishDerSignature(der, 31_001) }
        assertThrows(DeviceProofException::class.java) { expired.finishDerSignature(der, 1000) }
        assertThrows(DeviceProofException::class.java) { PreparedDeviceRegistration.prepare("https://id.example.edu", "school-user", "Phone", public, public, jti, 1000) }
    }

    @Test fun relayProofUsesTheRegisteredKeyAndBindsTheNormalizedHelloAndFreshSocketChallenge() {
        val now = 1_792_886_400_000L
        val device = "22222222-2222-4222-8222-222222222222"
        val runtime = "33333333-3333-4333-8333-333333333333"
        val hello = DeviceHello(device, listOf("session.read.v1", "connection.heartbeat.v1"))
        val challenge = DeviceChallenge.parse(jsonObject("v" to 1L.json(), "type" to "challenge".json(), "payload" to jsonObject(
            "role" to "device".json(), "connection_id" to "44444444-4444-4444-8444-444444444444".json(),
            "challenge_id" to "55555555-5555-4555-8555-555555555555".json(), "nonce" to "A".repeat(43).json(), "expires_at" to "2026-10-25T00:00:10Z".json())), now, now + 30_000)
        val compact = DeviceProofs.relayHandshake(signer, hello, challenge, runtime, now)
        val jws = JWSObject.parse(compact)
        assertTrue(jws.verify(ECDSAVerifier(key)))
        assertEquals(RELAY_PROOF_TYPE, jws.header.type.toString())
        assertNull(jws.header.jwk)
        val claims = JsonDocument.parse(jws.payload.toBytes()).root
        claims.exactKeys("iss", "aud", "challenge_id", "connection_id", "nonce", "runtime_id", "hello_sha256", "iat", "jti")
        assertEquals(device, claims.string("iss")); assertEquals(runtime, claims.string("runtime_id"))
        assertEquals(RELAY_PROOF_AUDIENCE, claims.string("aud")); assertEquals(hello.digest(), claims.string("hello_sha256"))
        assertEquals(challenge.connectionId, claims.string("connection_id")); assertEquals(challenge.nonce, claims.string("nonce"))
        assertThrows(DeviceProofException::class.java) { DeviceProofs.relayHandshake(signer, hello, challenge, runtime, challenge.expiresAt) }
        val changed = DeviceProofs.relayHandshake(signer, DeviceHello(device, listOf("connection.heartbeat.v1")), challenge, runtime, now)
        assertNotEquals(claims.string("hello_sha256"), JsonDocument.parse(JWSObject.parse(changed).payload.toBytes()).root.string("hello_sha256"))
        assertNotEquals(claims.string("jti"), JsonDocument.parse(JWSObject.parse(changed).payload.toBytes()).root.string("jti"))
    }
}
