package cn.edu.ustc.dsh.keystore

import android.app.KeyguardManager
import android.content.Context
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.protocol.*
import com.nimbusds.jose.crypto.impl.ECDSA
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.security.Signature
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class DeviceKeyStoreTest {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val keys = DeviceKeyStore(context)
    private val scopes = mutableListOf<DeviceKeyScope>()
    private fun scope(): DeviceKeyScope = DeviceKeyScope(UUID.randomUUID().toString(), UUID.randomUUID().toString()).also { scopes += it }

    @After fun clean() {
        scopes.forEach { scope -> DeviceKeyPurpose.entries.forEach { purpose -> keys.delete(scope, purpose, 1) } }
        keys.close()
    }

    @Test fun proofKeysAreNonExportablePersistedAndScoped() {
        val firstScope = scope()
        val first = keys.create(firstScope, DeviceKeyPurpose.PROOF, 1)
        val another = keys.create(scope(), DeviceKeyPurpose.PROOF, 1)
        assertNotEquals(first.thumbprint, another.thumbprint)
        assertEquals(first.thumbprint, keys.load(firstScope, DeviceKeyPurpose.PROOF, 1).thumbprint)
        val platform = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertNull(platform.getKey(first.alias, null).encoded)
        val input = "header.payload".toByteArray(Charsets.US_ASCII)
        val signature = first.signProof(input)
        assertEquals(64, signature.size)
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(platform.getCertificate(first.alias).publicKey)
        verifier.update(input)
        assertTrue(verifier.verify(ECDSA.transcodeSignatureToDER(signature)))
        assertEquals(setOf("kty", "crv", "x", "y"), first.publicJwk.fields.keys)
        val jkt = Contract.base64url(java.security.MessageDigest.getInstance("SHA-256").digest(JsonDocument.of(first.publicJwk).canonicalBytes()))
        assertEquals(jkt, first.thumbprint)
        assertEquals(DeviceCryptoFailure.KEY_EXISTS, assertThrows(DeviceCryptoException::class.java) { keys.create(firstScope, DeviceKeyPurpose.PROOF, 1) }.failure)
    }

    @Test fun deletionAndAccountDisposalFenceOldHandlesWithoutRecreatingKeys() {
        val scope = scope()
        val first = keys.create(scope, DeviceKeyPurpose.PROOF, 1)
        keys.delete(scope, DeviceKeyPurpose.PROOF, 1)
        assertEquals(DeviceCryptoFailure.CANCELLED, assertThrows(DeviceCryptoException::class.java) { first.signProof(byteArrayOf(1)) }.failure)
        assertEquals(DeviceCryptoFailure.KEY_MISSING, assertThrows(DeviceCryptoException::class.java) { keys.load(scope, DeviceKeyPurpose.PROOF, 1) }.failure)
        val second = keys.create(scope, DeviceKeyPurpose.PROOF, 1)
        assertNotEquals(first.thumbprint, second.thumbprint)
        second.close()
        assertEquals(DeviceCryptoFailure.CANCELLED, assertThrows(DeviceCryptoException::class.java) { second.signProof(byteArrayOf(1)) }.failure)
        // Closing the account's owner fences handles but deliberately preserves
        // enrolled private keys for an explicitly authorized future login.
        val otherOwner = DeviceKeyStore(context)
        val loaded = otherOwner.load(scope, DeviceKeyPurpose.PROOF, 1)
        otherOwner.close()
        assertEquals(DeviceCryptoFailure.CANCELLED, assertThrows(DeviceCryptoException::class.java) { loaded.signProof(byteArrayOf(1)) }.failure)
        assertEquals(DeviceCryptoFailure.CANCELLED, assertThrows(DeviceCryptoException::class.java) { otherOwner.load(scope, DeviceKeyPurpose.PROOF, 1) }.failure)
    }

    @Test fun approvalEnrollmentRequiresSecureLockAndStrongBiometricWithNoUnsignedFallback() {
        val scope = scope()
        val secure = context.getSystemService(KeyguardManager::class.java).isDeviceSecure
        val biometric = BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (!secure || biometric != BiometricManager.BIOMETRIC_SUCCESS) {
            val error = assertThrows(DeviceCryptoException::class.java) { keys.create(scope, DeviceKeyPurpose.APPROVAL, 1) }
            assertEquals(if (!secure) DeviceCryptoFailure.LOCK_REQUIRED else DeviceCryptoFailure.BIOMETRIC_REQUIRED, error.failure)
            assertEquals(DeviceCryptoFailure.KEY_MISSING, assertThrows(DeviceCryptoException::class.java) { keys.load(scope, DeviceKeyPurpose.APPROVAL, 1) }.failure)
        } else {
            val approval = keys.create(scope, DeviceKeyPurpose.APPROVAL, 1)
            assertEquals(DeviceCryptoFailure.WRONG_KEY, assertThrows(DeviceCryptoException::class.java) { approval.signProof(byteArrayOf(1)) }.failure)
            val platform = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val private = platform.getKey(approval.alias, null) as java.security.PrivateKey
            assertNull(private.encoded)
            // Merely owning the Java key handle cannot satisfy per-use auth.
            val denied = assertThrows(java.security.GeneralSecurityException::class.java) {
                Signature.getInstance("SHA256withECDSA").apply { initSign(private); update(byteArrayOf(1)) }.sign()
            }
            // Some providers reject initSign directly; API 26 can instead
            // surface the authentication failure as a SignatureException at sign.
            assertTrue(denied is UserNotAuthenticatedException || denied is java.security.SignatureException)
        }
    }
}
