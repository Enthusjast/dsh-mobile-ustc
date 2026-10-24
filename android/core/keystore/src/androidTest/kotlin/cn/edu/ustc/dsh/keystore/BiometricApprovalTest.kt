package cn.edu.ustc.dsh.keystore

import android.content.Intent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Test-only activity, absent from the published library and any production app. */
class BiometricTestActivity : FragmentActivity()

@RunWith(AndroidJUnit4::class)
class BiometricApprovalTest {
    @Test fun actualBiometricCryptoObjectSignsBothChoicesAndCancelledOperationsStayClosed() {
        // Real-device users must opt in before a test opens authentication UI.
        assumeTrue("Requires explicit biometricFixture=true and an enrolled test fingerprint",
            InstrumentationRegistry.getArguments().getString("biometricFixture") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assertEquals(BiometricManager.BIOMETRIC_SUCCESS, BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG))
        val keys = DeviceKeyStore(context)
        val scope = DeviceKeyScope(UUID.randomUUID().toString(), UUID.randomUUID().toString())
        try {
            val key = keys.create(scope, DeviceKeyPurpose.APPROVAL, 1)
            val fixture = JsonDocument.parse(context.assets.open("approval-signatures.json").use { it.readBytes() }).root
            val registered = RegisteredApprovalKey.parse(fixture.obj("registered").with("public_jwk" to key.publicJwk, "approval_key_jkt" to key.thumbprint.json()))
            for (choice in ApprovalChoice.entries) {
                val now = System.currentTimeMillis()
                val current = ApprovalContext.from(JsonDocument.of(fixture.obj("context").with(
                    "created_at" to Contract.timestamp(now).json(), "expires_at" to Contract.timestamp(now + MAX_APPROVAL_LIFETIME_MS).json(),
                    "approval_id" to UUID.randomUUID().toString().json(), "execution_id" to UUID.randomUUID().toString().json(),
                )))
                val cancelled = key.beginApproval(ApprovalSignatures.prepare(current, choice, registered, now))
                val oldCrypto = cancelled.cryptoObject
                cancelled.close()
                assertEquals(DeviceCryptoFailure.CANCELLED, assertThrows(DeviceCryptoException::class.java) { cancelled.cryptoObject }.failure)
                assertThrows(java.security.SignatureException::class.java) { oldCrypto.signature!!.sign() }
                val request = ApprovalSignatures.prepare(current, choice, registered, System.currentTimeMillis())
                val operation = key.beginApproval(request)
                val result = AtomicReference<SignedApprovalDecision>()
                val failure = AtomicReference<Throwable>()
                val completed = CountDownLatch(1)
                val intent = Intent(context, BiometricTestActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                ActivityScenario.launch<BiometricTestActivity>(intent).use { scenario ->
                    scenario.onActivity { activity ->
                        val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationSucceeded(authenticated: BiometricPrompt.AuthenticationResult) {
                                try { result.set(operation.finish(authenticated)) } catch (error: Throwable) { failure.set(error) }
                                completed.countDown()
                            }
                            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                                failure.set(AssertionError("Biometric prompt failed with code $errorCode")); operation.close(); completed.countDown()
                            }
                        })
                        prompt.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle("Approval signature fixture")
                            .setSubtitle("Isolated test device only").setNegativeButtonText("Cancel")
                            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG).build(), operation.cryptoObject)
                    }
                    assertTrue("Timed out waiting for the test fingerprint", completed.await(45, TimeUnit.SECONDS))
                    failure.get()?.let { throw AssertionError("Platform approval signing failed", it) }
                    val signed = result.get() ?: throw AssertionError("Missing signed decision")
                    assertEquals(choice, signed.decision.choice)
                    assertEquals(signed.payloadSha256, ApprovalSignatures.verify(signed.compact, registered, current, System.currentTimeMillis()).payloadSha256)
                    assertEquals(DeviceCryptoFailure.CANCELLED, assertThrows(DeviceCryptoException::class.java) { operation.cryptoObject }.failure)
                }
            }
        } finally { keys.delete(scope, DeviceKeyPurpose.APPROVAL, 1); keys.close() }
    }
}
