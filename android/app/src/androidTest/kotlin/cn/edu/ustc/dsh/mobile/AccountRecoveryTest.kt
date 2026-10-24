package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import android.os.Bundle
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.auth.*
import cn.edu.ustc.dsh.keystore.*
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicReference

@RunWith(AndroidJUnit4::class)
class AccountRecoveryTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private var fixture: AccountFixture? = null
    private val controllers = mutableListOf<LoginController>()
    @Before fun requireExplicitFixture() {
        assumeTrue("explicit account fixture required", InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        val guard = context.getSystemService(KeyguardManager::class.java)
        assertTrue("secure unlocked test device required", guard.isDeviceSecure && !guard.isDeviceLocked)
        assertEquals(BiometricManager.BIOMETRIC_SUCCESS, BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG))
        fixture = AccountFixture(context)
    }
    @After fun clean() { main { controllers.forEach(LoginController::close) }; fixture?.close() }
    private fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
    private fun biometricProgress(value: String) {
        val run = InstrumentationRegistry.getArguments().getString("accountFixtureRun") ?: "manual"
        instrumentation.sendStatus(2, Bundle().apply { putString("stream", "\nACCOUNT_FIXTURE_BIOMETRIC_$value $run\n") })
    }
    private fun controller(minimumValidity: Long = 0): LoginController {
        val test = fixture!!
        lateinit var controller: LoginController
        main { controller = LoginController(context, test.http, test.environment(minimumValidity)); controllers += controller }
        return controller
    }
    private fun until(description: String, test: () -> Boolean) {
        val timeout = android.os.SystemClock.elapsedRealtime() + 30_000
        while (android.os.SystemClock.elapsedRealtime() < timeout) {
            fixture!!.failure.get()?.let { throw AssertionError(it) }
            if (test()) return
            Thread.sleep(25)
        }
        throw AssertionError("Timed out: $description")
    }
    private fun phase(controller: LoginController, phase: HomePhase) = until("phase $phase; current ${controller.state.value.phase}") {
        val state = controller.state.value
        state.phase == phase && (phase != HomePhase.READY || !state.refreshing && state.runtimes.size == 1)
    }
    private fun browser(controller: LoginController) {
        val test = fixture!!
        main { controller.login() }
        phase(controller, HomePhase.BROWSER)
        val uri = controller.state.value.browser!!.uri
        test.browserNonce = uri.getQueryParameter("nonce")!!
        test.browserChallenge = uri.getQueryParameter("code_challenge")!!
        main { controller.callback(LoginConfiguration.REDIRECT_URI + "?state=${uri.getQueryParameter("state")}&code=fixture-code") }
    }
    private fun missingProofKey(test: AccountFixture) {
        DeviceKeyStore(context).use { owner ->
            assertEquals(DeviceCryptoFailure.KEY_MISSING, assertThrows(DeviceCryptoException::class.java) { owner.load(DeviceKeyScope(test.accountId, test.organizationId), DeviceKeyPurpose.PROOF, 1) }.failure)
        }
    }

    @Test fun registeringCheckpointReconcilesAcceptedKeysAndSurvivesNewControllerWithoutAnotherPost() {
        val test = fixture!!; test.seed(registering = true)
        val abandoned = test.orphanProof()
        val original = test.proofJkt
        val first = controller(); phase(first, HomePhase.READY)
        assertEquals(test.deviceId, first.state.value.deviceId)
        assertEquals(EnrollmentCheckpoint.ACTIVE, test.checkpoint()!!.enrollment)
        assertEquals(0, test.registrationRequests.get())
        DeviceKeyStore(context).use { owner ->
            assertEquals(DeviceCryptoFailure.KEY_MISSING, assertThrows(DeviceCryptoException::class.java) { owner.load(abandoned.scope(), DeviceKeyPurpose.PROOF, 1) }.failure)
        }
        main { first.close() }
        val restored = controller(); phase(restored, HomePhase.READY)
        assertEquals(test.deviceId, restored.state.value.deviceId)
        assertEquals(original, test.checkpoint()!!.session.proofKeyThumbprint)
        assertEquals(0, test.registrationRequests.get())
    }

    @Test fun lostRefreshResponseRequiresSameAccountBrowserLoginAndKeepsOriginalDevice() {
        val test = fixture!!; test.seed(); test.dropRefreshReply = true
        val first = controller(180_000); phase(first, HomePhase.READY)
        main { first.refresh() }; phase(first, HomePhase.REAUTHENTICATE)
        assertEquals(1, test.refreshRequests.get())
        assertNotEquals(RefreshCheckpoint.READY, test.checkpoint()!!.refresh)
        main { first.close() }
        val restored = controller(); phase(restored, HomePhase.REAUTHENTICATE)
        assertEquals(1, test.refreshRequests.get())
        val before = test.meRequests.get()
        test.browserSubject = "different-school-account"
        browser(restored); phase(restored, HomePhase.REAUTHENTICATE)
        assertEquals("login.account_mismatch", restored.state.value.error)
        assertEquals(before, test.meRequests.get())
        test.browserSubject = test.subject; test.dropRefreshReply = false
        browser(restored); phase(restored, HomePhase.READY)
        assertEquals(test.deviceId, restored.state.value.deviceId)
        assertEquals(RefreshCheckpoint.READY, test.checkpoint()!!.refresh)
        assertEquals(0, test.registrationRequests.get())
    }

    @Test fun logoutDuringRefreshCannotBeUndoneByTheLateResponseOrANewController() {
        val test = fixture!!; test.seed(); test.holdRefresh = true
        val first = controller(180_000); phase(first, HomePhase.READY)
        main { first.refresh() }
        until("refresh request arrived after durable marker") { test.refreshRequests.get() == 1 }
        assertEquals(RefreshCheckpoint.REFRESHING, test.checkpoint()!!.refresh)
        main { first.cancel() }; phase(first, HomePhase.SIGNED_OUT)
        Thread.sleep(2500)
        assertNull(test.vault.read()); missingProofKey(test)
        main { first.close() }
        val restored = controller(); phase(restored, HomePhase.SIGNED_OUT)
        assertEquals(1, test.refreshRequests.get())
        assertNull(test.vault.read())
    }

    @Test fun membershipLossClearsAcceptedCredentialsAndKeysBeforeTheDirectoryCanReopen() {
        val test = fixture!!; test.seed()
        val first = controller(); phase(first, HomePhase.READY)
        val previousHosts = test.hostRequests.get()
        test.member = false
        main { first.refresh() }; phase(first, HomePhase.SIGNED_OUT)
        assertEquals(previousHosts, test.hostRequests.get())
        assertNull(test.vault.read()); missingProofKey(test)
        main { first.close() }
        val restored = controller(); phase(restored, HomePhase.SIGNED_OUT)
    }

    @Test fun interruptedRefreshMarkerNeverSendsAnOldRotatingCredentialOnRestore() {
        val test = fixture!!; test.seed(refreshing = true)
        val restored = controller(); phase(restored, HomePhase.REAUTHENTICATE)
        assertEquals(0, test.refreshRequests.get())
        assertEquals(0, test.meRequests.get())
        assertEquals(test.deviceId, test.checkpoint()!!.deviceId)
        assertEquals(RefreshCheckpoint.REFRESHING, test.checkpoint()!!.refresh)
    }

    @Test fun successfulRotationPersistsTheNewRefreshCredentialForTheNextController() {
        val test = fixture!!; test.seed()
        val original = test.proofJkt
        val first = controller(180_000); phase(first, HomePhase.READY)
        main { first.refresh() }
        until("first credential rotation") { test.refreshRequests.get() == 1 }
        phase(first, HomePhase.READY)
        assertEquals(RefreshCheckpoint.READY, test.checkpoint()!!.refresh)
        main { first.close() }
        val restored = controller(360_000); phase(restored, HomePhase.READY)
        main { restored.refresh() }
        until("restored rotated refresh credential used") { test.refreshRequests.get() == 2 }
        phase(restored, HomePhase.READY)
        assertEquals(test.deviceId, restored.state.value.deviceId)
        assertEquals(original, test.checkpoint()!!.session.proofKeyThumbprint)
        assertEquals(0, test.registrationRequests.get())
    }

    @Test fun changedInternalUserMappingCannotReuseTheExistingEnrollment() {
        val test = fixture!!; test.seed()
        val first = controller(); phase(first, HomePhase.READY)
        val previousHosts = test.hostRequests.get()
        test.serviceUserId = "66666666-6666-4666-8666-666666666666"
        main { first.refresh() }; phase(first, HomePhase.SIGNED_OUT)
        assertEquals(previousHosts, test.hostRequests.get())
        assertNull(test.vault.read()); missingProofKey(test)
    }

    @Test fun realBiometricRegistrationRecoversLostResponseAndReopensWithTheSamePlatformKeys() {
        val test = fixture!!; test.dropRegistrationReply = true
        val first = controller(); phase(first, HomePhase.SIGNED_OUT)
        val errors = AtomicReference<String?>()
        ActivityScenario.launch(MainActivity::class.java).use { activity ->
            // The foreground host exists before preparing the 30-second proof, as in the real UI.
            browser(first); phase(first, HomePhase.ENROLL)
            main { first.register("校园夹具手机") }; phase(first, HomePhase.AUTHENTICATING)
            activity.onActivity { host ->
                val launch = first.state.value.biometric!!
                first.promptOpened(launch.id)
                val prompt = BiometricPrompt(host, ContextCompat.getMainExecutor(host), object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        biometricProgress("DONE")
                        first.authenticated(launch.id, result)
                    }
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) { errors.set("biometric error $errorCode") }
                })
                prompt.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle("Fixture device enrollment")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG).setNegativeButtonText("Cancel").build(), launch.operation.cryptoObject)
                biometricProgress("READY")
            }
            until("actual biometric enrollment and response-loss recovery") {
                errors.get()?.let { throw AssertionError(it) }
                val state = first.state.value
                if (state.phase in setOf(HomePhase.ENROLL, HomePhase.RECOVERY_ERROR, HomePhase.REAUTHENTICATE, HomePhase.REGISTRATION_UNKNOWN, HomePhase.SIGNED_OUT)) {
                    throw AssertionError("Enrollment stopped at ${state.phase}, code=${state.error}, writes=${test.registrationRequests.get()}")
                }
                state.phase == HomePhase.READY && !state.refreshing && state.runtimes.size == 1
            }
        }
        val saved = test.checkpoint()!!
        assertEquals(EnrollmentCheckpoint.ACTIVE, saved.enrollment)
        assertEquals(test.deviceId, saved.deviceId)
        assertEquals(1, test.registrationRequests.get())
        assertEquals(test.proofJkt, saved.session.proofKeyThumbprint)
        assertEquals(test.approvalJkt, saved.approvalKeyJkt)
        main { first.close() }
        val restored = controller(); phase(restored, HomePhase.READY)
        assertEquals(test.deviceId, restored.state.value.deviceId)
        assertEquals(1, test.registrationRequests.get())
    }
}
