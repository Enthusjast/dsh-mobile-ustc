package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.network.HostBindingPhase
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AccountHostBindingTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private var fixture: AccountFixture? = null
    private var controller: LoginController? = null
    private fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
    @Before fun setup() {
        assumeTrue("explicit account fixture required", InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        val context = instrumentation.targetContext
        val guard = context.getSystemService(KeyguardManager::class.java)
        assertTrue("secure unlocked fixture required", guard.isDeviceSecure && !guard.isDeviceLocked)
        fixture = AccountFixture(context).also { it.bindingMode = true; it.seed() }
        main { controller = LoginController(context, fixture!!.http, fixture!!.environment()); controller!!.foreground(true) }
        until("authorized account") { controller!!.state.value.let { it.phase == HomePhase.READY && !it.refreshing } }
        main { controller!!.openBinding() }
    }
    @After fun cleanup() { main { controller?.close() }; fixture?.close() }
    private fun until(label: String, condition: () -> Boolean) {
        val deadline = android.os.SystemClock.elapsedRealtime() + 30_000
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            fixture!!.failure.get()?.let { throw AssertionError(it) }
            if (condition()) return
            Thread.sleep(25)
        }
        throw AssertionError("Timed out: $label; account=${controller?.state?.value?.phase}; binding=${controller?.state?.value?.binding?.phase}; error=${controller?.state?.value?.binding?.error}")
    }
    private fun phase(phase: HostBindingPhase) = until("binding $phase") { controller!!.state.value.binding?.phase == phase }
    private fun review() {
        main { controller!!.previewBinding(fixture!!.bindingId, fixture!!.bindingCode) }; phase(HostBindingPhase.REVIEW)
        assertFalse(controller!!.state.value.toString().contains(fixture!!.bindingCode))
    }
    @Test fun explicitPhoneConfirmationWaitsForTheHostAndTheCurrentGrant() {
        val owner = controller!!; val test = fixture!!
        review(); assertEquals(0, test.bindingWrites.get()); assertTrue(owner.state.value.runtimes.isEmpty())
        main { owner.confirmBinding() }; phase(HostBindingPhase.WAITING_HOST)
        assertEquals(1, test.bindingWrites.get()); assertFalse(test.bindingHostConfirmed)
        assertEquals(test.bindingId, owner.state.value.pendingBindingId)
        test.bindingHostConfirmed = true
        main { owner.refreshBinding() }
        until("confirmed and authorized directory") { owner.state.value.let { it.binding?.phase == HostBindingPhase.READY && !it.refreshing && it.runtimes.size == 1 } }
        assertTrue(owner.state.value.binding!!.details!!.confirmedByMe)
        main { owner.closeBinding() }; assertNull(owner.state.value.binding); assertNull(owner.state.value.pendingBindingId)
        assertEquals(test.runtimeId, owner.state.value.runtimes.single().id)
    }
    @Test fun lostConfirmationReplyResumesWithStatusReadsAcrossForegroundChanges() {
        val owner = controller!!; val test = fixture!!; test.dropBindingReply = true
        review(); main { owner.confirmBinding() }; phase(HostBindingPhase.UNKNOWN)
        assertEquals(1, test.bindingWrites.get())
        main { owner.foreground(false) }; assertEquals(HostBindingPhase.PAUSED, owner.state.value.binding!!.phase)
        assertNull(owner.state.value.binding!!.details)
        main { owner.foreground(true) }; phase(HostBindingPhase.WAITING_HOST)
        assertEquals(1, test.bindingWrites.get()); assertTrue(test.bindingStatusReads.get() >= 1)
        test.bindingHostConfirmed = true
        main { owner.refreshBinding() }; phase(HostBindingPhase.READY)
        assertEquals(1, test.bindingWrites.get())
    }
    @Test fun logoutFencesALatePreviewAndRemovesAllBindingState() {
        val owner = controller!!; val test = fixture!!; test.holdBindingPreview = true
        main { owner.previewBinding(test.bindingId, test.bindingCode) }
        until("delayed preview arrived") { test.bindingPreviews.get() == 1 }
        main { owner.cancel() }
        until("local exit") { owner.state.value.phase == HomePhase.SIGNED_OUT }
        Thread.sleep(2300)
        assertNull(owner.state.value.binding); assertNull(owner.state.value.pendingBindingId)
        assertEquals(0, test.bindingWrites.get()); assertNull(test.vault.read())
    }
    @Test fun backgroundRetiresUnsubmittedReviewAndAnotherAccountNeverEnablesConfirmation() {
        val owner = controller!!; val test = fixture!!
        review()
        main { owner.foreground(false); owner.foreground(true); owner.confirmBinding() }
        phase(HostBindingPhase.ENTER); assertEquals(0, test.bindingWrites.get())
        test.bindingUserConfirmed = true; test.bindingConfirmedElsewhere = true
        main { owner.previewBinding(test.bindingId, test.bindingCode) }; phase(HostBindingPhase.UNAVAILABLE)
        assertEquals("binding.confirmed_elsewhere", owner.state.value.binding!!.error)
        main { owner.confirmBinding() }; assertEquals(0, test.bindingWrites.get())
    }
    @Test fun aBindingSpecificDenialDoesNotDeleteAnOtherwiseAuthorizedAccount() {
        val owner = controller!!; val test = fixture!!
        main { owner.previewBinding(test.bindingId, "K".repeat(42) + "A") }
        until("resource denial reconciled with account authority") { owner.state.value.let { it.phase == HomePhase.READY && !it.refreshing && it.binding?.phase == HostBindingPhase.ERROR } }
        assertEquals("access.denied", owner.state.value.binding!!.error)
        assertNotNull(test.checkpoint()); assertEquals(test.deviceId, owner.state.value.deviceId)
        assertEquals(0, test.bindingWrites.get())
    }
}
