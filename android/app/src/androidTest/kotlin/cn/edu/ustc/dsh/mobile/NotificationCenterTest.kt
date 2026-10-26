package cn.edu.ustc.dsh.mobile

import android.app.Notification
import android.app.NotificationManager
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.auth.PushDeployment
import cn.edu.ustc.dsh.protocol.*
import org.junit.*
import org.junit.Assert.*
import org.junit.runner.RunWith
import java.io.File
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CountDownLatch

@RunWith(AndroidJUnit4::class)
class NotificationCenterTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val slot = "push-test-${UUID.randomUUID()}"
    private val center = NotificationCenter(context, slot)
    private val owner = "a".repeat(64)
    private val deployment = "b".repeat(64)
    private val config = PushDeployment.parse(JsonDocument.of(jsonObject("v" to 1L.json(), "deployment_sha256" to deployment.json(), "package_name" to context.packageName.json(),
        "fcm" to jsonObject("project_id" to "fixture-project".json(), "application_id" to "1:123456789:android:abcdef012345".json(), "sender_id" to "123456789".json(), "api_key" to "fixture_public_key_1234567890".json()))).canonicalBytes(), deployment, context.packageName)
    private val manager = context.getSystemService(NotificationManager::class.java)
    private val tag get() = "dsh-interactions-$slot"
    private fun active(): PushRoute {
        center.ensureChannel(); assertTrue("owned test image must permit generic notifications", center.allowed())
        val route = center.stage(owner, deployment, config, "https://local.example.edu", UUID.randomUUID().toString(), "c" + "A".repeat(21))
        center.update(owner, PushBinding.parse(jsonObject("binding_id" to route.id.json(), "state" to "active".json(), "challenge_expires_at" to Instant.now().plusSeconds(60).toString().json(), "expires_at" to Instant.now().plusSeconds(3600).toString().json())))
        return center.snapshot().route!!
    }
    private fun packet(route: PushRoute, id: String = UUID.randomUUID().toString()) = mapOf("v" to "1", "kind" to "interaction", "binding_id" to route.id, "notification_id" to id, "expires_at" to Instant.now().plusSeconds(60).toString())
    private fun posted() = manager.activeNotifications.filter { it.tag == tag }
    @After fun cleanup() { center.retire(); PushStorage(context, slot).destroy(); File(context.noBackupFilesDir, "notification-routing/$slot").deleteRecursively() }
    @Test fun encryptedRoutingRequiresTheOriginalBindingSenderAndExactMinimalPayload() {
        val route = active(); val message = packet(route)
        center.receive(config, "another-project", message)
        center.receive(config, config.senderId, message + ("arguments" to "PRIVATE_TOOL_BODY"))
        center.receive(config, config.senderId, message + ("binding_id" to UUID.randomUUID().toString()))
        assertTrue(posted().isEmpty())
        center.receive(config, config.senderId, message)
        center.receive(config, config.senderId, message)
        assertEquals(1, posted().size); assertEquals(1, center.snapshot().notices.size); assertEquals(1, center.snapshot().receipts.count { it.state == "posted" })
        val notification = posted().single().notification
        assertEquals(Notification.VISIBILITY_PRIVATE, notification.visibility)
        assertFalse(notification.extras.toString().contains("PRIVATE_TOOL_BODY")); assertFalse(notification.extras.toString().contains(config.projectId))
        assertNotNull(notification.publicVersion)
        val directory = File(context.noBackupFilesDir, "notification-routing/$slot")
        directory.walkTopDown().filter(File::isFile).forEach {
            val bytes = it.readBytes().toString(Charsets.ISO_8859_1)
            for (secret in listOf(route.secret, route.address, route.owner)) assertFalse(bytes.contains(secret))
        }
    }
    @Test fun sameSessionIndependentReferencesKeepOneInboxEntryAndRetirementFencesLatePackets() {
        val route = active()
        center.receive(config, config.senderId, packet(route))
        center.receive(config, config.senderId, packet(route))
        assertEquals(2, center.snapshot().notices.size); assertEquals(1, posted().size)
        val barrier = CountDownLatch(1)
        val receiver = Thread { barrier.await(); repeat(10) { center.receive(config, config.senderId, packet(route)) } }
        receiver.start(); barrier.countDown(); center.retire(owner); receiver.join()
        assertNull(center.snapshot().route); assertTrue(posted().isEmpty())
        assertEquals(route.id, center.snapshot().revocations.single().id)
        center.receive(config, config.senderId, packet(route)); assertTrue(posted().isEmpty())
    }
    @Test fun pendingChallengeNeverDisplaysAndSdkAutomaticNotificationPayloadIsRejected() {
        center.ensureChannel()
        val route = center.stage(owner, deployment, config, "https://local.example.edu", UUID.randomUUID().toString(), "c" + "C".repeat(21))
        center.receive(config, config.senderId, mapOf("v" to "1", "kind" to "registration_challenge", "binding_id" to route.id, "challenge" to "A".repeat(43), "expires_at" to Instant.now().plusSeconds(60).toString()))
        assertNotNull(center.challenge(owner, route.id)); assertTrue(posted().isEmpty())
        center.retirePending(owner); assertNull(center.challenge(owner, route.id))
        // This returns before Firebase's auto-display path, even without an attached service context.
        DshMessagingService().handleIntent(Intent("com.google.android.c2dm.intent.RECEIVE").putExtra("gcm.n.e", "1").putExtra("gcm.n.body", "PRIVATE_AUTO_DISPLAY"))
        assertTrue(posted().isEmpty())
    }
    @Test fun notificationIntentHasNoActionPayloadAndRejectsOtherSchemesOrInjectedSelectors() {
        val binding = UUID.randomUUID().toString(); val id = UUID.randomUUID().toString()
        val intent = NotificationOpen.intent(context, binding, id)
        val parsed = NotificationOpen.parse(intent)!!; assertEquals(binding, parsed.bindingId); assertEquals(id, parsed.notificationId)
        assertNull(NotificationOpen.parse(Intent(intent).setAction(Intent.ACTION_VIEW)))
        assertNull(NotificationOpen.parse(Intent(intent).setData(android.net.Uri.parse("dsh-notification:/binding/$binding/entry/$id?decision=allow"))))
    }
}
