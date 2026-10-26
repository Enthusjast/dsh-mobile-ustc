package cn.edu.ustc.dsh.protocol

import org.junit.Assert.*
import org.junit.Test
import java.io.File

class NotificationsTest {
    private fun sample(name: String) = JsonDocument.parse(File(System.getProperty("contracts.root"), "push/v1/golden/$name.json").readBytes()).root
    @Test fun sharedMinimalPacketsStaySeparateFromReferenceDetailsAndActions() {
        for (name in listOf("registration-challenge", "interaction")) {
            val root = sample(name); val data = root.fields.mapValues { (_, value) -> (value as JsonString).value }
            val packet = PushPacket.parse(data)
            assertEquals(root.string("binding_id"), packet.bindingId)
            assertTrue(if (name == "interaction") packet is PushPacket.Interaction else packet is PushPacket.Challenge)
            for ((key, value) in listOf("arguments" to "private", "decision_jws" to "private", "session_id" to root.string("binding_id"), "notification_id" to "../private")) {
                assertThrows(ProtocolException::class.java) { PushPacket.parse(data + (key to value)) }
            }
            assertThrows(ProtocolException::class.java) { PushPacket.parse(data + ("v" to "2")) }
            assertFalse(packet.current(0)); assertFalse(packet.current(packet.expiresAt))
        }
        val view = NotificationReference.parse(sample("reference")); assertEquals("approval", view.kind)
        assertThrows(ProtocolException::class.java) { NotificationReference.parse(sample("reference").with("arguments" to "private".json())) }
        assertThrows(ProtocolException::class.java) { PushPacket.parse(sample("reference").fields.mapValues { it.value.toString() }) }
    }
    @Test fun registrationAndReferencesRejectCrossPurposeOrMalformedAuthority() {
        val root = sample("registration")
        val intent = PushRegistration(root.string("binding_id"), root.string("organization_id"), root.string("address"), root.string("revoke_secret_sha256"))
        assertEquals(JsonDocument.of(root).canonicalText(), JsonDocument.of(intent.json()).canonicalText())
        assertFalse(intent.toString().contains(root.string("address")))
        assertThrows(ProtocolException::class.java) { PushRegistration(intent.bindingId, intent.organizationId, "https://private.invalid", intent.revokeHash) }
        val ref = sample("reference")
        for (bad in listOf(ref.with("availability" to "trusted".json()), ref.with("state" to "approved_by_push".json()), ref.with("runtime_epoch" to JsonNull))) assertThrows(ProtocolException::class.java) { NotificationReference.parse(bad) }
        val duplicate = jsonObject("items" to JsonArray(listOf(ref, ref)), "cursor" to JsonNull)
        assertThrows(ProtocolException::class.java) { NotificationPage.parse(duplicate) }
    }
}
