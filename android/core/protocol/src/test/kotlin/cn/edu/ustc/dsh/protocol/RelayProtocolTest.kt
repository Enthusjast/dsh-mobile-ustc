package cn.edu.ustc.dsh.protocol

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.time.Instant

class RelayProtocolTest {
    private val now = 1_792_886_400_000L
    private val device = "22222222-2222-4222-8222-222222222222"
    private val runtime = "33333333-3333-4333-8333-333333333333"
    private val connection = "44444444-4444-4444-8444-444444444444"
    private val challengeId = "55555555-5555-4555-8555-555555555555"
    private val session = "66666666-6666-4666-8666-666666666666"
    private val workspace = "77777777-7777-4777-8777-777777777777"
    private val caps = listOf("connection.heartbeat.v1", "session.read.v1")
    private val scope = RelayScope(listOf("session.read"), emptyList(), listOf(session))
    private fun time(at: Long) = Instant.ofEpochMilli(at).toString().json()
    private fun challenge() = jsonObject("v" to 1L.json(), "type" to "challenge".json(), "payload" to jsonObject(
        "role" to "device".json(), "connection_id" to connection.json(), "challenge_id" to challengeId.json(), "nonce" to "A".repeat(43).json(), "expires_at" to time(now + 10_000)))
    private fun accepted() = jsonObject("v" to 1L.json(), "type" to "hello.ok".json(), "payload" to jsonObject(
        "role" to "device".json(), "connection_id" to connection.json(), "device_id" to device.json(), "runtime_id" to runtime.json(), "grant_version" to 7L.json(),
        "scope" to scope.json(), "protocols" to JsonArray(listOf(1L.json())), "capabilities" to JsonArray(caps.map(String::json)), "server_time" to time(now),
        "heartbeat_seconds" to 20L.json(), "max_frame_bytes" to RELAY_FRAME_BYTES.toLong().json(), "lease_expires_at" to time(now + 300_000)))

    @Test fun helloDigestMatchesTheSharedLengthPrefixedGoNodeEncoding() {
        val fixture = JsonDocument.parse(File(System.getProperty("contracts.root"), "security/relay-device-hello.json").readBytes()).root
        val expected = fixture.string("hello_sha256")
        assertEquals(expected, DeviceHello(device, caps).digest())
        assertEquals(expected, DeviceHello(device, caps.reversed()).digest())
        assertNotEquals(expected, DeviceHello(runtime, caps).digest())
        assertThrows(ProtocolException::class.java) { DeviceHello(device, caps + caps.first()) }
    }

    @Test fun scopeSelectionUsesOnlyAnExplicitSessionOrItsActuallyGrantedWorkspace() {
        val granted = RelayScope(listOf("session.list", "session.read"), listOf(workspace), listOf(session))
        assertTrue(granted.contains(scope))
        assertTrue(granted.readSession(session, workspace).same(scope))
        val onlyWorkspace = RelayScope(listOf("session.read"), listOf(workspace), emptyList())
        assertTrue(onlyWorkspace.readSession(session, workspace).same(onlyWorkspace))
        assertThrows(ProtocolException::class.java) { onlyWorkspace.readSession(session, null) }
        assertThrows(ProtocolException::class.java) { onlyWorkspace.readSession(session, runtime) }
        assertThrows(ProtocolException::class.java) { RelayScope(listOf("session.list"), listOf(workspace), listOf(session)).readSession(session, workspace) }
        assertFalse(onlyWorkspace.contains(scope))
        assertThrows(ProtocolException::class.java) { RelayScope(listOf("session.read"), listOf(workspace, workspace), emptyList()) }
    }

    @Test fun challengesBindExactRoleIdsFreshNonceAndTicketLifetime() {
        assertEquals(connection, DeviceChallenge.parse(challenge(), now, now + 30_000).connectionId)
        for (changed in listOf(
            challenge().with("extra" to JsonNull), challenge().with("v" to 2L.json()),
            challenge().with("payload" to challenge().obj("payload").with("role" to "installation".json())),
            challenge().with("payload" to challenge().obj("payload").with("nonce" to "A".repeat(42).json())),
            challenge().with("payload" to challenge().obj("payload").with("expires_at" to time(now))),
            challenge().with("payload" to challenge().obj("payload").with("expires_at" to time(now + 31_000))),
        )) assertThrows(ProtocolException::class.java) { DeviceChallenge.parse(changed, now, now + 30_000) }
        assertThrows(ProtocolException::class.java) { DeviceChallenge.parse(challenge(), now, now + 5000) }
        assertEquals(1_792_886_400_123L, relayTime("2026-10-25T00:00:00.123456789Z"))
        assertThrows(ProtocolException::class.java) { relayTime("2026-02-30T00:00:00Z") }
    }

    @Test fun acceptanceCannotChangeAuthorityCapabilitiesLeaseOrConnectionLimits() {
        val hello = DeviceHello(device, caps)
        val challenge = DeviceChallenge.parse(challenge(), now, now + 30_000)
        fun parse(root: JsonObject) = DeviceConnection.parse(root, hello, challenge, runtime, 7, scope, now, now + 60_000)
        assertEquals(now + 60_000, parse(accepted()).leaseExpiresAt)
        val payload = accepted().obj("payload")
        for (bad in listOf(
            payload.with("connection_id" to runtime.json()), payload.with("device_id" to runtime.json()), payload.with("runtime_id" to device.json()),
            payload.with("grant_version" to 8L.json()), payload.with("scope" to RelayScope(listOf("session.read", "message.submit"), emptyList(), listOf(session)).json()),
            payload.with("capabilities" to JsonArray((caps + "approval.signed.v1").map(String::json))),
            payload.with("capabilities" to JsonArray(listOf("connection.heartbeat.v1".json()))),
            payload.with("heartbeat_seconds" to 60L.json()), payload.with("max_frame_bytes" to 1_000_000L.json()),
            payload.with("lease_expires_at" to time(now + 300_001)), payload.with("server_time" to time(now + 30_001)),
        )) assertThrows(ProtocolException::class.java) { parse(accepted().with("payload" to bad)) }
    }

    @Test fun wireFramesRejectOversizeDuplicateFieldsAndMalformedUtf8() {
        val raw = JsonDocument.of(challenge()).canonicalBytes()
        assertEquals("challenge", relayFrame(raw).string("type"))
        assertThrows(ProtocolException::class.java) { relayFrame(ByteArray(RELAY_FRAME_BYTES + 1)) }
        assertThrows(ProtocolException::class.java) { relayFrame("{\"v\":1,\"v\":1}".toByteArray()) }
        assertThrows(ProtocolException::class.java) { relayFrame(byteArrayOf(123, 34, 0xc0.toByte(), 34, 58, 49, 125)) }
    }
}
