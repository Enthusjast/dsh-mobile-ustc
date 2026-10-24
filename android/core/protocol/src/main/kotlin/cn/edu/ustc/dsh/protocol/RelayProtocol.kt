package cn.edu.ustc.dsh.protocol

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter
import java.util.Collections

const val RELAY_FRAME_BYTES = 64 * 1024
const val RELAY_SUBPROTOCOL = "dsh.remote.v1"
const val RELAY_PROOF_TYPE = "dsh-relay-handshake-proof+jwt"
const val RELAY_PROOF_AUDIENCE = "urn:dsh-mobile-ustc:realtime"

/** RFC 3339 transport times include the Go server's nanosecond precision; approval UTC remains stricter. */
fun relayTime(value: String): Long = try {
    if (value.length !in 20..40 || value.any { it <= ' ' || it >= '\u007f' }) throw ProtocolException()
    OffsetDateTime.parse(value, DateTimeFormatter.ISO_OFFSET_DATE_TIME).toInstant().toEpochMilli().also {
        if (it !in 0..MAX_SAFE_INTEGER) throw ProtocolException()
    }
} catch (_: Exception) { throw ProtocolException() }

/** Literal action/resource containment matches the service grant and ticket rules. */
class RelayScope(actions: Collection<String>, workspaces: Collection<String>, sessions: Collection<String>) {
    val actions = checked(actions, 64, false)
    val workspaces = checked(workspaces, 256, true)
    val sessions = checked(sessions, 256, true)
    fun json(): JsonObject = jsonObject("actions" to JsonArray(actions.map(String::json)), "workspaces" to JsonArray(workspaces.map(String::json)), "sessions" to JsonArray(sessions.map(String::json)))
    fun contains(other: RelayScope): Boolean = actions.containsAll(other.actions) && workspaces.containsAll(other.workspaces) && sessions.containsAll(other.sessions)
    fun same(other: RelayScope): Boolean = actions == other.actions && workspaces == other.workspaces && sessions == other.sessions
    fun readSession(sessionId: String, workspaceId: String?): RelayScope {
        Contract.uuid(sessionId); workspaceId?.let(Contract::uuid)
        if ("session.read" !in actions) throw ProtocolException()
        return when {
            sessionId in sessions -> RelayScope(listOf("session.read"), emptyList(), listOf(sessionId))
            workspaceId != null && workspaceId in workspaces -> RelayScope(listOf("session.read"), listOf(workspaceId), emptyList())
            else -> throw ProtocolException()
        }
    }
    companion object {
        fun parse(root: JsonObject): RelayScope {
            root.exactKeys("actions", "workspaces", "sessions")
            fun values(name: String) = root.array(name).map { (it as? JsonString)?.value ?: throw ProtocolException() }
            return RelayScope(values("actions"), values("workspaces"), values("sessions"))
        }
        private fun checked(values: Collection<String>, limit: Int, uuid: Boolean): Set<String> {
            if (values.size > limit || values.toSet().size != values.size) throw ProtocolException()
            values.forEach { if (uuid) Contract.uuid(it) else if (!Regex("[a-z][a-z0-9_.]{0,63}").matches(it)) throw ProtocolException() }
            return Collections.unmodifiableSet(values.toSortedSet())
        }
    }
}

class DeviceHello(val deviceId: String, capabilities: Collection<String>) {
    val capabilities: Set<String>
    init {
        Contract.uuid(deviceId)
        if (capabilities.size > 64 || capabilities.toSet().size != capabilities.size || capabilities.any { !Regex("[a-z][a-z0-9_.]{0,63}").matches(it) }) throw ProtocolException()
        this.capabilities = Collections.unmodifiableSet(capabilities.toSortedSet())
    }
    fun digest(): String {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { output ->
            output.write("dsh-mobile-ustc/relay-hello/v1\u0000".toByteArray(Charsets.UTF_8))
            listOf("device", deviceId, "1", capabilities.joinToString("\n")).forEach { part ->
                val encoded = part.toByteArray(Charsets.UTF_8); output.writeInt(encoded.size); output.write(encoded)
            }
        }
        return Contract.base64url(MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()))
    }
    fun frame(proof: String): JsonObject = jsonObject("v" to 1L.json(), "type" to "hello.proof".json(), "payload" to jsonObject(
        "device_id" to deviceId.json(), "protocols" to JsonArray(listOf(1L.json())), "capabilities" to JsonArray(capabilities.map(String::json)), "proof" to proof.json(),
    ))
}

class DeviceChallenge private constructor(val connectionId: String, val challengeId: String, val nonce: String, val expiresAt: Long) {
    companion object {
        fun parse(root: JsonObject, now: Long, ticketExpiresAt: Long): DeviceChallenge {
            relayEnvelope(root, "challenge", "v", "type", "payload")
            val payload = root.obj("payload"); payload.exactKeys("connection_id", "challenge_id", "nonce", "role", "expires_at")
            if (payload.string("role") != "device") throw ProtocolException()
            val nonce = payload.string("nonce")
            if (Contract.base64url(nonce).size != 32) throw ProtocolException()
            val expires = relayTime(payload.string("expires_at"))
            if (now < 0 || expires <= now || expires > now + 30_000 || expires > ticketExpiresAt) throw ProtocolException()
            return DeviceChallenge(Contract.uuid(payload.string("connection_id")), Contract.uuid(payload.string("challenge_id")), nonce, expires)
        }
    }
}

class DeviceConnection private constructor(
    val connectionId: String, val runtimeId: String, val deviceId: String, val grantVersion: Long,
    val scope: RelayScope, val capabilities: Set<String>, val leaseExpiresAt: Long, val connectedAt: Long,
) {
    companion object {
        fun parse(root: JsonObject, hello: DeviceHello, challenge: DeviceChallenge, runtimeId: String, grantVersion: Long,
            scope: RelayScope, now: Long, credentialExpiresAt: Long): DeviceConnection {
            relayEnvelope(root, "hello.ok", "v", "type", "payload")
            val payload = root.obj("payload")
            payload.exactKeys("role", "connection_id", "device_id", "runtime_id", "grant_version", "scope", "protocols", "capabilities", "server_time", "heartbeat_seconds", "max_frame_bytes", "lease_expires_at")
            val returnedScope = RelayScope.parse(payload.obj("scope"))
            if (payload.string("role") != "device" || payload.string("connection_id") != challenge.connectionId || payload.string("device_id") != hello.deviceId ||
                payload.string("runtime_id") != runtimeId || payload.integer("grant_version") != grantVersion || !scope.same(returnedScope) ||
                payload.array("protocols") != listOf(1L.json()) || payload.integer("heartbeat_seconds") != 20L || payload.integer("max_frame_bytes") != RELAY_FRAME_BYTES.toLong()) throw ProtocolException()
            val capabilities = payload.array("capabilities").map { (it as? JsonString)?.value ?: throw ProtocolException() }
            if (capabilities.toSet().size != capabilities.size || !hello.capabilities.containsAll(capabilities) || !capabilities.containsAll(listOf("connection.heartbeat.v1", "session.read.v1"))) throw ProtocolException()
            val serverTime = relayTime(payload.string("server_time"))
            val expires = relayTime(payload.string("lease_expires_at"))
            if (now < 0 || kotlin.math.abs(serverTime - now) > 30_000 || expires <= serverTime || expires - serverTime > 300_000 || expires <= now || credentialExpiresAt <= now) throw ProtocolException()
            return DeviceConnection(challenge.connectionId, Contract.uuid(runtimeId), hello.deviceId, grantVersion, returnedScope,
                Collections.unmodifiableSet(capabilities.toSortedSet()), minOf(expires, now + (expires - serverTime), credentialExpiresAt), now)
        }
    }
}

fun relayEnvelope(root: JsonObject, type: String, vararg fields: String) {
    root.exactKeys(*fields)
    if (root.integer("v", 1, 1) != 1L || root.string("type") != type) throw ProtocolException()
}

fun relayFrame(bytes: ByteArray): JsonObject {
    if (bytes.size > RELAY_FRAME_BYTES) throw ProtocolException()
    return JsonDocument.parse(bytes).root
}
