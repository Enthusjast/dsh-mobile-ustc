package cn.edu.ustc.dsh.session

import cn.edu.ustc.dsh.protocol.*
import java.io.ByteArrayOutputStream
import java.util.Base64

data class SessionRoute(val runtimeId: String, val epoch: String, val sessionId: String, val subscriptionId: String) {
    init { listOf(runtimeId, epoch, sessionId, subscriptionId).forEach(Contract::uuid) }
    fun matches(frame: JsonObject): Boolean = frame.string("runtime_id") == runtimeId && frame.string("runtime_epoch") == epoch && frame.string("session_id") == sessionId && frame.string("subscription_id") == subscriptionId
}

class SessionContent(val type: String, val requestId: String, val syncId: String, val payload: JsonObject)

/** One logical content group per subscription. Incomplete payloads never reach the window. */
class SessionFragments(private val route: SessionRoute) {
    companion object {
        private val types = setOf("session.snapshot", "session.event", "session.checkpoint", "session.page.result", "assistant.start", "assistant.chunk", "assistant.end","question.snapshot","question.timed.snapshot")
        private val fields = setOf("v", "type", "request_id", "runtime_id", "runtime_epoch", "session_id", "subscription_id", "payload", "sync_id")
    }
    private class Partial(val id: String, val type: String, val request: String, val sync: String, val count: Int, val started: Long) {
        val bytes = ByteArrayOutputStream()
        var next = 0
    }
    private var partial: Partial? = null
    fun pendingMillis(nowNanos: Long = System.nanoTime()): Long? = partial?.let { ((it.started + 10_000_000_000 - nowNanos) / 1_000_000).coerceAtLeast(0) }
    fun clear() { partial = null }
    fun accept(frame: JsonObject, nowNanos: Long = System.nanoTime()): SessionContent? {
        SessionJson.fields(frame, fields)
        if (frame.integer("v", 1, 1) != 1L || !route.matches(frame)) throw SessionDataException()
        val request = Contract.uuid(frame.string("request_id")); val sync = Contract.uuid(frame.string("sync_id"))
        val kind = frame.string("type")
        if (kind != "session.fragment") {
            if (partial != null || kind !in types) throw SessionDataException()
            return SessionContent(kind, request, sync, frame.obj("payload"))
        }
        val payload = frame.obj("payload"); payload.exactKeys("type", "fragment_id", "index", "count", "data")
        val type = payload.string("type")
        if (type !in types) throw SessionDataException("protocol.unsupported")
        val id = Contract.uuid(payload.string("fragment_id"))
        val index = payload.integer("index", 0, 51).toInt(); val count = payload.integer("count", 2, 52).toInt()
        val encoded = payload.string("data")
        if (encoded.length !in 4..54616 || encoded.length % 4 != 0 || !Regex("[A-Za-z0-9+/]+={0,2}").matches(encoded)) throw SessionDataException()
        val bytes = try { Base64.getDecoder().decode(encoded) } catch (_: Exception) { throw SessionDataException() }
        if (bytes.size !in 1..40 * 1024 || Base64.getEncoder().encodeToString(bytes) != encoded) throw SessionDataException()
        if (partial == null) {
            if (index != 0) throw SessionDataException()
            partial = Partial(id, type, request, sync, count, nowNanos)
        }
        val pending = partial!!
        if (pending.id != id || pending.type != type || pending.request != request || pending.sync != sync || pending.count != count || pending.next != index || index >= count ||
            nowNanos < pending.started || nowNanos - pending.started > 10_000_000_000) throw SessionDataException()
        if (pending.bytes.size() + bytes.size > SESSION_PAYLOAD_BYTES) throw SessionDataException("protocol.snapshot_too_large")
        pending.bytes.write(bytes); pending.next++
        if (pending.next != count) return null
        partial = null
        return SessionContent(type, request, sync, SessionJson.parse(pending.bytes.toByteArray()))
    }
}
