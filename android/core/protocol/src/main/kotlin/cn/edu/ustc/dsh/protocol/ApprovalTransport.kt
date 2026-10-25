package cn.edu.ustc.dsh.protocol

import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.Collections

const val SIGNED_APPROVAL_CAPABILITY = "approval.signed.v1"

enum class ApprovalRemoteState(val wire: String) {
    PENDING("pending"), DECISION_RECEIVED("decision_received"), ALLOWED("allowed"), DENIED("denied"),
    EXPIRED("expired"), CANCELLED("cancelled"), INVALIDATED("invalidated"), OUTCOME_UNKNOWN("outcome_unknown");
}
enum class ApprovalHostState(val wire: String) {
    APPROVED("approved"), DENIED("denied"), CONSUMED("consumed"), SETTLED("settled"),
    EXPIRED("expired"), CANCELLED("cancelled"), INVALIDATED("invalidated"), OUTCOME_UNKNOWN("outcome_unknown");
}
enum class ApprovalExecutionOutcome(val wire: String) { SUCCEEDED("succeeded"), FAILED("failed"), CANCELLED("cancelled") }
enum class ApprovalDelivery(val wire: String) { PENDING("pending"), FORWARDED("forwarded"), RECORDED("recorded") }

/** Durable server metadata. It contains neither a tool body nor execution authority. */
class ApprovalStatus private constructor(val document: JsonDocument) {
    val root get() = document.root
    val id = root.string("approval_id")
    val runtimeId = root.string("runtime_id")
    val epoch = root.string("runtime_epoch")
    val sessionId = root.string("session_id")
    val executionId = root.string("execution_id")
    val bindingSha256 = root.string("binding_sha256")
    val expiresAt = relayTime(root.string("expires_at"))
    val state = wireEnum<ApprovalRemoteState>(root.string("state")) { it.wire }
    val decision = root.fields["decision"]?.let { wireEnum<ApprovalChoice>(root.string("decision")) { it.wire } }
    val decisionSha256 = root.fields["decision_payload_sha256"]?.let { Contract.digest(root.string("decision_payload_sha256")) }
    val hostState = root.fields["host_state"]?.let { wireEnum<ApprovalHostState>(root.string("host_state")) { it.wire } }
    val outcome = root.fields["execution_outcome"]?.let { wireEnum<ApprovalExecutionOutcome>(root.string("execution_outcome")) { it.wire } }

    fun pending(now: Long): Boolean = now >= 0 && state == ApprovalRemoteState.PENDING && decision == null && decisionSha256 == null && hostState == null && expiresAt > now
    fun sameRequest(other: ApprovalStatus): Boolean = id == other.id && runtimeId == other.runtimeId && epoch == other.epoch &&
        sessionId == other.sessionId && executionId == other.executionId && bindingSha256 == other.bindingSha256 && expiresAt == other.expiresAt
    fun matches(context: ApprovalContext): Boolean = root.string("approval_id") == context.root.string("approval_id") &&
        runtimeId == context.root.string("runtime_id") && epoch == context.root.string("runtime_epoch") && sessionId == context.root.string("session_id") &&
        executionId == context.root.string("execution_id") && bindingSha256 == context.bindingSha256 && expiresAt == context.expiresAt
    override fun toString() = "ApprovalStatus(${state.wire})"

    companion object {
        fun parse(root: JsonObject): ApprovalStatus {
            approvalFields(root, setOf("approval_id", "runtime_id", "runtime_epoch", "session_id", "execution_id", "binding_sha256", "state", "expires_at"),
                setOf("decision", "decision_payload_sha256", "host_state", "execution_outcome"))
            listOf("approval_id", "runtime_id", "runtime_epoch", "session_id", "execution_id").forEach { Contract.uuid(root.string(it)) }
            Contract.digest(root.string("binding_sha256"))
            return ApprovalStatus(JsonDocument.of(root)).also {
                if ((it.hostState == ApprovalHostState.SETTLED) != (it.outcome != null)) throw ProtocolException()
            }
        }
    }
}

class ApprovalAdmission private constructor(val status: ApprovalStatus, val delivery: ApprovalDelivery) {
    companion object {
        fun parse(root: JsonObject, expected: ApprovalStatus, choice: ApprovalChoice, decisionSha256: String): ApprovalAdmission {
            root.exactKeys("status", "delivery")
            Contract.digest(decisionSha256)
            val status = ApprovalStatus.parse(root.obj("status"))
            if (!expected.sameRequest(status) || status.decision != choice || status.decisionSha256 != decisionSha256 || status.state == ApprovalRemoteState.PENDING) throw ProtocolException()
            return ApprovalAdmission(status, wireEnum<ApprovalDelivery>(root.string("delivery")) { it.wire })
        }
    }
}

object ApprovalTransport {
    fun subscribe(runtime: String, request: String) = runtimeFrame("approval.subscribe", runtime, request, jsonObject())
    fun unsubscribe(runtime: String, request: String) = runtimeFrame("approval.unsubscribe", runtime, request, jsonObject())
    fun status(runtime: String, request: String, approval: String) = runtimeFrame("approval.status.get", runtime, request, jsonObject("approval_id" to Contract.uuid(approval).json()))
    fun details(reference: ApprovalStatus, request: String) = runtimeFrame("approval.details.get", reference.runtimeId, request, jsonObject("approval_id" to reference.id.json()))
        .with("runtime_epoch" to reference.epoch.json(), "session_id" to reference.sessionId.json())

    fun snapshot(frame: JsonObject, runtime: String, request: String): List<ApprovalStatus> {
        relayEnvelope(frame, "approval.snapshot", "v", "type", "request_id", "runtime_id", "payload")
        runtimeRoute(frame, runtime, request)
        val payload = frame.obj("payload"); payload.exactKeys("items")
        val items = payload.array("items")
        if (items.size > 64) throw ProtocolException()
        val statuses = items.map { ApprovalStatus.parse(it as? JsonObject ?: throw ProtocolException()) }
        if (statuses.any { it.runtimeId != runtime } || statuses.map { it.id }.toSet().size != statuses.size) throw ProtocolException()
        return Collections.unmodifiableList(statuses)
    }

    fun reference(frame: JsonObject, runtime: String, request: String): ApprovalStatus {
        scopedEnvelope(frame, "approval.reference", runtime, request)
        val payload = frame.obj("payload"); payload.exactKeys("status")
        return ApprovalStatus.parse(payload.obj("status")).also {
            if (it.runtimeId != runtime || it.epoch != frame.string("runtime_epoch") || it.sessionId != frame.string("session_id")) throw ProtocolException()
        }
    }

    fun error(frame: JsonObject, reference: ApprovalStatus, request: String): String {
        scopedEnvelope(frame, "approval.error", reference.runtimeId, request)
        if (frame.string("runtime_epoch") != reference.epoch || frame.string("session_id") != reference.sessionId) throw ProtocolException()
        val payload = frame.obj("payload"); payload.exactKeys("approval_id", "code")
        if (payload.string("approval_id") != reference.id) throw ProtocolException()
        return payload.string("code").also { if (it !in setOf("approval.stale", "approval.expired", "internal")) throw ProtocolException() }
    }

    private fun runtimeFrame(type: String, runtime: String, request: String, payload: JsonObject) = jsonObject(
        "v" to 1L.json(), "type" to type.json(), "request_id" to Contract.uuid(request).json(), "runtime_id" to Contract.uuid(runtime).json(), "payload" to payload)
    internal fun scopedEnvelope(frame: JsonObject, type: String, runtime: String, request: String) {
        relayEnvelope(frame, type, "v", "type", "request_id", "runtime_id", "runtime_epoch", "session_id", "payload")
        runtimeRoute(frame, runtime, request)
        Contract.uuid(frame.string("runtime_epoch")); Contract.uuid(frame.string("session_id"))
    }
    private fun runtimeRoute(frame: JsonObject, runtime: String, request: String) {
        Contract.uuid(runtime); Contract.uuid(request)
        if (frame.string("runtime_id") != runtime || frame.string("request_id") != request) throw ProtocolException()
    }
}

/** One solicited online context. Incomplete, stale or malformed parts never expose a body. */
class ApprovalDetailsTransfer(val reference: ApprovalStatus, val requestId: String, private val hostId: String) : AutoCloseable {
    private class Partial(val id: String, val count: Int, val started: Long) {
        val bytes = ByteArrayOutputStream()
        var next = 0
    }
    private var partial: Partial? = null
    private var ended = false
    init { Contract.uuid(requestId); Contract.uuid(hostId) }
    fun pendingMillis(nowNanos: Long = System.nanoTime()): Long? = partial?.let { ((it.started + 3_000_000_000 - nowNanos) / 1_000_000).coerceAtLeast(0) }

    fun accept(frame: JsonObject, nowNanos: Long = System.nanoTime()): ApprovalContext? {
        try {
            if (ended || JsonDocument.of(frame).canonicalBytes().size > RELAY_FRAME_BYTES) throw ProtocolException()
            val type = frame.string("type")
            ApprovalTransport.scopedEnvelope(frame, type, reference.runtimeId, requestId)
            if (frame.string("runtime_epoch") != reference.epoch || frame.string("session_id") != reference.sessionId) throw ProtocolException()
            val payload = frame.obj("payload")
            val context = when (type) {
                "approval.details" -> {
                    if (partial != null) throw ProtocolException()
                    payload.exactKeys("context")
                    ApprovalContext.from(JsonDocument.of(payload.obj("context")))
                }
                "approval.fragment" -> {
                    payload.exactKeys("kind", "transfer_id", "index", "count", "data")
                    if (payload.string("kind") != "approval.details") throw ProtocolException()
                    val id = Contract.uuid(payload.string("transfer_id"))
                    val count = payload.integer("count", 1, 4).toInt()
                    val index = payload.integer("index", 0, 3).toInt()
                    if (index >= count) throw ProtocolException()
                    val data = payload.string("data")
                    if (data.length !in 4..54_616 || data.length % 4 != 0 || !Regex("[A-Za-z0-9+/]+={0,2}").matches(data)) throw ProtocolException()
                    val bytes = try { Base64.getDecoder().decode(data) } catch (_: Exception) { throw ProtocolException() }
                    if (bytes.size !in 1..40 * 1024 || Base64.getEncoder().encodeToString(bytes) != data) throw ProtocolException()
                    if (partial == null) {
                        if (index != 0) throw ProtocolException()
                        partial = Partial(id, count, nowNanos)
                    }
                    val current = partial!!
                    if (current.id != id || current.count != count || current.next != index || nowNanos < current.started || nowNanos - current.started >= 3_000_000_000 ||
                        current.bytes.size() + bytes.size > JsonDocument.MAX_BYTES) throw ProtocolException()
                    current.bytes.write(bytes); current.next++
                    if (current.next != count) return null
                    ApprovalContext.parse(current.bytes.toByteArray())
                }
                else -> throw ProtocolException()
            }
            if (!reference.matches(context) || context.root.string("host_id") != hostId) throw ProtocolException()
            close()
            return context
        } catch (error: Exception) {
            close()
            if (error is ProtocolException) throw error
            throw ProtocolException()
        }
    }

    override fun close() { partial?.bytes?.reset(); partial = null; ended = true }
}

private inline fun <reified T : Enum<T>> wireEnum(value: String, wire: (T) -> String): T = enumValues<T>().firstOrNull { wire(it) == value } ?: throw ProtocolException()
private fun approvalFields(root: JsonObject, required: Set<String>, optional: Set<String>) {
    if (!root.fields.keys.containsAll(required) || root.fields.keys.any { it !in required && it !in optional }) throw ProtocolException()
}
