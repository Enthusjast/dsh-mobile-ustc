package cn.edu.ustc.dsh.protocol

const val SESSION_FORK_CAPABILITY = "session.fork.v1"

data class SessionActionBinding(val runtimeId: String, val epoch: String, val sessionId: String, val subscriptionId: String, val syncId: String) {
    init { listOf(runtimeId, epoch, sessionId, subscriptionId, syncId).forEach(Contract::uuid) }
    fun envelope(type: String, requestId: String, payload: JsonObject) = jsonObject(
        "v" to 1L.json(), "type" to type.json(), "request_id" to Contract.uuid(requestId).json(),
        "runtime_id" to runtimeId.json(), "runtime_epoch" to epoch.json(), "session_id" to sessionId.json(),
        "subscription_id" to subscriptionId.json(), "payload" to payload)
    companion object {
        fun parseFrame(root: JsonObject): SessionActionBinding {
            relayEnvelope(root, root.string("type"), "v", "type", "request_id", "runtime_id", "runtime_epoch", "session_id", "subscription_id", "sync_id", "payload")
            Contract.uuid(root.string("request_id"))
            return SessionActionBinding(root.string("runtime_id"), root.string("runtime_epoch"), root.string("session_id"), root.string("subscription_id"), root.string("sync_id"))
        }
    }
}

data class SessionForkAnchor(val subscriptionId: String, val syncId: String, val nativeSeq: Long, val messageVersionSha256: String, val anchorSha256: String) {
    init {
        Contract.uuid(subscriptionId); Contract.uuid(syncId); Contract.digest(messageVersionSha256); Contract.digest(anchorSha256)
        if (nativeSeq !in 0..MAX_SAFE_INTEGER) throw ProtocolException()
    }
    fun json() = jsonObject("v" to 1L.json(), "subscription_id" to subscriptionId.json(), "sync_id" to syncId.json(),
        "native_seq" to nativeSeq.json(), "message_version_sha256" to messageVersionSha256.json(), "anchor_sha256" to anchorSha256.json())
    companion object {
        fun parse(root: JsonObject): SessionForkAnchor {
            root.exactKeys("v", "subscription_id", "sync_id", "native_seq", "message_version_sha256", "anchor_sha256")
            root.integer("v", 1, 1)
            return SessionForkAnchor(root.string("subscription_id"), root.string("sync_id"), root.integer("native_seq", 0), root.string("message_version_sha256"), root.string("anchor_sha256"))
        }
    }
}

data class SessionForkOutcome(val workspaceAttachment: String, val checkpoint: String) {
    init {
        if (workspaceAttachment !in setOf("attached", "failed", "unknown") || checkpoint !in setOf("persisted", "unavailable", "failed", "unknown")) throw ProtocolException()
    }
    fun json() = jsonObject("v" to 1L.json(), "workspace_attachment" to workspaceAttachment.json(), "checkpoint" to checkpoint.json())
    companion object {
        fun parse(root: JsonObject): SessionForkOutcome {
            root.exactKeys("v", "workspace_attachment", "checkpoint"); root.integer("v", 1, 1)
            return SessionForkOutcome(root.string("workspace_attachment"), root.string("checkpoint"))
        }
    }
}

/** Conservative payload accounting matches both canonical JSON and Go's HTML-safe encoder. */
fun sessionActionPayloadBytes(root: JsonObject): Int {
    val bytes = JsonDocument.of(root).canonicalBytes()
    var size = bytes.size
    for (index in bytes.indices) {
        if (bytes[index] == 60.toByte() || bytes[index] == 62.toByte() || bytes[index] == 38.toByte()) size += 5
        if (index + 2 < bytes.size && bytes[index] == 0xe2.toByte() && bytes[index + 1] == 0x80.toByte() &&
            (bytes[index + 2] == 0xa8.toByte() || bytes[index + 2] == 0xa9.toByte())) size += 3
    }
    return size
}

val SESSION_ACTION_ERROR_CODES: Set<String> = setOf("session.not_found", "runtime.changed", "runtime.offline", "access.denied", "protocol.invalid",
    "protocol.snapshot_too_large", "protocol.resync_required", "rate.limited", "message.stale", "message.unavailable", "message.not_persisted",
    "changes.stale", "changes.unavailable", "changes.not_git", "changes.limit")

fun sessionActionError(root: JsonObject): String {
    root.exactKeys("code")
    return root.string("code").also { if (it !in SESSION_ACTION_ERROR_CODES || sessionActionPayloadBytes(root) > 256) throw ProtocolException() }
}
