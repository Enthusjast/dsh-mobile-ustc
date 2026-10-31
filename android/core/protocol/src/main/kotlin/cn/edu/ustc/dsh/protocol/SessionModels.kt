package cn.edu.ustc.dsh.protocol

import java.util.Collections

const val SESSION_MODELS_CAPABILITY = "session.models.v1"
const val SESSION_MODEL_SELECT_CAPABILITY = "session.model.select.v1"
const val SESSION_MODELS_PAGE_BYTES = 32 * 1024

/** Native identifiers are opaque. Never trim, case-fold or substitute display labels. */
object SessionModelIdentifiers {
    fun id(value: String, maximum: Int = 128): String {
        if (value.length !in 1..maximum) throw ProtocolException()
        requireText(value)
        return value
    }
}

data class SessionModelLabel(val id: String, val label: String)
data class SessionModelItem(val provider: SessionModelLabel, val model: SessionModelLabel, val reasoningEfforts: List<SessionModelLabel>)
data class SessionModelSelection(val providerId: String, val modelId: String, val reasoningEffortId: String? = null) {
    init {
        SessionModelIdentifiers.id(providerId); SessionModelIdentifiers.id(modelId)
        reasoningEffortId?.let { SessionModelIdentifiers.id(it, 64) }
    }
}

/** Exact accepted snapshot, not a durable authorization token. */
data class SessionModelBinding(val runtimeId: String, val epoch: String, val sessionId: String, val subscriptionId: String, val syncId: String) {
    init { listOf(runtimeId, epoch, sessionId, subscriptionId, syncId).forEach(Contract::uuid) }
    internal fun envelope(type: String, requestId: String, payload: JsonObject) = jsonObject(
        "v" to 1L.json(), "type" to type.json(), "request_id" to Contract.uuid(requestId).json(),
        "runtime_id" to runtimeId.json(), "runtime_epoch" to epoch.json(), "session_id" to sessionId.json(),
        "subscription_id" to subscriptionId.json(), "payload" to payload)
}

class SessionModelsGet(val requestId: String, val binding: SessionModelBinding, val limit: Int, val cursor: String? = null) {
    init {
        Contract.uuid(requestId)
        if (limit !in 1..50) throw ProtocolException()
        cursor?.let(::modelCursor)
    }
    fun frame(): JsonObject {
        var payload = jsonObject("sync_id" to binding.syncId.json(), "limit" to limit.toLong().json())
        if (cursor != null) payload = payload.with("cursor" to cursor.json())
        return binding.envelope("session.models.get", requestId, payload)
    }
    companion object {
        fun parse(root: JsonObject): SessionModelsGet {
            modelEnvelope(root, "session.models.get", false)
            val payload = root.obj("payload")
            payload.exactKeys(*(setOf("sync_id", "limit") + if ("cursor" in payload.fields) setOf("cursor") else emptySet()).toTypedArray())
            val binding = modelBinding(root, payload.string("sync_id"))
            return SessionModelsGet(root.string("request_id"), binding, payload.integer("limit", 1, 50).toInt(),
                payload.fields["cursor"]?.let { (it as? JsonString)?.value ?: throw ProtocolException() })
        }
    }
}

class SessionModelsResult private constructor(val requestId: String, val binding: SessionModelBinding, val items: List<SessionModelItem>,
    val nextCursor: String?, val unavailableProviderCount: Int, val encodedBytes: Int) {
    companion object {
        fun parse(root: JsonObject): SessionModelsResult {
            modelEnvelope(root, "session.models.result", true)
            val bytes = modelPageBytes(root)
            if (bytes > SESSION_MODELS_PAGE_BYTES) throw ProtocolException()
            val payload = root.obj("payload")
            payload.exactKeys("items", "next_cursor", "unavailable_provider_count")
            val rawItems = payload.array("items")
            if (rawItems.size > 50) throw ProtocolException()
            val keys = HashSet<Pair<String, String>>()
            val items = rawItems.map { raw ->
                val item = raw as? JsonObject ?: throw ProtocolException()
                item.exactKeys("provider", "model", "reasoning_efforts")
                val provider = modelLabel(item.obj("provider"), 128)
                val model = modelLabel(item.obj("model"), 128)
                if (!keys.add(provider.id to model.id)) throw ProtocolException()
                val rawEfforts = item.array("reasoning_efforts")
                if (rawEfforts.size > 32) throw ProtocolException()
                val efforts = rawEfforts.map { modelLabel(it as? JsonObject ?: throw ProtocolException(), 64) }
                if (efforts.map { it.id }.toSet().size != efforts.size) throw ProtocolException()
                SessionModelItem(provider, model, Collections.unmodifiableList(efforts))
            }
            val cursor = when (val value = payload["next_cursor"]) {
                JsonNull -> null
                is JsonString -> modelCursor(value.value)
                else -> throw ProtocolException()
            }
            if (items.isEmpty() && cursor != null) throw ProtocolException()
            return SessionModelsResult(root.string("request_id"), modelBinding(root, root.string("sync_id")), Collections.unmodifiableList(items),
                cursor, payload.integer("unavailable_provider_count", 0, 128).toInt(), bytes)
        }
    }
}

class SessionModelsError private constructor(val requestId: String, val binding: SessionModelBinding, val code: String) {
    companion object {
        val codes: Set<String> = setOf("session.not_found", "runtime.changed", "access.denied", "protocol.snapshot_too_large",
            "protocol.resync_required", "rate.limited", "internal", "runtime.offline")
        fun parse(root: JsonObject): SessionModelsError {
            modelEnvelope(root, "session.models.error", true)
            val payload = root.obj("payload"); payload.exactKeys("code")
            val code = payload.string("code")
            if (code !in codes) throw ProtocolException()
            return SessionModelsError(root.string("request_id"), modelBinding(root, root.string("sync_id")), code)
        }
    }
}

private fun modelLabel(root: JsonObject, maximum: Int): SessionModelLabel {
    root.exactKeys("id", "label")
    val label = root.string("label")
    if (label.length !in 1..256 || label.any { it <= '\u001f' || it == '\u007f' }) throw ProtocolException()
    return SessionModelLabel(SessionModelIdentifiers.id(root.string("id"), maximum), label)
}
private fun modelCursor(value: String): String {
    if (value.length !in 1..1024) throw ProtocolException()
    requireText(value)
    return value
}
private fun modelBinding(root: JsonObject, sync: String) = SessionModelBinding(root.string("runtime_id"), root.string("runtime_epoch"),
    root.string("session_id"), root.string("subscription_id"), sync)
private fun modelEnvelope(root: JsonObject, type: String, sync: Boolean) {
    relayEnvelope(root, type, *(setOf("v", "type", "request_id", "runtime_id", "runtime_epoch", "session_id", "subscription_id", "payload") +
        if (sync) setOf("sync_id") else emptySet()).toTypedArray())
    listOf("request_id", "runtime_id", "runtime_epoch", "session_id", "subscription_id").forEach { Contract.uuid(root.string(it)) }
}
/** Relay's HTML-safe JSON escaping costs more than JCS for these scalars. */
private fun modelPageBytes(root: JsonObject): Int {
    val bytes = JsonDocument.of(root).canonicalBytes()
    var size = bytes.size
    for (index in bytes.indices) {
        if (bytes[index] == '<'.code.toByte() || bytes[index] == '>'.code.toByte() || bytes[index] == '&'.code.toByte()) size += 5
        if (index + 2 < bytes.size && bytes[index] == 0xe2.toByte() && bytes[index + 1] == 0x80.toByte() &&
            (bytes[index + 2] == 0xa8.toByte() || bytes[index + 2] == 0xa9.toByte())) size += 3
    }
    return size
}
