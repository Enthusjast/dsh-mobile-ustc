package cn.edu.ustc.dsh.session

import cn.edu.ustc.dsh.protocol.*
import java.util.Collections
import java.util.TreeMap

enum class ConversationRole { USER, ASSISTANT, TOOL, NOTICE }
class ConversationItem(val id: String, val role: ConversationRole, val blocks: List<DisplayBlock>, val live: Boolean, val persisted: Boolean, val interrupted: Boolean = false) {
    override fun toString() = "ConversationItem($role, live=$live)"
}
class SessionRecord private constructor(val seq: Long, val type: String, val data: JsonObject, val raw: JsonObject, val blocks: List<DisplayBlock>, val replacement: Boolean,
    private val versionRoot: JsonObject, initialVersion: String?) {
    val weight = SessionJson.weight(raw)
    private var cachedVersion = initialVersion
    val messageVersionSha256: String get() = synchronized(this) { cachedVersion ?: mediaEventSha256(SessionJson.encode(versionRoot)).also { cachedVersion = it } }
    companion object {
        fun parse(root: JsonObject, mediaRefs: Boolean = false): SessionRecord {
            SessionJson.fields(root, setOf("native_seq", "time", "type", "data"), setOf("surface_op", "source_event_seqs"))
            val seq = root.integer("native_seq", 0)
            val time = (root["time"] as? JsonNumber)?.value ?: throw SessionDataException()
            if (!time.isFinite() || kotlin.math.abs(time) > MAX_SAFE_INTEGER) throw SessionDataException()
            val type = Contract.boundedText(root.string("type"), 128)
            val data = root.obj("data")
            var replacement = false
            root.fields["surface_op"]?.let { operation ->
                if (operation != "append".json()) {
                    val replace = operation as? JsonObject ?: throw SessionDataException()
                    replace.exactKeys("op", "startSeq", "endSeq")
                    if (replace.string("op") != "replace" || replace.integer("startSeq", 0) > replace.integer("endSeq", 0) || replace.integer("endSeq", 0) >= seq) throw SessionDataException()
                    replacement = true
                }
            }
            var blocks: List<DisplayBlock> = emptyList()
            var lastMediaIndex = -1
            fun content(source: JsonObject): List<DisplayBlock> = source.array("content").map { value ->
                val block = value as? JsonObject ?: throw SessionDataException()
                if (block.string("type") == "image") {
                    if (!mediaRefs) throw SessionDataException("protocol.unsupported")
                    block.exactKeys("type", "reference")
                    val reference = VisibleMediaReference.parse(block.obj("reference"))
                    if (reference.nativeSeq != seq || reference.partIndex <= lastMediaIndex) throw SessionDataException()
                    lastMediaIndex = reference.partIndex
                    DisplayBlock(BlockKind.IMAGE, "", reference.manifest.name, complete = true, media = reference)
                } else {
                    block.exactKeys("type", "text")
                    DisplayBlock(when (block.string("type")) { "text" -> BlockKind.TEXT; "reasoning" -> BlockKind.REASONING; else -> throw SessionDataException("protocol.unsupported") }, block.string("text"), complete = true)
                }
            }
            when (type) {
                "cursor" -> data.exactKeys()
                "user/message" -> { SessionJson.fields(data, setOf("content"), setOf("id")); blocks = content(data) }
                "assistant/message", "tool/result" -> {
                    SessionJson.fields(data, setOf("message"), setOf("turn", "step", "interrupted"))
                    val message = data.obj("message")
                    SessionJson.fields(message, setOf("content"), setOf("id", "callId", "isError")); blocks = content(message)
                }
                "assistant/attempt" -> {
                    SessionJson.fields(data, setOf("stream"), setOf("turn", "step"))
                    blocks = StreamBlocks().apply { compact(data.array("stream")) }.snapshot()
                }
                "tool/call" -> {
                    SessionJson.fields(data, setOf("callId", "name", "arguments"), setOf("turn", "step"))
                    blocks = listOf(DisplayBlock(BlockKind.TOOL, "", Contract.boundedText(data.string("name"), 256), Contract.boundedText(data.string("callId"), 2048)))
                }
                "turn/start", "turn/end" -> SessionJson.fields(data, setOf("turn"), if (type == "turn/end") setOf("reason") else emptySet())
                "step/start", "step/end" -> data.exactKeys("turn", "step")
                "approval/asked" -> SessionJson.fields(data, emptySet(), setOf("id", "toolName", "callId", "reason"))
                "approval/decided" -> SessionJson.fields(data, emptySet(), setOf("id", "outcome"))
                else -> throw SessionDataException("protocol.unsupported")
            }
            for (number in listOf("turn", "step")) if (number in data.fields) data.integer(number, 0)
            if ("interrupted" in data.fields) SessionJson.boolean(data, "interrupted")
            val references = blocks.mapNotNull { it.media }
            var ordinary = root
            var version: String? = null
            if (references.isNotEmpty()) {
                val message = if (type == "user/message") data else data.obj("message")
                val legacy = JsonArray(message.array("content").map { value ->
                    val block = value as JsonObject
                    if (block.string("type") == "image") jsonObject("type" to "text".json(), "text" to LEGACY_IMAGE_NOTICE.json()) else block
                })
                val legacyData = if (type == "user/message") data.with("content" to legacy) else data.with("message" to message.with("content" to legacy))
                ordinary = root.with("data" to legacyData)
                version = mediaEventSha256(SessionJson.encode(ordinary))
                if (references.any { it.eventVersionSha256 != version }) throw SessionDataException()
            }
            return SessionRecord(seq, type, data, root, Collections.unmodifiableList(blocks), replacement, ordinary, version)
        }
    }
}

class SessionTranscript internal constructor(
    val records: List<SessionRecord>, val cursor: Long, val openingCursor: Long, val hasMore: Boolean,
    val persistedThrough: Long, val checkpoint: String, val items: List<ConversationItem>, val taskRunning: Boolean,
    val durableOnly: Boolean = false,
) {
    override fun toString() = "SessionTranscript(records=${records.size})"
}
class SessionPageRequest(val requestId: String, val payload: JsonObject)

/** One acknowledged subscription/sync. A replacement snapshot discards old transient and observation state. */
class SessionWindow(private val subscribeRequest: String, private val mediaRefs: Boolean = false) {
    companion object { const val MAX_RECORDS = 4096; const val MAX_RETAINED_WEIGHT = 8L * 1024 * 1024 }
    private class Attempt(val id: String, val after: Long, val turn: Long, val step: Long, var next: Long, val blocks: StreamBlocks)
    private class Page(val id: String, val before: Long)
    private val records = TreeMap<Long, SessionRecord>()
    private var retainedWeight = 0L
    private var sync: String? = null
    private val retiredSyncs = linkedSetOf<String>()
    private var openingPayload: JsonObject? = null
    private var opening = -1L
    private var cursor = -1L
    private var more = false
    private var persisted = -1L
    private var checkpoint = "unavailable"
    private var revision: Long? = null
    private var lastAssistant: JsonObject? = null
    private var active: Attempt? = null
    private var held: SessionRecord? = null
    private var heldAt = 0L
    private var page: Page? = null
    val ready get() = sync != null
    val paging get() = page != null
    val syncId get() = sync
    fun acceptsSync(value: String): Boolean = if(value==sync) true else if(value in retiredSyncs) false else throw SessionDataException()
    fun settlementMillis(nowNanos: Long = System.nanoTime()): Long? = held?.let { ((heldAt + 10_000_000_000 - nowNanos) / 1_000_000).coerceAtLeast(0) }

    fun accept(content: SessionContent, nowNanos: Long = System.nanoTime()): Boolean {
        if (content.type == "session.snapshot") {
            if (content.requestId != subscribeRequest) throw SessionDataException()
            if (content.syncId == sync) {
                if (openingPayload?.let { SessionJson.same(it, content.payload) } != true) throw SessionDataException()
                return false
            }
            if (content.syncId in retiredSyncs) return false
            replace(content, nowNanos); return true
        }
        if (!ready) throw SessionDataException()
        if (content.syncId != sync) { if (content.syncId in retiredSyncs) return false; throw SessionDataException() }
        if (content.type == "session.page.result") return prepend(content)
        if (content.requestId != subscribeRequest) throw SessionDataException()
        val payload = content.payload
        when (content.type) {
            "session.event" -> {
                val record = SessionRecord.parse(payload, mediaRefs)
                if (record.seq <= cursor) {
                    records[record.seq]?.let { if (!SessionJson.same(it.raw, record.raw)) throw SessionDataException() }
                    return false
                }
                if (record.seq != cursor + 1) throw SessionDataException()
                budget(records.size + 1, retainedWeight + record.weight)
                records[record.seq] = record; retainedWeight += record.weight; cursor = record.seq
                val attempt = active
                if (attempt != null && record.type in setOf("assistant/message", "assistant/attempt") && !record.replacement && record.seq > attempt.after &&
                    (record.data.fields["turn"] as? JsonNumber)?.value == attempt.turn.toDouble() && (record.data.fields["step"] as? JsonNumber)?.value == attempt.step.toDouble()) {
                    if (held != null) throw SessionDataException()
                    held = record; heldAt = nowNanos
                }
            }
            "session.checkpoint" -> {
                when (payload.string("state")) {
                    "persisted" -> {
                        payload.exactKeys("state", "through_seq")
                        val through = payload.integer("through_seq", -1)
                        if (through < persisted) throw SessionDataException()
                        persisted = through; checkpoint = "persisted"
                    }
                    "unavailable", "failed" -> { payload.exactKeys("state"); checkpoint = payload.string("state") }
                    else -> throw SessionDataException()
                }
            }
            "assistant.start", "assistant.chunk", "assistant.end" -> assistant(content.type, payload)
            else -> throw SessionDataException("protocol.unsupported")
        }
        return true
    }

    private fun replace(content: SessionContent, nowNanos: Long) {
        val payload = content.payload; payload.exactKeys("cursor", "has_more", "records", "assistant")
        val cut = payload.integer("cursor", -1)
        val entries = parseRecords(payload.array("records"))
        val hasMore = SessionJson.boolean(payload, "has_more")
        if (cut == -1L && entries.isNotEmpty() || cut >= 0 && (entries.isEmpty() || entries.last().seq != cut) || hasMore != (entries.firstOrNull()?.seq?.let { it > 0 } ?: false)) throw SessionDataException()
        var nextRevision: Long? = null
        var attempt: Attempt? = null
        if (payload["assistant"] != JsonNull) {
            val baseline = payload.obj("assistant"); SessionJson.fields(baseline, setOf("revision"), setOf("activeAttempt"))
            nextRevision = baseline.integer("revision", 0)
            if ("activeAttempt" in baseline.fields) {
                val live = baseline.obj("activeAttempt"); live.exactKeys("attemptId", "startedAfterSeq", "turn", "step", "nextIndex", "stream")
                val next = live.integer("nextIndex", 0, SESSION_MAX_NODES.toLong())
                attempt = Attempt(Contract.boundedText(live.string("attemptId"), 2048), live.integer("startedAfterSeq", -1), live.integer("turn", 0), live.integer("step", 0), next,
                    StreamBlocks().apply { compact(live.array("stream"), next) })
            }
        }
        val weight = entries.sumOf(SessionRecord::weight)
        budget(entries.size, weight)
        sync?.let { retiredSyncs += it }; if (retiredSyncs.size > 32) throw SessionDataException("protocol.resync_required")
        records.clear(); entries.forEach { records[it.seq] = it }; retainedWeight = weight
        opening = cut; cursor = cut; more = hasMore; persisted = -1; checkpoint = "unavailable"
        sync = content.syncId; openingPayload = payload; revision = nextRevision; active = attempt; lastAssistant = null; held = null; heldAt = nowNanos; page = null
    }
    private fun parseRecords(values: List<JsonValue>): List<SessionRecord> {
        if (values.size > MAX_RECORDS) throw SessionDataException("client.history_limit")
        val result = values.map { SessionRecord.parse(it as? JsonObject ?: throw SessionDataException(), mediaRefs) }
        for (index in 1 until result.size) if (result[index].seq != result[index - 1].seq + 1) throw SessionDataException()
        return result
    }
    private fun budget(count: Int, weight: Long) { if (count > MAX_RECORDS || weight > MAX_RETAINED_WEIGHT) throw SessionDataException("client.history_limit") }

    fun page(requestId: String): SessionPageRequest? {
        Contract.uuid(requestId)
        if (!ready || !more || page != null) return null
        if (records.size >= MAX_RECORDS) throw SessionDataException("client.history_limit")
        val before = records.firstKey()
        page = Page(requestId, before)
        return SessionPageRequest(requestId, jsonObject("sync_id" to sync!!.json(), "through_seq" to opening.json(), "before_seq" to before.json(), "max_messages" to 20L.json()))
    }
    fun pageFailed(requestId: String) { if (page?.id == requestId) page = null }
    private fun prepend(content: SessionContent): Boolean {
        val pending = page ?: return false
        if (content.requestId != pending.id) return false
        val payload = content.payload; payload.exactKeys("records", "has_more", "through_seq")
        val entries = parseRecords(payload.array("records")); val hasMore = SessionJson.boolean(payload, "has_more")
        if (payload.integer("through_seq", -1) != opening || entries.isEmpty() || entries.last().seq != pending.before - 1 || hasMore != (entries.first().seq > 0)) throw SessionDataException()
        val weight = entries.sumOf(SessionRecord::weight)
        budget(records.size + entries.size, retainedWeight + weight)
        entries.forEach { if (records.put(it.seq, it) != null) throw SessionDataException() }
        retainedWeight += weight; more = hasMore; page = null
        return true
    }
    private fun assistant(kind: String, payload: JsonObject) {
        val nextRevision = payload.integer("revision", 0)
        if (revision == nextRevision && lastAssistant?.let { SessionJson.same(it, payload) } == true) return
        if (revision != null && nextRevision != revision!! + 1) throw SessionDataException()
        revision = nextRevision; lastAssistant = payload
        when (kind) {
            "assistant.start" -> {
                payload.exactKeys("type", "attemptId", "revision", "startedAfterSeq", "turn", "step")
                if (payload.string("type") != "start" || active != null || held != null) throw SessionDataException()
                active = Attempt(Contract.boundedText(payload.string("attemptId"), 2048), payload.integer("startedAfterSeq", -1), payload.integer("turn", 0), payload.integer("step", 0), 0, StreamBlocks())
            }
            "assistant.chunk" -> {
                payload.exactKeys("type", "attemptId", "revision", "index", "time", "chunk")
                if (payload.string("type") != "chunk") throw SessionDataException()
                payload.integer("time", -MAX_SAFE_INTEGER)
                val attempt = active ?: return
                if (payload.string("attemptId") != attempt.id || payload.integer("index", 0) != attempt.next) throw SessionDataException()
                attempt.blocks.accept(payload.obj("chunk")); attempt.next++
            }
            "assistant.end" -> {
                payload.exactKeys("type", "attemptId", "revision", "index", "outcome")
                if (payload.string("type") != "end") throw SessionDataException()
                val attempt = active ?: return
                if (payload.string("attemptId") != attempt.id || payload.integer("index", 0) != attempt.next) throw SessionDataException()
                val outcome = payload.obj("outcome")
                if (outcome.string("kind") == "abandoned") {
                    outcome.exactKeys("kind"); if (held != null) throw SessionDataException()
                } else {
                    outcome.exactKeys("kind", "eventType", "seq")
                    val pending = held ?: throw SessionDataException()
                    if (outcome.string("kind") != "committed" || outcome.string("eventType") != pending.type || outcome.integer("seq", 0) != pending.seq) throw SessionDataException()
                }
                active = null; held = null
            }
        }
    }

    fun snapshot(durableOnly: Boolean = false): SessionTranscript {
        // A held settlement and its suffix cannot be restored as completed history
        // until the matching committed end arrives, even if a checkpoint led it.
        val entries = records.values.filter { !durableOnly || it.seq <= persisted && (held == null || it.seq < held!!.seq) }
        val live = if (durableOnly) null else active
        val items = arrayListOf<ConversationItem>()
        var liveAdded = false
        fun addLive() { live?.let { items += ConversationItem("live:${it.id}", ConversationRole.ASSISTANT, it.blocks.snapshot(), true, false) }; liveAdded = true }
        for (record in entries) {
            if (!liveAdded && live != null && record.seq > live.after) addLive()
            if (record.seq != held?.seq) record.conversationItem(persisted)?.let(items::add)
        }
        if (!liveAdded && live != null) addLive()
        val running = entries.lastOrNull { it.type == "turn/start" || it.type == "turn/end" }?.type == "turn/start"
        return SessionTranscript(Collections.unmodifiableList(entries), if (durableOnly) entries.lastOrNull()?.seq ?: -1 else cursor,
            if (durableOnly) minOf(opening, entries.lastOrNull()?.seq ?: -1) else opening, more, persisted, checkpoint, Collections.unmodifiableList(items), running,
            durableOnly && (entries.isNotEmpty() || cursor == -1L && checkpoint == "persisted"))
    }
}

internal fun SessionRecord.conversationItem(persisted: Long): ConversationItem? {
    if (replacement || blocks.isEmpty()) return null
    val role = when (type) {
        "user/message" -> ConversationRole.USER
        "assistant/message", "assistant/attempt" -> ConversationRole.ASSISTANT
        "tool/call", "tool/result" -> ConversationRole.TOOL
        else -> return null
    }
    return ConversationItem("event:$seq", role, blocks, false, seq <= persisted,
        type == "assistant/attempt" || data.fields["interrupted"] == JsonBoolean(true))
}
