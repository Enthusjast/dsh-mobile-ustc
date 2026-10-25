package cn.edu.ustc.dsh.command

import cn.edu.ustc.dsh.protocol.*
import java.time.Instant
import java.time.OffsetDateTime

class CommandDataException(val code: String) : IllegalStateException(code)

typealias CommandOwner = LocalDataOwner

enum class CommandKind(val wire: String) { MESSAGE("message.submit"), CANCEL("session.cancel"), CREATE("session.create") }

/** An immutable original intent; epochs may never be changed to force a cancellation through. */
class CommandIntent private constructor(val requestId: String, val runtimeId: String, val sessionId: String?, val kind: CommandKind, val epoch: String?, val payload: JsonObject, val workspaceId: String? = null) {
    val digest: String
    init {
        listOfNotNull(requestId, runtimeId, sessionId, workspaceId).forEach(Contract::uuid)
        var body = jsonObject("type" to kind.wire.json(), "payload" to payload)
        if (sessionId != null) body = body.with("session_id" to sessionId.json())
        if (epoch != null) body = body.with("runtime_epoch" to Contract.uuid(epoch).json())
        digest = JsonDocument.of(body).sha256()
        if (JsonDocument.of(frame()).canonicalBytes().size > RELAY_FRAME_BYTES) throw CommandDataException("command.too_large")
    }
    fun frame(): JsonObject {
        var frame = jsonObject("v" to 1L.json(), "type" to kind.wire.json(), "request_id" to requestId.json(), "runtime_id" to runtimeId.json(), "payload" to payload)
        if (sessionId != null) frame = frame.with("session_id" to sessionId.json())
        if (epoch != null) frame = frame.with("runtime_epoch" to epoch.json())
        return frame
    }
    fun storageBytes(): ByteArray = JsonDocument.of(frame()).canonicalBytes()
    fun text(): String? = if (kind == CommandKind.MESSAGE) payload.array("content").joinToString("\n") { (it as JsonObject).string("text") } else null
    override fun toString() = "CommandIntent(${kind.wire})"
    companion object {
        fun message(request: String, runtime: String, session: String, mode: String, text: String): CommandIntent =
            parse(jsonObject("v" to 1L.json(), "type" to "message.submit".json(), "request_id" to request.json(), "runtime_id" to runtime.json(), "session_id" to session.json(),
                "payload" to jsonObject("mode" to mode.json(), "content" to JsonArray(listOf(jsonObject("type" to "text".json(), "text" to text.json()))))))
        fun cancel(request: String, runtime: String, session: String, epoch: String): CommandIntent =
            parse(jsonObject("v" to 1L.json(), "type" to "session.cancel".json(), "request_id" to request.json(), "runtime_id" to runtime.json(), "session_id" to session.json(), "runtime_epoch" to epoch.json(), "payload" to jsonObject()))
        fun createSession(request: String, runtime: String, workspace: String, preset: String, epoch: String): CommandIntent =
            parse(jsonObject("v" to 1L.json(), "type" to "session.create".json(), "request_id" to request.json(), "runtime_id" to runtime.json(), "runtime_epoch" to epoch.json(),
                "payload" to jsonObject("workspace_id" to workspace.json(), "preset" to preset.json())))
        fun parse(root: JsonObject): CommandIntent {
            val kind = CommandKind.entries.firstOrNull { it.wire == root.string("type") } ?: throw ProtocolException()
            val fields = setOf("v", "type", "request_id", "runtime_id", "payload") + if (kind == CommandKind.CREATE) setOf("runtime_epoch")
                else setOf("session_id") + if (kind == CommandKind.CANCEL) setOf("runtime_epoch") else emptySet()
            if (root.fields.keys != fields || root.integer("v", 1, 1) != 1L) throw ProtocolException()
            val payload = root.obj("payload")
            if (kind == CommandKind.CREATE) {
                payload.exactKeys("workspace_id", "preset"); Contract.uuid(payload.string("workspace_id"))
                if (!Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}").matches(payload.string("preset"))) throw ProtocolException()
            } else if (kind == CommandKind.CANCEL) payload.exactKeys() else {
                payload.exactKeys("mode", "content")
                if (payload.string("mode") !in setOf("queue", "steer")) throw ProtocolException()
                val blocks = payload.array("content")
                if (blocks.size !in 1..16) throw ProtocolException()
                for (item in blocks) {
                    val block = item as? JsonObject ?: throw ProtocolException(); block.exactKeys("type", "text")
                    val text = block.string("text")
                    if (block.string("type") != "text" || text.isBlank() || text.codePointCount(0, text.length) > 32_768 ||
                        text.any { Character.isISOControl(it) && it !in "\n\r\t" }) throw ProtocolException()
                }
            }
            // Enforce scalar Unicode independently of callers constructing JSON values.
            JsonDocument.of(root)
            return CommandIntent(root.string("request_id"), root.string("runtime_id"), if (kind == CommandKind.CREATE) null else root.string("session_id"), kind,
                if (kind != CommandKind.MESSAGE) root.string("runtime_epoch") else null, payload, if (kind == CommandKind.CREATE) payload.string("workspace_id") else null)
        }
    }
}

enum class RemoteCommandState(val wire: String) {
    RECEIVED("received"), HOST_ACCEPTED("host_accepted"), DISPATCHING("dispatching"), AGENT_QUEUED("agent_queued"), OBSERVED("observed"), SETTLED("settled"), REJECTED("rejected"), OUTCOME_UNKNOWN("outcome_unknown");
    companion object { fun parse(value: String) = entries.firstOrNull { it.wire == value } ?: throw ProtocolException() }
}
class CommandReceipt(val requestId: String, val sessionId: String?, val digest: String, val state: RemoteCommandState, val timestamp: String, val epoch: String? = null, val workspaceId: String? = null) {
    val instant: Instant
    val updatedAt: Long
    init {
        listOfNotNull(requestId, sessionId, workspaceId).forEach(Contract::uuid); Contract.digest(digest); epoch?.let(Contract::uuid)
        if (workspaceId == null && sessionId == null || workspaceId != null &&
            (state in setOf(RemoteCommandState.AGENT_QUEUED, RemoteCommandState.OBSERVED) || (state == RemoteCommandState.SETTLED) != (sessionId != null))) throw ProtocolException()
        updatedAt = relayTime(timestamp); instant = OffsetDateTime.parse(timestamp).toInstant()
    }
    companion object {
        fun socket(frame: JsonObject, runtime: String, epoch: String? = null): CommandReceipt {
            val fields = setOf("v", "type", "request_id", "runtime_id", "runtime_epoch", "payload") + if ("session_id" in frame.fields) setOf("session_id") else emptySet()
            relayEnvelope(frame, "command.receipt", *fields.toTypedArray())
            val actualEpoch = Contract.uuid(frame.string("runtime_epoch"))
            if (frame.string("runtime_id") != runtime || epoch != null && actualEpoch != epoch) throw ProtocolException()
            return body(frame.obj("payload"), frame.string("request_id"), frame.fields["session_id"]?.let { frame.string("session_id") }, actualEpoch)
        }
        fun status(root: JsonObject): CommandReceipt {
            val fields = setOf("request_id", "state", "payload_sha256", "updated_at") + setOf("session_id", "workspace_id").filter { it in root.fields }
            root.exactKeys(*fields.toTypedArray())
            return body(JsonObject(root.fields.filterKeys { it !in setOf("request_id", "session_id") }), root.string("request_id"), root.fields["session_id"]?.let { root.string("session_id") }, null)
        }
        private fun body(payload: JsonObject, request: String, session: String?, epoch: String?): CommandReceipt {
            val fields = setOf("state", "payload_sha256", "updated_at") + if ("workspace_id" in payload.fields) setOf("workspace_id") else emptySet()
            payload.exactKeys(*fields.toTypedArray())
            return CommandReceipt(request, session, payload.string("payload_sha256"), RemoteCommandState.parse(payload.string("state")), payload.string("updated_at"), epoch,
                payload.fields["workspace_id"]?.let { payload.string("workspace_id") })
        }
    }
}

/** Local delivery knowledge and remote persistence facts are separate axes. */
enum class CommandDelivery { PENDING, RECONCILE, CONFIRMED, BLOCKED }
class PendingCommand(val intent: CommandIntent, val delivery: CommandDelivery, val remote: RemoteCommandState?, val attempts: Long, val revision: Long, val createdAt: Long,
    val updatedAt: Long, val remoteTimestamp: String?, val everHostSaved: Boolean, val everAgentQueued: Boolean, val error: String?, val createdSessionId: String? = null) {
    override fun toString() = "PendingCommand(${intent.kind}, $delivery, $remote)"
}

object CommandEvolution {
    fun created(intent: CommandIntent, now: Long) = PendingCommand(intent, CommandDelivery.PENDING, null, 0, 1, now, now, null, false, false, null)
    fun begin(record: PendingCommand, now: Long): PendingCommand {
        if (record.delivery != CommandDelivery.PENDING || record.attempts > 0 && record.remote != RemoteCommandState.RECEIVED) throw CommandDataException("command.reconcile_required")
        return copy(record, CommandDelivery.RECONCILE, attempts = record.attempts + 1, now = now, error = null)
    }
    fun rearm(record: PendingCommand, proof: CommandReceipt): PendingCommand {
        val current = receipt(record, proof)
        if (proof.state != RemoteCommandState.RECEIVED || current.remote != RemoteCommandState.RECEIVED || current.everHostSaved) throw CommandDataException("command.reconcile_required")
        return copy(current, CommandDelivery.PENDING, now = System.currentTimeMillis(), error = null)
    }
    fun uncertain(record: PendingCommand, code: String, now: Long): PendingCommand =
        if (record.delivery == CommandDelivery.PENDING || record.remote in setOf(RemoteCommandState.AGENT_QUEUED, RemoteCommandState.OBSERVED, RemoteCommandState.SETTLED, RemoteCommandState.REJECTED)) record
        else copy(record, CommandDelivery.RECONCILE, now = now, error = code)
    fun receipt(record: PendingCommand, receipt: CommandReceipt): PendingCommand {
        val creation = record.intent.kind == CommandKind.CREATE
        if (receipt.requestId != record.intent.requestId || receipt.workspaceId != record.intent.workspaceId || !creation && receipt.sessionId != record.intent.sessionId || receipt.digest != record.intent.digest ||
            receipt.epoch != null && record.intent.epoch != null && receipt.epoch != record.intent.epoch) throw CommandDataException("command.request_conflict")
        if (record.createdSessionId != null && receipt.sessionId != null && receipt.sessionId != record.createdSessionId) throw CommandDataException("command.request_conflict")
        if (record.attempts == 0L) throw CommandDataException("command.unsent_receipt")
        val previous = record.remoteTimestamp?.let { OffsetDateTime.parse(it).toInstant() }
        if (previous != null && receipt.instant < previous) return record
        if (previous == receipt.instant && record.remote == receipt.state) return record
        if (record.remote in setOf(RemoteCommandState.SETTLED, RemoteCommandState.REJECTED) && record.remote != receipt.state) throw CommandDataException("command.state_conflict")
        // A later weak status cannot erase a previously confirmed uncertain
        // outcome and make an attempted command eligible for replay.
        if (record.remote == RemoteCommandState.OUTCOME_UNKNOWN && receipt.state == RemoteCommandState.RECEIVED) return record
        val saved = record.everHostSaved || receipt.state in setOf(RemoteCommandState.HOST_ACCEPTED, RemoteCommandState.DISPATCHING, RemoteCommandState.AGENT_QUEUED, RemoteCommandState.OBSERVED, RemoteCommandState.SETTLED)
        val queued = record.everAgentQueued || record.intent.kind == CommandKind.MESSAGE && receipt.state in setOf(RemoteCommandState.AGENT_QUEUED, RemoteCommandState.OBSERVED, RemoteCommandState.SETTLED)
        if (saved && receipt.state == RemoteCommandState.RECEIVED || queued && receipt.state in setOf(RemoteCommandState.HOST_ACCEPTED, RemoteCommandState.DISPATCHING)) return record
        return PendingCommand(record.intent, if (receipt.state == RemoteCommandState.OUTCOME_UNKNOWN) CommandDelivery.RECONCILE else CommandDelivery.CONFIRMED,
            receipt.state, record.attempts, record.revision + 1, record.createdAt, maxOf(record.updatedAt, receipt.updatedAt), receipt.timestamp, saved, queued, null,
            record.createdSessionId ?: if (creation && receipt.state == RemoteCommandState.SETTLED) receipt.sessionId else null)
    }
    private fun copy(record: PendingCommand, delivery: CommandDelivery, attempts: Long = record.attempts, now: Long, error: String?) =
        PendingCommand(record.intent, delivery, record.remote, attempts, record.revision + 1, record.createdAt, maxOf(now, record.updatedAt), record.remoteTimestamp, record.everHostSaved, record.everAgentQueued, error, record.createdSessionId)
}

interface CommandJournal : AutoCloseable {
    val owner: CommandOwner
    suspend fun create(intent: CommandIntent, now: Long = System.currentTimeMillis()): PendingCommand
    suspend fun list(runtime: String, session: String): List<PendingCommand>
    suspend fun listCreations(runtime: String): List<PendingCommand>
    /** Must durably commit before any socket write. Only original unsent intent is eligible. */
    suspend fun beginAttempt(id: String, now: Long = System.currentTimeMillis()): PendingCommand
    suspend fun record(receipt: CommandReceipt): PendingCommand?
    suspend fun uncertain(id: String, code: String): PendingCommand?
    /** Explicit same-ID retry, only after a current-device status query still says received. */
    suspend fun rearm(id: String, proof: CommandReceipt): PendingCommand
    suspend fun discard(id: String)
    suspend fun revokeRuntime(runtime: String)
    suspend fun revokeSessionCommands(runtime: String)
}
