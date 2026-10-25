package cn.edu.ustc.dsh.protocol

const val MAX_FILE_BYTES = 200_000_000L
const val FILE_MESSAGE_CAPABILITY = "message.files.v1"

/** Display metadata only; neither a device path nor native receipt. */
class FileManifest(val name: String, val sizeBytes: Long, val sha256: String) {
    init {
        if (name.isBlank() || name == "." || name == ".." || name.toByteArray(Charsets.UTF_8).size > 512 ||
            name.any { it == '/' || it == '\\' || Character.isISOControl(it) } || sizeBytes !in 0..MAX_FILE_BYTES) throw ProtocolException()
        Contract.digest(sha256)
        JsonDocument.of(json()) // Reject unpaired surrogates independently of transport decoding.
    }
    fun json() = jsonObject("name" to name.json(), "size_bytes" to sizeBytes.json(), "sha256" to sha256.json())
    fun same(other: FileManifest) = name == other.name && sizeBytes == other.sizeBytes && sha256 == other.sha256
    override fun toString() = "FileManifest"
    companion object {
        fun parse(root: JsonObject): FileManifest {
            root.exactKeys("name", "size_bytes", "sha256")
            return FileManifest(root.string("name"), root.integer("size_bytes", 0, MAX_FILE_BYTES), root.string("sha256"))
        }
    }
}

enum class FileTransferState(val wire: String) {
    UPLOADING("uploading"), SCANNING("scanning"), CLEAN("clean"), REJECTED("rejected"), EXPIRED("expired");
    companion object { fun parse(value: String) = entries.firstOrNull { it.wire == value } ?: throw ProtocolException() }
}

enum class FileDeliveryState { WAITING, READY, BOUND }
class FileDelivery private constructor(val state: FileDeliveryState, val expiresAt: Long?, val requestId: String?, val commandState: String?) {
    override fun toString() = "FileDelivery($state)"
    companion object {
        fun parse(root: JsonObject): FileDelivery = when (root.string("state")) {
            "waiting" -> { root.exactKeys("state"); FileDelivery(FileDeliveryState.WAITING, null, null, null) }
            "ready" -> { root.exactKeys("state", "expires_at"); FileDelivery(FileDeliveryState.READY, relayTime(root.string("expires_at")), null, null) }
            "bound" -> {
                root.exactKeys("state", "request_id", "command_state")
                val state = root.string("command_state")
                if (state !in setOf("received", "host_accepted", "dispatching", "agent_queued", "observed", "settled", "rejected", "outcome_unknown")) throw ProtocolException()
                FileDelivery(FileDeliveryState.BOUND, null, Contract.uuid(root.string("request_id")), state)
            }
            else -> throw ProtocolException()
        }
    }
}

class RemoteFileStatus private constructor(val id: String, val runtimeId: String, val sessionId: String, val manifest: FileManifest,
    val state: FileTransferState, val error: String?, val uploadExpiresAt: Long, val expiresAt: Long, val createdAt: Long, val delivery: FileDelivery?) {
    private val observed = System.currentTimeMillis()
    private val since = System.nanoTime()
    fun readyForMessage(now: Long = System.currentTimeMillis()) = state == FileTransferState.CLEAN && delivery?.state == FileDeliveryState.READY &&
        now >= observed && now < minOf(expiresAt, delivery.expiresAt!!) && (System.nanoTime() - since) / 1_000_000 < 5000
    override fun toString() = "RemoteFileStatus(${state.wire})"
    companion object {
        private val errors = setOf("integrity_mismatch", "content_rejected", "scan_unavailable", "storage_unavailable", "access_revoked", "expired")
        fun parse(root: JsonObject): RemoteFileStatus {
            val keys = setOf("file_id", "runtime_id", "session_id", "direction", "name", "size_bytes", "sha256", "state", "upload_expires_at", "expires_at", "created_at") +
                (if ("error_code" in root.fields) setOf("error_code") else emptySet()) + (if ("delivery" in root.fields) setOf("delivery") else emptySet())
            if (root.fields.keys != keys || root.string("direction") != "to_host") throw ProtocolException()
            val manifest = FileManifest(root.string("name"), root.integer("size_bytes", 0, MAX_FILE_BYTES), root.string("sha256"))
            val state = FileTransferState.parse(root.string("state"))
            val error = if ("error_code" in root.fields) root.string("error_code").also { if (it !in errors) throw ProtocolException() } else null
            val upload = relayTime(root.string("upload_expires_at")); val expires = relayTime(root.string("expires_at")); val created = relayTime(root.string("created_at"))
            if (upload <= created || expires <= created || state in setOf(FileTransferState.UPLOADING, FileTransferState.CLEAN) && error != null ||
                state == FileTransferState.SCANNING && error != null && error !in setOf("scan_unavailable", "storage_unavailable")) throw ProtocolException()
            val delivery = if ("delivery" in root.fields) FileDelivery.parse(root.obj("delivery")) else null
            if (delivery?.state == FileDeliveryState.READY && (state != FileTransferState.CLEAN || delivery.expiresAt!! > expires)) throw ProtocolException()
            return RemoteFileStatus(Contract.uuid(root.string("file_id")), Contract.uuid(root.string("runtime_id")), Contract.uuid(root.string("session_id")), manifest, state, error, upload, expires, created, delivery)
        }
    }
}
