package cn.edu.ustc.dsh.protocol

const val FILE_EXPORT_CAPABILITY = "file.export.v1"
const val MAX_EXPORT_BYTES = 2_000_000_000L

/** A different type keeps the upload limit and message admission unchanged. */
class ExportManifest(val name: String, val sizeBytes: Long, val sha256: String) {
    init {
        FileManifest(name, 0, sha256) // Shared leaf-name and digest rules, without widening uploads.
        if (sizeBytes !in 0..MAX_EXPORT_BYTES) throw ProtocolException()
    }
    fun json() = jsonObject("name" to name.json(), "size_bytes" to sizeBytes.json(), "sha256" to sha256.json())
    fun same(other: ExportManifest) = name == other.name && sizeBytes == other.sizeBytes && sha256 == other.sha256
    override fun toString() = "ExportManifest"
    companion object {
        fun parse(root: JsonObject): ExportManifest {
            root.exactKeys("name", "size_bytes", "sha256")
            return ExportManifest(root.string("name"), root.integer("size_bytes", 0, MAX_EXPORT_BYTES), root.string("sha256"))
        }
    }
}

enum class ExportOrigin(val wire: String) {
    SESSION_ATTACHMENT("session_attachment"), WORKSPACE_ARTIFACT("workspace_artifact");
    companion object { fun parse(value: String) = entries.firstOrNull { it.wire == value } ?: throw ProtocolException() }
}

class ExportSource private constructor(val id: String, val directory: Boolean, val origin: ExportOrigin, val name: String,
    val sizeBytes: Long?, val expiresAt: Long, val unavailable: Boolean) {
    private val observed = System.currentTimeMillis()
    private val started = System.nanoTime()
    fun current() = System.currentTimeMillis() in observed until expiresAt && (System.nanoTime() - started) / 1_000_000 < expiresAt - observed
    override fun toString() = "ExportSource"
    companion object {
        fun parse(root: JsonObject): ExportSource {
            val directory = when (root.string("kind")) { "directory" -> true; "file" -> false; else -> throw ProtocolException() }
            val keys = setOf("source_id", "kind", "origin", "name", "expires_at") + (if (!directory) setOf("size_bytes") else emptySet()) +
                (if ("unavailable" in root.fields) setOf("unavailable") else emptySet())
            if (root.fields.keys != keys || directory && "unavailable" in root.fields) throw ProtocolException()
            val name = root.string("name"); FileManifest(name, 0, "0".repeat(64))
            val size = if (directory) null else root.integer("size_bytes", 0, 9_007_199_254_740_991)
            val unavailable = "unavailable" in root.fields
            if (unavailable && root.string("unavailable") != "file.too_large" || !directory && size!! > MAX_EXPORT_BYTES && !unavailable) throw ProtocolException()
            return ExportSource(Contract.uuid(root.string("source_id")), directory, ExportOrigin.parse(root.string("origin")), name, size, relayTime(root.string("expires_at")), unavailable)
        }
    }
}

class ExportPage private constructor(val items: List<ExportSource>, val directoryId: String?, val cursor: String?) {
    override fun toString() = "ExportPage"
    companion object {
        fun parse(root: JsonObject): ExportPage {
            root.exactKeys("items", "directory_id", "cursor")
            val items = (root["items"] as? JsonArray)?.values ?: throw ProtocolException()
            if (items.size > 16) throw ProtocolException()
            val parsed = items.map { ExportSource.parse(it as? JsonObject ?: throw ProtocolException()) }
            if (parsed.map { it.id }.toSet().size != parsed.size) throw ProtocolException()
            fun nullableId(key: String) = when (val value = root[key]) { JsonNull -> null; is JsonString -> Contract.uuid(value.value); else -> throw ProtocolException() }
            return ExportPage(parsed, nullableId("directory_id"), nullableId("cursor"))
        }
    }
}

class RemoteExportStatus private constructor(val id: String, val runtimeId: String, val sessionId: String, val manifest: ExportManifest,
    val state: FileTransferState, val error: String?, val expiresAt: Long) {
    private val observed = System.currentTimeMillis()
    private val started = System.nanoTime()
    fun downloadable() = state == FileTransferState.CLEAN && System.currentTimeMillis() in observed until expiresAt &&
        (System.nanoTime() - started) / 1_000_000 < expiresAt - observed
    override fun toString() = "RemoteExportStatus(${state.wire})"
    companion object {
        fun parse(root: JsonObject): RemoteExportStatus {
            val keys = setOf("file_id", "runtime_id", "session_id", "direction", "name", "size_bytes", "sha256", "state", "upload_expires_at", "expires_at", "created_at") +
                (if ("error_code" in root.fields) setOf("error_code") else emptySet())
            if (root.fields.keys != keys || root.string("direction") != "from_host") throw ProtocolException()
            val manifest = ExportManifest(root.string("name"), root.integer("size_bytes", 0, MAX_EXPORT_BYTES), root.string("sha256"))
            val state = FileTransferState.parse(root.string("state"))
            val error = if ("error_code" in root.fields) root.string("error_code").also {
                if (it !in setOf("integrity_mismatch", "content_rejected", "scan_unavailable", "storage_unavailable", "access_revoked", "expired")) throw ProtocolException()
            } else null
            val created = relayTime(root.string("created_at")); val upload = relayTime(root.string("upload_expires_at")); val expires = relayTime(root.string("expires_at"))
            if (upload <= created || expires <= created || state in setOf(FileTransferState.UPLOADING, FileTransferState.CLEAN) && error != null ||
                state == FileTransferState.SCANNING && error != null && error !in setOf("scan_unavailable", "storage_unavailable")) throw ProtocolException()
            return RemoteExportStatus(Contract.uuid(root.string("file_id")), Contract.uuid(root.string("runtime_id")), Contract.uuid(root.string("session_id")), manifest, state, error, expires)
        }
    }
}
