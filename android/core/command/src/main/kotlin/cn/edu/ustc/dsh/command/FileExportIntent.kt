package cn.edu.ustc.dsh.command

import cn.edu.ustc.dsh.protocol.*

/** The original selection is durable before dispatch. Recovery only reads its request ID. */
class FileExportIntent(val requestId: String, val runtimeId: String, val sessionId: String, val epoch: String,
    val sourceId: String, val workspaceId: String?, val origin: ExportOrigin, val name: String, val sizeBytes: Long) {
    init {
        listOfNotNull(requestId, runtimeId, sessionId, epoch, sourceId, workspaceId).forEach(Contract::uuid)
        ExportManifest(name, sizeBytes, "0".repeat(64))
        if (origin == ExportOrigin.WORKSPACE_ARTIFACT && workspaceId == null) throw ProtocolException()
    }
    fun bytes(): ByteArray = JsonDocument.of(jsonObject("v" to 1L.json(), "request_id" to requestId.json(), "runtime_id" to runtimeId.json(), "session_id" to sessionId.json(),
        "runtime_epoch" to epoch.json(), "source_id" to sourceId.json(), "workspace_id" to (workspaceId?.json() ?: JsonNull), "origin" to origin.wire.json(), "name" to name.json(), "size_bytes" to sizeBytes.json())).canonicalBytes()
    val digest get() = JsonDocument.parse(bytes()).sha256()
    fun matches(file: RemoteExportStatus) = file.runtimeId == runtimeId && file.sessionId == sessionId && file.manifest.name == name && file.manifest.sizeBytes == sizeBytes
    override fun toString() = "FileExportIntent"
    companion object {
        fun parse(bytes: ByteArray): FileExportIntent {
            val root = JsonDocument.parse(bytes).root
            root.exactKeys("v", "request_id", "runtime_id", "session_id", "runtime_epoch", "source_id", "workspace_id", "origin", "name", "size_bytes"); root.integer("v", 1, 1)
            val workspace = when (val value = root["workspace_id"]) { JsonNull -> null; is JsonString -> Contract.uuid(value.value); else -> throw ProtocolException() }
            return FileExportIntent(root.string("request_id"), root.string("runtime_id"), root.string("session_id"), root.string("runtime_epoch"), root.string("source_id"), workspace,
                ExportOrigin.parse(root.string("origin")), root.string("name"), root.integer("size_bytes", 0, MAX_EXPORT_BYTES))
        }
    }
}

class StoredFileExport(val intent: FileExportIntent, val fileId: String?, val manifest: ExportManifest?, val createdAt: Long, val updatedAt: Long) {
    init {
        fileId?.let(Contract::uuid)
        if ((fileId == null) != (manifest == null) || manifest?.let { it.name != intent.name || it.sizeBytes != intent.sizeBytes } == true || createdAt < 0 || updatedAt < createdAt) throw ProtocolException()
    }
    override fun toString() = "StoredFileExport"
}

interface FileExportJournal {
    val owner: CommandOwner
    suspend fun createExport(intent: FileExportIntent, now: Long = System.currentTimeMillis()): StoredFileExport
    suspend fun exports(runtime: String, session: String): List<StoredFileExport>
    suspend fun registeredExport(id: String, file: RemoteExportStatus, now: Long = System.currentTimeMillis()): StoredFileExport
    suspend fun removeExport(id: String)
}
