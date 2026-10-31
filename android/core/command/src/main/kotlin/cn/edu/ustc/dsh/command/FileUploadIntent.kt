package cn.edu.ustc.dsh.command

import cn.edu.ustc.dsh.protocol.*

/** Durable metadata only. Source URIs, bytes and signed URLs never belong here. */
class FileUploadIntent(val requestId: String, val runtimeId: String, val sessionId: String, val workspaceId: String?, val manifest: FileManifest,
    val image: ImageUploadMetadata? = null) {
    init {
        listOfNotNull(requestId, runtimeId, sessionId, workspaceId).forEach(Contract::uuid)
        if (image != null && manifest.sizeBytes !in 1..MAX_IMAGE_BYTES.toLong()) throw ProtocolException()
    }
    fun bytes(): ByteArray {
        var value = jsonObject("v" to (if (image == null) 1L else 2L).json(), "request_id" to requestId.json(), "runtime_id" to runtimeId.json(), "session_id" to sessionId.json(),
            "workspace_id" to (workspaceId?.json() ?: JsonNull), "manifest" to manifest.json())
        image?.let { value = value.with("image" to it.json()) }
        return JsonDocument.of(value).canonicalBytes()
    }
    val digest get() = JsonDocument.parse(bytes()).sha256()
    override fun toString() = "FileUploadIntent"
    companion object {
        fun parse(bytes: ByteArray): FileUploadIntent {
            val root = JsonDocument.parse(bytes).root
            val version = root.integer("v", 1, 2)
            root.exactKeys(*(setOf("v", "request_id", "runtime_id", "session_id", "workspace_id", "manifest") + if (version == 2L) setOf("image") else emptySet()).toTypedArray())
            val workspace = when (val value = root["workspace_id"]) { JsonNull -> null; is JsonString -> Contract.uuid(value.value); else -> throw ProtocolException() }
            return FileUploadIntent(root.string("request_id"), root.string("runtime_id"), root.string("session_id"), workspace, FileManifest.parse(root.obj("manifest")),
                if (version == 2L) ImageUploadMetadata.parse(root.obj("image")) else null)
        }
    }
}

class StoredFileUpload(val intent: FileUploadIntent, val fileId: String?, val messageId: String?, val createdAt: Long, val updatedAt: Long) {
    init {
        listOfNotNull(fileId, messageId).forEach(Contract::uuid)
        if (messageId != null && fileId == null || createdAt < 0 || updatedAt < createdAt) throw ProtocolException()
    }
    override fun toString() = "StoredFileUpload"
}

interface FileUploadJournal {
    val owner: CommandOwner
    suspend fun createUpload(intent: FileUploadIntent, now: Long = System.currentTimeMillis()): StoredFileUpload
    suspend fun uploads(runtime: String, session: String): List<StoredFileUpload>
    suspend fun registeredUpload(id: String, fileId: String, now: Long = System.currentTimeMillis()): StoredFileUpload
    suspend fun removeUpload(id: String)
}
