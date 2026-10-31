package cn.edu.ustc.dsh.protocol

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.Base64
import java.util.Collections

const val SESSION_CHANGES_CAPABILITY = "session.changes.v1"
const val SESSION_CHANGES_MAX_PATCH_BYTES = 1024 * 1024

private fun changeBoolean(root: JsonObject, key: String) = (root[key] as? JsonBoolean)?.value ?: throw ProtocolException()
private fun changeObject(value: JsonValue) = value as? JsonObject ?: throw ProtocolException()
private fun changeNullableString(root: JsonObject, key: String): String? = when (val value = root[key]) {
    JsonNull -> null; is JsonString -> value.value.also(::requireText); else -> throw ProtocolException()
}
private fun changeNullableNumber(root: JsonObject, key: String): Long? = if (root[key] == JsonNull) null else root.integer(key, 0)
private fun changeCursor(root: JsonObject): String? = changeNullableString(root, "next_cursor")?.let(Contract::uuid)
private fun changeKind(value: String) = value.also { if (it !in setOf("text", "binary", "symlink", "gitlink")) throw ProtocolException() }
fun sessionChangeBytes(value: String, maximum: Int = SESSION_CHANGES_MAX_PATCH_BYTES): ByteArray {
    if (maximum < 0 || value.length > ((maximum + 2L) / 3 * 4) || value.length % 4 != 0) throw ProtocolException()
    val bytes = try { Base64.getDecoder().decode(value) } catch (_: IllegalArgumentException) { throw ProtocolException() }
    if (bytes.size > maximum || Base64.getEncoder().encodeToString(bytes) != value) throw ProtocolException()
    return bytes
}
fun sessionChangeUtf8(bytes: ByteArray): String? = try {
    Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
} catch (_: java.nio.charset.CharacterCodingException) { null }

class SessionChangePath private constructor(val bytesBase64: String, val display: String) {
    companion object {
        fun parse(root: JsonObject): SessionChangePath {
            root.exactKeys("bytes_base64", "display")
            val encoded = root.string("bytes_base64"); val bytes = sessionChangeBytes(encoded, 4096); val display = root.string("display")
            if (bytes.isEmpty() || bytes.any { it == 0.toByte() } || display.length > 16_384 || display.any { it < ' ' || it > '~' }) throw ProtocolException()
            return SessionChangePath(encoded, display)
        }
    }
}
class SessionChangeFile private constructor(val fileId: String, val status: String, val oldPath: SessionChangePath?, val newPath: SessionChangePath?,
    val oldMode: String, val newMode: String, val kind: String, val patchBytes: Long, val complete: Boolean, val copyable: Boolean) {
    companion object {
        fun parse(root: JsonObject): SessionChangeFile {
            root.exactKeys("file_id", "status", "old_path", "new_path", "old_mode", "new_mode", "kind", "patch_bytes", "complete", "copyable")
            val status = root.string("status"); val kind = changeKind(root.string("kind"))
            if (status !in setOf("added", "modified", "deleted", "renamed", "type_changed")) throw ProtocolException()
            val oldMode = root.string("old_mode"); val newMode = root.string("new_mode")
            if (!Regex("[0-7]{6}").matches(oldMode) || !Regex("[0-7]{6}").matches(newMode)) throw ProtocolException()
            val complete = changeBoolean(root, "complete"); val copyable = changeBoolean(root, "copyable")
            if (copyable && (!complete || kind == "binary")) throw ProtocolException()
            fun path(key: String) = if (root[key] == JsonNull) null else SessionChangePath.parse(root.obj(key))
            return SessionChangeFile(Contract.uuid(root.string("file_id")), status, path("old_path"), path("new_path"), oldMode, newMode, kind,
                root.integer("patch_bytes", 0, SESSION_CHANGES_MAX_PATCH_BYTES.toLong()), complete, copyable)
        }
    }
}
data class SessionChangesManifest(val baseOid: String, val version: String, val manifestSha256: String, val expiresAt: Long, val snapshotId: String)
class SessionChangesPage private constructor(val syncId: String, val manifest: SessionChangesManifest, val files: List<SessionChangeFile>, val nextCursor: String?, val encodedBytes: Int) {
    companion object {
        fun parse(root: JsonObject): SessionChangesPage {
            root.exactKeys("v", "sync_id", "snapshot_id", "source", "base", "version", "manifest_sha256", "expires_at", "scope", "excluded", "complete", "truncated", "files", "next_cursor")
            root.integer("v", 1, 1)
            val size = sessionActionPayloadBytes(root); if (size > 32 * 1024) throw ProtocolException()
            val base = root.obj("base"); base.exactKeys("kind", "oid")
            val oid = base.string("oid")
            if (root.string("source") != "configured_workspace_git" || root.string("scope") != "tracked_head_to_index_worktree" ||
                base.string("kind") != "git_head" || !Regex("(?:[0-9a-f]{40}|[0-9a-f]{64})").matches(oid) ||
                root.array("excluded") != listOf("untracked".json(), "ignored".json(), "submodule_contents".json()) ||
                !changeBoolean(root, "complete") || changeBoolean(root, "truncated")) throw ProtocolException()
            val files = root.array("files"); if (files.size > 20) throw ProtocolException()
            val parsed = files.map { SessionChangeFile.parse(changeObject(it)) }
            if (parsed.map { it.fileId }.toSet().size != parsed.size) throw ProtocolException()
            val cursor = changeCursor(root); if (parsed.isEmpty() && cursor != null) throw ProtocolException()
            return SessionChangesPage(Contract.uuid(root.string("sync_id")), SessionChangesManifest(oid, Contract.digest(root.string("version")),
                Contract.digest(root.string("manifest_sha256")), relayTime(root.string("expires_at")), Contract.uuid(root.string("snapshot_id"))), Collections.unmodifiableList(parsed), cursor, size)
        }
    }
}
class SessionChangeLine private constructor(val kind: String, val bytesBase64: String, val text: String?, val oldLine: Long?, val newLine: Long?) {
    companion object {
        fun parse(root: JsonObject): SessionChangeLine {
            root.exactKeys("kind", "bytes_base64", "text", "old_line", "new_line")
            val kind = root.string("kind"); if (kind !in setOf("context", "add", "delete", "no_final_newline")) throw ProtocolException()
            val encoded = root.string("bytes_base64"); if (encoded.length > 22_000) throw ProtocolException()
            val bytes = sessionChangeBytes(encoded, 16_384); val text = changeNullableString(root, "text")
            if (text != null && (text.length > 16_384 || sessionChangeUtf8(bytes) != text)) throw ProtocolException()
            return SessionChangeLine(kind, encoded, text, changeNullableNumber(root, "old_line"), changeNullableNumber(root, "new_line"))
        }
    }
}
data class SessionChangeHunk(val oldStart: Long, val oldCount: Long, val newStart: Long, val newCount: Long, val lines: List<SessionChangeLine>) {
    companion object {
        fun parse(root: JsonObject): SessionChangeHunk {
            root.exactKeys("old_start", "old_count", "new_start", "new_count", "lines")
            val lines = root.array("lines"); if (lines.size > 20_000) throw ProtocolException()
            return SessionChangeHunk(root.integer("old_start", 0), root.integer("old_count", 0), root.integer("new_start", 0), root.integer("new_count", 0),
                Collections.unmodifiableList(lines.map { SessionChangeLine.parse(changeObject(it)) }))
        }
    }
}
/** Parsed page or accumulated foreground patch. partial never means a complete copy authorization. */
data class SessionChangesPatch(val syncId: String, val snapshotId: String, val fileId: String, val version: String, val kind: String,
    val complete: Boolean, val copyable: Boolean, val partial: Boolean, val patchBase64: String, val patchUtf8: String?,
    val hunks: List<SessionChangeHunk>, val nextCursor: String?) {
    companion object {
        fun parse(root: JsonObject): SessionChangesPatch {
            root.exactKeys("v", "sync_id", "snapshot_id", "file_id", "version", "kind", "complete", "copyable", "partial", "patch_base64", "patch_utf8", "hunks", "next_cursor")
            root.integer("v", 1, 1); if (sessionActionPayloadBytes(root) > 16 * 1024) throw ProtocolException()
            val encoded = root.string("patch_base64"); if (encoded.length > 22_000) throw ProtocolException()
            val bytes = sessionChangeBytes(encoded, 16_384); val text = changeNullableString(root, "patch_utf8")
            if (text != null && (text.length > 16_384 || sessionChangeUtf8(bytes) != text)) throw ProtocolException()
            val complete = changeBoolean(root, "complete"); val copyable = changeBoolean(root, "copyable"); val partial = changeBoolean(root, "partial")
            val kind = changeKind(root.string("kind")); val cursor = changeCursor(root)
            if (copyable && (!complete || partial || cursor != null || text == null || kind == "binary")) throw ProtocolException()
            val hunks = root.array("hunks"); if (hunks.size > 20_000) throw ProtocolException()
            val parsed = hunks.map { SessionChangeHunk.parse(changeObject(it)) }; if (parsed.sumOf { it.lines.size } > 20_000) throw ProtocolException()
            return SessionChangesPatch(Contract.uuid(root.string("sync_id")), Contract.uuid(root.string("snapshot_id")), Contract.uuid(root.string("file_id")),
                Contract.digest(root.string("version")), kind, complete, copyable, partial, encoded, text, Collections.unmodifiableList(parsed), cursor)
        }
    }
}
