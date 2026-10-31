package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*
import java.util.Collections

/** Untrusted display hints only: never use a name as a resource or permission. */
class DirectoryDisplayMetadata private constructor(val title: String?, val workspaceTitle: String?, val titleSource: String?, val titleAsOfSeq: Long?) {
    companion object {
        fun parse(root: JsonObject): DirectoryDisplayMetadata {
            root.exactKeys("v", "title", "workspace_title", "title_source", "title_as_of_seq")
            root.integer("v", 1, 1)
            fun name(key: String): String? = when (val value = root[key]) {
                JsonNull -> null
                is JsonString -> value.value.also(::directoryPlainName)
                else -> throw ProtocolException()
            }
            val title = name("title")
            val workspace = name("workspace_title")
            val source = when (val value = root["title_source"]) {
                JsonNull -> null
                is JsonString -> value.value.also { if (it != "cached" && it != "sequenced") throw ProtocolException() }
                else -> throw ProtocolException()
            }
            val cut = if (root["title_as_of_seq"] == JsonNull) null else root.integer("title_as_of_seq", -1)
            if ((title == null) != (source == null) || (source == null) != (cut == null)) throw ProtocolException()
            return DirectoryDisplayMetadata(title, workspace, source, cut)
        }
    }
}

private fun directoryPlainName(value: String) {
    if (value.isBlank() || value.length > 256) throw ProtocolException()
    var index = 0
    var utf8Bytes = 0
    while (index < value.length) {
        val character = value[index]
        if (character <= '\u001f' || character in '\u007f'..'\u009f' || character == '\u061c' || character == '\u200e' || character == '\u200f' ||
            character == '\u2028' || character == '\u2029' || character in '\u202a'..'\u202e' || character in '\u2066'..'\u2069') throw ProtocolException()
        if (character.isHighSurrogate()) {
            if (++index >= value.length || !value[index].isLowSurrogate()) throw ProtocolException()
            utf8Bytes += 4
        } else {
            if (character.isLowSurrogate()) throw ProtocolException()
            utf8Bytes += if (character <= '\u007f') 1 else if (character <= '\u07ff') 2 else 3
        }
        if (utf8Bytes > 1024) throw ProtocolException()
        index++
    }
}

class SessionDirectoryPage private constructor(val items: List<SessionDirectoryEntry>, val nextCursor: String?) {
    companion object {
        private val cursorPattern = Regex("[A-Za-z0-9_-]+")
        fun parse(root: JsonObject, runtimeId: String): SessionDirectoryPage {
            Contract.uuid(runtimeId)
            root.exactKeys("ok", "data")
            if (root["ok"] != JsonBoolean(true)) throw ProtocolException()
            val data = root.obj("data")
            data.exactKeys("runtime_id", "items", "next_cursor")
            if (Contract.uuid(data.string("runtime_id")) != runtimeId) throw ProtocolException()
            val items = data.array("items").map { SessionDirectoryEntry.parse(it as? JsonObject ?: throw ProtocolException(), namesProjection = true) }
            if (items.size > 100) throw ProtocolException()
            for (index in 1 until items.size) if (items[index - 1].id >= items[index].id) throw ProtocolException()
            val cursor = when (val value = data["next_cursor"]) {
                JsonNull -> null
                is JsonString -> value.value.also { if (it.length !in 1..1024 || !cursorPattern.matches(it) || items.isEmpty()) throw ProtocolException() }
                else -> throw ProtocolException()
            }
            return SessionDirectoryPage(Collections.unmodifiableList(items), cursor)
        }
    }
}

/** Missing or conflicting row evidence is not a workspace name. */
fun directoryWorkspaceTitle(workspaceId: String, rows: List<SessionDirectoryEntry>, grant: RuntimeDirectoryEntry?, now: Long = System.currentTimeMillis()): String? {
    var title: String? = null
    for (row in rows) {
        if (row.workspaceId != workspaceId) continue
        val next = row.displayMetadata(grant, now)?.workspaceTitle ?: return null
        if (title != null && title != next) return null
        title = next
    }
    return title
}

/** Build once for a directory render instead of rescanning all rows per item. */
fun directoryWorkspaceTitles(rows: List<SessionDirectoryEntry>, grant: RuntimeDirectoryEntry?, now: Long = System.currentTimeMillis()): Map<String, String?> {
    if (grant?.canReadMetadata(now) != true) return emptyMap()
    val titles = HashMap<String, String?>()
    for (row in rows) {
        val id = row.workspaceId ?: continue
        val next = row.displayMetadata(grant, now)?.workspaceTitle
        if (!titles.containsKey(id)) titles[id] = next
        else if (titles[id] != next) titles[id] = null
    }
    return Collections.unmodifiableMap(titles)
}
