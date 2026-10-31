package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test

class DirectoryMetadataTest {
    private val runtime = "11111111-1111-4111-8111-111111111111"
    private val session = "22222222-2222-4222-8222-222222222222"
    private val workspace = "33333333-3333-4333-8333-333333333333"
    private fun metadata(title: JsonValue = "原生标题".json(), workspaceTitle: JsonValue = "原生工作区".json()) = jsonObject(
        "v" to 1L.json(), "title" to title, "workspace_title" to workspaceTitle,
        "title_source" to if (title == JsonNull) JsonNull else "cached".json(),
        "title_as_of_seq" to if (title == JsonNull) JsonNull else 4L.json())
    private fun row(display: JsonObject? = metadata()) = jsonObject("session_id" to session.json(), "workspace_id" to workspace.json(),
        "state" to "available".json(), "last_persisted_seq" to 7L.json(), "updated_at" to "2026-10-30T12:00:00Z".json()).let {
        if (display == null) it else it.with("metadata" to display)
    }
    private fun grant(actions: List<String> = listOf("session.list", "session.metadata.read"), sessions: List<String> = listOf(session), expires: String? = null): RuntimeDirectoryEntry {
        var access = jsonObject("role" to "viewer".json(), "grant_version" to 1L.json(), "scope" to RelayScope(actions, emptyList(), sessions).json())
        if (expires != null) access = access.with("expires_at" to expires.json())
        return RuntimeDirectoryEntry.parse(jsonObject("id" to runtime.json(), "host_id" to runtime.json(), "protocol_version" to 1L.json(), "access" to access))
    }

    @Test fun metadataRequiresExplicitProjectionAndPreservesCachedProvenance() {
        assertThrows(ProtocolException::class.java) { SessionDirectoryEntry.parse(row()) }
        val parsed = SessionDirectoryEntry.parse(row(), namesProjection = true)
        assertEquals(session, parsed.id); assertEquals(workspace, parsed.workspaceId)
        val display = parsed.metadata!!
        assertEquals("原生标题", display.title); assertEquals("cached", display.titleSource); assertEquals(4L, display.titleAsOfSeq)
        assertNull(SessionDirectoryEntry.parse(row(null)).metadata)
        val withdrawn = SessionDirectoryEntry.parse(row(metadata(JsonNull, JsonNull)), namesProjection = true)
        val cleared = withdrawn.metadata!!
        assertNull(cleared.title); assertNull(cleared.workspaceTitle); assertNull(cleared.titleSource)
        assertNull(parsed.withoutMetadata().metadata)
        assertEquals(parsed.id, parsed.withoutMetadata().id)
    }

    @Test fun namesRequireCurrentActionResourceAndUnexpiredGrantWithoutChangingReadAccess() {
        val parsed = SessionDirectoryEntry.parse(row(), namesProjection = true)
        assertEquals("原生标题", parsed.displayMetadata(grant())!!.title)
        assertNull(parsed.displayMetadata(grant(actions = listOf("session.list"))))
        assertNull(parsed.displayMetadata(grant(actions = listOf("session.metadata.read"))))
        assertNull(parsed.displayMetadata(grant(sessions = emptyList())))
        assertNull(parsed.displayMetadata(grant(expires = "2026-10-30T12:00:00Z"), 1_800_000_000_000))
        assertTrue(grant(actions = listOf("session.list")).canList())
        assertEquals("原生工作区", directoryWorkspaceTitle(workspace, listOf(parsed), grant()))
        assertNull(directoryWorkspaceTitle(workspace, listOf(parsed, parsed.withoutMetadata()), grant()))
        assertNull(directoryWorkspaceTitle(workspace, listOf(parsed), grant(actions = listOf("session.list"))))
    }

    @Test fun unknownVersionsKeysNullShapesAndInvalidPlainNamesFailClosed() {
        for (invalid in listOf(metadata().with("v" to 2L.json()), metadata().with("cwd" to "/private".json()),
            JsonObject(metadata().fields - "title"), metadata().with("title" to JsonNull), metadata().with("title_source" to "live".json()),
            metadata().with("title_as_of_seq" to (-2L).json()))) {
            assertThrows(ProtocolException::class.java) { DirectoryDisplayMetadata.parse(invalid) }
        }
        for (invalid in listOf("", " ", "x".repeat(257), "😀".repeat(129), "bad\nname", "bad\u202ename", "bad\u200fname", "\ud800"))
            assertThrows(ProtocolException::class.java) { DirectoryDisplayMetadata.parse(metadata(invalid.json())) }
        assertEquals("😀".repeat(128), DirectoryDisplayMetadata.parse(metadata("😀".repeat(128).json())).title)
        assertThrows(ProtocolException::class.java) { SessionDirectoryEntry.parse(row().with("metadata" to JsonNull), namesProjection = true) }
        assertThrows(ProtocolException::class.java) { SessionDirectoryEntry.parse(row().with("workspace_id" to JsonNull), namesProjection = true) }
        assertThrows(ProtocolException::class.java) { SessionDirectoryEntry.parse(row().with("state" to "unavailable".json()), namesProjection = true) }
    }

    @Test fun directoryPagesBindRuntimeOrderingAndCursorWithoutGrantingNames() {
        fun page(rows: List<JsonValue>, cursor: JsonValue = JsonNull) = jsonObject("ok" to JsonBoolean(true), "data" to jsonObject(
            "runtime_id" to runtime.json(), "items" to JsonArray(rows), "next_cursor" to cursor))
        val parsed = SessionDirectoryPage.parse(page(listOf(row()), "opaque".json()), runtime)
        assertEquals("opaque", parsed.nextCursor); assertEquals(session, parsed.items.single().id)
        for (invalid in listOf(page(listOf(row(), row())), page(emptyList(), "opaque".json()), page(listOf(row()), "bad cursor".json()),
            page(listOf(row())).with("extra" to JsonNull))) {
            assertThrows(ProtocolException::class.java) { SessionDirectoryPage.parse(invalid, runtime) }
        }
        assertThrows(ProtocolException::class.java) { SessionDirectoryPage.parse(page(listOf(row())), workspace) }
    }
}
