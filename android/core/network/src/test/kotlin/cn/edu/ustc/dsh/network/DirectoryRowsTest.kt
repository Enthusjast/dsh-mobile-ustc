package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

class DirectoryRowsTest {
    private val runtime = "11111111-1111-4111-8111-111111111111"
    private val session = "22222222-2222-4222-8222-222222222222"
    private val workspace = "33333333-3333-4333-8333-333333333333"
    private fun row() = jsonObject("id" to runtime.json(), "host_id" to runtime.json(), "organization_id" to runtime.json(), "protocol_version" to 1L.json(), "dsh_version" to "0.2.1-rc.2".json())
    private fun access(actions: List<String> = listOf("session.list", "session.read"), workspaces: List<String> = listOf(workspace), sessions: List<String> = listOf(session)) =
        jsonObject("role" to "viewer".json(), "grant_version" to 7L.json(), "scope" to RelayScope(actions, workspaces, sessions).json())
    private fun session(workspaceValue: JsonValue = workspace.json(), state: String = "available") = SessionDirectoryEntry.parse(jsonObject("session_id" to session.json(), "workspace_id" to workspaceValue,
        "state" to state.json(), "last_persisted_seq" to (-1L).json(), "updated_at" to Instant.now().toString().json()))

    @Test fun readScopePreservesLiteralGrantsAndMissingWorkspaceCannotExpandAuthority() {
        val direct = RuntimeDirectoryEntry.parse(row().with("access" to access()))
        assertTrue(session().readScope(direct)!!.same(RelayScope(listOf("session.read"), emptyList(), listOf(session))))
        val workspaceOnly = RuntimeDirectoryEntry.parse(row().with("access" to access(sessions = emptyList())))
        assertTrue(session().readScope(workspaceOnly)!!.same(RelayScope(listOf("session.read"), listOf(workspace), emptyList())))
        assertNull(session(JsonNull).readScope(workspaceOnly)); assertNull(session(state = "unavailable").readScope(direct))
        val listOnly = RuntimeDirectoryEntry.parse(row().with("access" to access(actions = listOf("session.list"))))
        assertTrue(listOnly.canList()); assertNull(session().readScope(listOnly))
    }
    @Test fun missingExpiredOrUnknownProtocolMetadataDisablesReading() {
        assertFalse(RuntimeDirectoryEntry.parse(row()).canList())
        val expired = access().with("expires_at" to Instant.ofEpochMilli(1000).toString().json())
        assertFalse(RuntimeDirectoryEntry.parse(row().with("access" to expired)).canList(1000))
        assertFalse(RuntimeDirectoryEntry.parse(row().with("access" to access(), "protocol_version" to 2L.json())).canList())
    }
    @Test fun malformedPresentOptionalFieldsAndGrantVersionsFailClosed() {
        for (bad in listOf(row().with("organization_id" to JsonNull), row().with("dsh_version" to 1L.json()), row().with("access" to JsonNull),
            row().with("access" to access().with("expires_at" to JsonNull)), row().with("access" to access().with("grant_version" to 0L.json())))) {
            assertThrows(ProtocolException::class.java) { RuntimeDirectoryEntry.parse(bad) }
        }
    }
    @Test fun approvalScopeRequiresExplicitClientOptInAndCurrentOwnerAuthority() {
        val scope = access(listOf("session.list", "session.read", "approval.decide"))
        val owner = RuntimeDirectoryEntry.parse(row().with("access" to scope.with("role" to "owner".json())))
        assertEquals(setOf("session.read"), session().viewScope(owner)!!.actions)
        assertEquals(setOf("session.read", "approval.decide"), session().viewScope(owner, includeApprovals = true)!!.actions)
        for (role in listOf("viewer", "operator")) {
            val grant = RuntimeDirectoryEntry.parse(row().with("access" to scope.with("role" to role.json())))
            assertEquals(setOf("session.read"), session().viewScope(grant, includeApprovals = true)!!.actions)
        }
    }
    @Test fun archivedScopeRetainsHistoryStatusAndExplicitRestoreButDropsExecutionActions() {
        val actions = listOf("session.list", "session.read", "message.submit", "session.cancel", "session.archive", "question.answer", "command.status", "approval.decide")
        val owner = RuntimeDirectoryEntry.parse(row().with("access" to access(actions).with("role" to "owner".json())))
        assertEquals(setOf("session.read", "command.status", "session.archive"), session(state = "archived").viewScope(owner, includeApprovals = true)!!.actions)
        assertNotNull(session(state = "archived").readScope(owner))
        assertTrue("session.archive" in session().viewScope(owner)!!.actions)
        val viewer = RuntimeDirectoryEntry.parse(row().with("access" to access(actions)))
        assertEquals(setOf("session.read", "command.status"), session(state = "archived").viewScope(viewer)!!.actions)
        assertFalse("session.archive" in session(state = "unavailable").viewScope(owner)!!.actions)
    }
    @Test fun exportTicketRetainsOnlyExplicitWorkspaceAuthorityIncludingForArchivedViewers() {
        val actions = listOf("session.list", "session.read", "file.download")
        val broad = RuntimeDirectoryEntry.parse(row().with("access" to access(actions)))
        val archived = session(state = "archived").viewScope(broad)!!
        assertEquals(setOf(workspace), archived.workspaces); assertEquals(setOf(session), archived.sessions)
        assertTrue(broad.scope!!.contains(archived)); assertTrue("file.download" in archived.actions)
        val narrow = RuntimeDirectoryEntry.parse(row().with("access" to access(actions, workspaces = emptyList())))
        assertTrue(session().viewScope(narrow)!!.workspaces.isEmpty())
        assertEquals(setOf(session), session().viewScope(narrow)!!.sessions)
    }

}
