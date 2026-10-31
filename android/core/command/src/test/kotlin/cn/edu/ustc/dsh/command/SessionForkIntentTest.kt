package cn.edu.ustc.dsh.command

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

class SessionForkIntentTest {
    private val request = "11111111-1111-4111-8111-111111111111"
    private val runtime = "22222222-2222-4222-8222-222222222222"
    private val source = "33333333-3333-4333-8333-333333333333"
    private val epoch = "44444444-4444-4444-8444-444444444444"
    private val workspace = "55555555-5555-4555-8555-555555555555"
    private val child = "66666666-6666-4666-8666-666666666666"
    private val anchor = SessionForkAnchor("77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888", 5, "a".repeat(64), "b".repeat(64))
    private fun original() = CommandIntent.forkSession(request, runtime, source, epoch, workspace, anchor)
    private fun receipt(intent: CommandIntent, state: RemoteCommandState, at: Long, selectedChild: String? = null, outcome: SessionForkOutcome? = null) =
        CommandReceipt(request, source, intent.digest, state, Instant.ofEpochMilli(at).toString(), epoch, workspace, "session.fork", selectedChild, outcome)

    @Test fun originalKeepsSourceEpochWorkspaceAndOpaqueAnchorWithoutReplacingSessionIdentity() {
        val intent = original()
        assertEquals(CommandKind.FORK, intent.kind); assertEquals(source, intent.sessionId); assertEquals(workspace, intent.workspaceId)
        assertEquals(epoch, intent.epoch); assertEquals(anchor, SessionForkAnchor.parse(intent.payload.obj("anchor")))
        assertArrayEquals(intent.storageBytes(), CommandIntent.stored(intent.storageBytes()).storageBytes())
        val changed = CommandIntent.forkSession(request, runtime, source, child, workspace, anchor)
        assertNotEquals(intent.digest, changed.digest)
        assertThrows(ProtocolException::class.java) { CommandIntent.parse(intent.frame().with("child_session_id" to child.json())) }
        assertThrows(ProtocolException::class.java) { CommandIntent.parse(intent.frame().with("payload" to intent.payload.with("new_request_id" to child.json()))) }
    }

    @Test fun forkReceiptRequiresExplicitDiscriminatorAndNeverTreatsChildAsSource() {
        val intent = original()
        val body = jsonObject("request_id" to request.json(), "session_id" to source.json(), "workspace_id" to workspace.json(),
            "command_type" to "session.fork".json(), "state" to "outcome_unknown".json(), "payload_sha256" to intent.digest.json(),
            "updated_at" to Instant.ofEpochMilli(2000).toString().json(), "child_session_id" to child.json(),
            "fork_outcome" to SessionForkOutcome("failed", "failed").json())
        val parsed = CommandReceipt.status(body)
        assertEquals(source, parsed.sessionId); assertEquals(child, parsed.childSessionId); assertEquals("failed", parsed.forkOutcome!!.workspaceAttachment)
        assertThrows(ProtocolException::class.java) { CommandReceipt.status(JsonObject(body.fields.filterKeys { it != "command_type" })) }
        assertThrows(ProtocolException::class.java) { CommandReceipt.status(JsonObject(body.fields.filterKeys { it != "fork_outcome" })) }
        assertThrows(ProtocolException::class.java) { CommandReceipt.status(body.with("session_id" to child.json())) }
        assertThrows(ProtocolException::class.java) { receipt(intent, RemoteCommandState.AGENT_QUEUED, 2000) }
        assertThrows(ProtocolException::class.java) { receipt(intent, RemoteCommandState.OBSERVED, 2000) }
        assertThrows(ProtocolException::class.java) { receipt(intent, RemoteCommandState.REJECTED, 2000, child, SessionForkOutcome("failed", "failed")) }
    }

    @Test fun anyNonRejectedKnownChildAndOutcomePersistAcrossSparseUnknownReceiptsWithoutReplay() {
        val intent = original()
        val attempted = CommandEvolution.begin(CommandEvolution.created(intent, 1000), 1001)
        val saved = CommandEvolution.receipt(attempted, receipt(intent, RemoteCommandState.HOST_ACCEPTED, 2000, child, SessionForkOutcome("failed", "persisted")))
        assertEquals(child, saved.createdSessionId); assertEquals(source, saved.intent.sessionId)
        val unknown = CommandEvolution.receipt(saved, receipt(intent, RemoteCommandState.OUTCOME_UNKNOWN, 3000))
        assertEquals(child, unknown.createdSessionId); assertEquals(SessionForkOutcome("failed", "persisted"), unknown.forkOutcome)
        val sparse = CommandEvolution.receipt(unknown, receipt(intent, RemoteCommandState.OUTCOME_UNKNOWN, 4000, child, SessionForkOutcome("unknown", "unknown")))
        assertEquals(unknown.forkOutcome, sparse.forkOutcome)
        assertThrows(CommandDataException::class.java) { CommandEvolution.rearm(sparse, receipt(intent, RemoteCommandState.RECEIVED, 5000)) }
        assertThrows(CommandDataException::class.java) { CommandEvolution.begin(sparse, 5000) }
        assertThrows(CommandDataException::class.java) { CommandEvolution.receipt(sparse, receipt(intent, RemoteCommandState.REJECTED, 5000)) }
        val other = "99999999-9999-4999-8999-999999999999"
        assertThrows(CommandDataException::class.java) { CommandEvolution.receipt(sparse, receipt(intent, RemoteCommandState.OUTCOME_UNKNOWN, 5000, other, SessionForkOutcome("failed", "persisted"))) }
        assertThrows(CommandDataException::class.java) { CommandEvolution.receipt(sparse, receipt(intent, RemoteCommandState.OUTCOME_UNKNOWN, 5000, child, SessionForkOutcome("attached", "persisted"))) }
    }

    @Test fun settledRequiresKnownChildAndPersistedCheckpointButReportsAttachmentFailureSeparately() {
        val intent = original()
        assertThrows(ProtocolException::class.java) { receipt(intent, RemoteCommandState.SETTLED, 2000) }
        assertThrows(ProtocolException::class.java) { receipt(intent, RemoteCommandState.SETTLED, 2000, child, SessionForkOutcome("attached", "failed")) }
        val attempted = CommandEvolution.begin(CommandEvolution.created(intent, 1000), 1001)
        val settled = CommandEvolution.receipt(attempted, receipt(intent, RemoteCommandState.SETTLED, 2000, child, SessionForkOutcome("failed", "persisted")))
        assertEquals(RemoteCommandState.SETTLED, settled.remote); assertEquals(child, settled.createdSessionId)
        assertEquals("failed", settled.forkOutcome!!.workspaceAttachment); assertFalse(settled.everAgentQueued)
        assertThrows(CommandDataException::class.java) { CommandEvolution.receipt(settled, receipt(intent, RemoteCommandState.OUTCOME_UNKNOWN, 3000)) }
    }
}
