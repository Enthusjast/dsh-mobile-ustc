package cn.edu.ustc.dsh.command

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class SessionModelSelectionTest {
    private val request = "66666666-6666-4666-8666-666666666666"
    private val runtime = "33333333-3333-4333-8333-333333333333"
    private val session = "55555555-5555-4555-8555-555555555555"
    private val epoch = "44444444-4444-4444-8444-444444444444"
    private fun selection(provider: String = "fixture", model: String = "local/模型<&", effort: String? = "high") =
        CommandIntent.selectModel(request, runtime, session, epoch, provider, model, effort)
    private fun receipt(intent: CommandIntent, state: RemoteCommandState, time: String = "2026-10-25T00:00:00Z") = CommandReceipt(request, session, intent.digest, state, time, epoch)

    @Test fun existingSharedSelectionDigestAndEncryptedJournalBytesPreserveOriginalExactly() {
        val root = File(System.getProperty("contracts.root"), "ws/v1/golden")
        val frame = JsonDocument.parse(File(root, "session-model-select.json").readBytes()).root
        val forwarded = JsonDocument.parse(File(root, "session-model-select.forwarded.json").readBytes()).root
        val parsed = CommandIntent.parse(frame)
        assertEquals(CommandKind.MODEL_SELECT, parsed.kind)
        assertEquals(forwarded.string("payload_sha256"), parsed.digest)
        assertEquals(parsed.digest, selection().digest)
        val restored = CommandIntent.stored(parsed.storageBytes())
        assertArrayEquals(parsed.storageBytes(), restored.storageBytes())
        assertEquals(SessionModelSelection("fixture", "local/模型<&", "high"), restored.modelSelection())
        assertEquals(request, restored.requestId); assertEquals(epoch, restored.epoch)
        assertFalse(parsed.toString().contains("模型"))
        assertNotEquals(parsed.digest, selection(effort = null).digest)
        assertNotEquals(parsed.digest, CommandIntent.selectModel(request, runtime, session, runtime, "fixture", "local/模型<&", "high").digest)
    }
    @Test fun onlyExactNativeIdentifiersAndOptionalAdvertisedEffortFitTheExistingWirePayload() {
        val original = "  模型/🙂  "
        assertEquals(original, selection(model = original, effort = null).modelSelection()!!.modelId)
        assertFalse(selection(effort = null).payload.fields.containsKey("reasoning_effort"))
        selection("p".repeat(128), "🙂".repeat(64), "e".repeat(64))
        for (bad in listOf("", "p".repeat(129), "\ud800")) assertThrows(ProtocolException::class.java) { selection(provider = bad) }
        for (bad in listOf("", "🙂".repeat(65))) assertThrows(ProtocolException::class.java) { selection(model = bad) }
        for (bad in listOf("", "e".repeat(65))) assertThrows(ProtocolException::class.java) { selection(effort = bad) }
        for (field in listOf("url", "api_key", "configuration", "sync_id")) assertThrows(ProtocolException::class.java) {
            CommandIntent.parse(selection().frame().with("payload" to selection().payload.with(field to "private".json())))
        }
        assertThrows(ProtocolException::class.java) { CommandIntent.parse(selection().frame().with("payload" to selection().payload.with("reasoning_effort" to JsonNull))) }
    }
    @Test fun unknownOutcomeIsNotReplayableAndSettledProvesCheckpointNotAgentActivity() {
        val intent = selection()
        val started = CommandEvolution.begin(CommandEvolution.created(intent, 1), 2)
        val unknown = CommandEvolution.receipt(started, receipt(intent, RemoteCommandState.OUTCOME_UNKNOWN))
        assertEquals(CommandDelivery.RECONCILE, unknown.delivery)
        assertThrows(CommandDataException::class.java) { CommandEvolution.begin(unknown, 3) }
        val weak = receipt(intent, RemoteCommandState.RECEIVED, "2026-10-25T00:00:01Z")
        assertSame(unknown, CommandEvolution.receipt(unknown, weak))
        assertThrows(CommandDataException::class.java) { CommandEvolution.rearm(unknown, weak) }
        for (state in listOf(RemoteCommandState.AGENT_QUEUED, RemoteCommandState.OBSERVED))
            assertThrows(CommandDataException::class.java) { CommandEvolution.receipt(started, receipt(intent, state)) }
        val settled = CommandEvolution.receipt(started, receipt(intent, RemoteCommandState.SETTLED))
        assertTrue(settled.everHostSaved); assertFalse(settled.everAgentQueued)
        assertEquals(RemoteCommandState.SETTLED, settled.remote)
    }
}
