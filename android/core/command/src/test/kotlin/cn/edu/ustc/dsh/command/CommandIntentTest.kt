package cn.edu.ustc.dsh.command

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class CommandIntentTest {
    private val request = "66666666-6666-4666-8666-666666666666"
    private val runtime = "33333333-3333-4333-8333-333333333333"
    private val session = "55555555-5555-4555-8555-555555555555"
    private val epoch = "44444444-4444-4444-8444-444444444444"
    private fun message(text: String = "hello") = CommandIntent.message(request, runtime, session, "queue", text)
    private fun receipt(intent: CommandIntent, state: RemoteCommandState, time: String = "2026-10-25T00:00:00.000000001Z") = CommandReceipt(request, session, intent.digest, state, time)
    @Test fun messageAndEpochBoundCancellationMatchTheSharedGoNodeDigests() {
        val root = File(System.getProperty("contracts.root"), "ws/v1/golden")
        for (kind in listOf("message-submit", "session-cancel", "session-archive", "session-archive-stop", "session-restore")) {
            val frame = JsonDocument.parse(File(root, "$kind.json").readBytes()).root
            val forwarded = JsonDocument.parse(File(root, "$kind.forwarded.json").readBytes()).root
            assertEquals(forwarded.string("payload_sha256"), CommandIntent.parse(frame).digest)
        }
        assertNotEquals(CommandIntent.cancel(request, runtime, session, epoch).digest,
            CommandIntent.cancel(request, runtime, session, "77777777-7777-4777-8777-777777777777").digest)
    }
    @Test fun archiveBindsBothChoicesAndEpochAndRetainsTheImmutableOriginal() {
        val original = CommandIntent.archive(request, runtime, session, epoch, true, false)
        assertEquals(CommandKind.ARCHIVE, original.kind)
        assertEquals(original.digest, CommandIntent.stored(original.storageBytes()).digest)
        assertNotEquals(original.digest, CommandIntent.archive(request, runtime, session, epoch, true, true).digest)
        assertNotEquals(original.digest, CommandIntent.archive(request, runtime, session, epoch, false, false).digest)
        assertNotEquals(original.digest, CommandIntent.archive(request, runtime, session, runtime, true, false).digest)
        assertThrows(ProtocolException::class.java) { CommandIntent.archive(request, runtime, session, epoch, false, true) }
        assertThrows(ProtocolException::class.java) { CommandIntent.parse(original.frame().with("payload" to jsonObject("archived" to JsonBoolean(true)))) }
    }
    @Test fun settledArchiveMeansRegistryDurabilityAndCannotBecomeAnAgentQueueFact() {
        val intent = CommandIntent.archive(request, runtime, session, epoch, true, true)
        val started = CommandEvolution.begin(CommandEvolution.created(intent, 1), 2)
        for (state in listOf(RemoteCommandState.AGENT_QUEUED, RemoteCommandState.OBSERVED)) {
            assertThrows(CommandDataException::class.java) { CommandEvolution.receipt(started, receipt(intent, state)) }
        }
        val settled = CommandEvolution.receipt(started, receipt(intent, RemoteCommandState.SETTLED))
        assertTrue(settled.everHostSaved); assertFalse(settled.everAgentQueued)
        val unknown = CommandEvolution.receipt(started, receipt(intent, RemoteCommandState.OUTCOME_UNKNOWN))
        assertThrows(CommandDataException::class.java) { CommandEvolution.rearm(unknown, receipt(intent, RemoteCommandState.RECEIVED, "2026-10-25T00:00:01Z")) }
    }
    @Test fun originalWhitespaceAndUnicodeSurviveWhileWireLimitsAndUnsafeInputFailClosed() {
        val text = "  中文🙂\n\tcontinue\r\n"
        val original = message(text)
        assertEquals(text, CommandIntent.parse(JsonDocument.parse(original.storageBytes()).root).text())
        for (bad in listOf(" ", "bad\u0000", "bad\u0085", "\ud800", "a".repeat(32_769))) assertThrows(IllegalArgumentException::class.java) { message(bad) }
        assertThrows(CommandDataException::class.java) { message("中".repeat(24_000)) }
        assertFalse(original.toString().contains("continue"))
    }
    @Test fun callerIdentityExtraEpochAndAlteredModeAreNotAdmitted() {
        val original = message().frame()
        for (bad in listOf(original.with("device_id" to request.json()), original.with("runtime_epoch" to epoch.json()),
            original.with("payload" to original.obj("payload").with("mode" to "shell".json())))) assertThrows(ProtocolException::class.java) { CommandIntent.parse(bad) }
    }
    @Test fun sendingIsMarkedUncertainBeforeIoAndCannotBeRepeatedImplicitly() {
        val intent = message(); val pending = CommandEvolution.created(intent, 1000)
        assertThrows(CommandDataException::class.java) { CommandEvolution.receipt(pending, receipt(intent, RemoteCommandState.RECEIVED)) }
        val attempted = CommandEvolution.begin(pending, 1001)
        assertEquals(CommandDelivery.RECONCILE, attempted.delivery); assertEquals(1L, attempted.attempts)
        assertThrows(CommandDataException::class.java) { CommandEvolution.begin(attempted, 1002) }
        val unknown = CommandEvolution.uncertain(attempted, "network.unavailable", 1003)
        assertNull(unknown.remote); assertEquals(CommandDelivery.RECONCILE, unknown.delivery)
    }
    @Test fun nanosecondReceiptOrderingDoesNotRollbackDurableMilestones() {
        val intent = message(); val started = CommandEvolution.begin(CommandEvolution.created(intent, 1000), 1001)
        val queued = CommandEvolution.receipt(started, receipt(intent, RemoteCommandState.AGENT_QUEUED, "2026-10-25T00:00:00.000000003Z"))
        val delayed = CommandEvolution.receipt(queued, receipt(intent, RemoteCommandState.HOST_ACCEPTED, "2026-10-25T00:00:00.000000002Z"))
        assertSame(queued, delayed); assertTrue(queued.everHostSaved); assertTrue(queued.everAgentQueued)
        val unknown = CommandEvolution.receipt(queued, receipt(intent, RemoteCommandState.OUTCOME_UNKNOWN, "2026-10-25T00:00:00.000000004Z"))
        assertTrue(unknown.everAgentQueued); assertEquals(CommandDelivery.RECONCILE, unknown.delivery)
        assertThrows(CommandDataException::class.java) { CommandEvolution.begin(unknown, 5000) }
    }
    @Test fun wrongTargetsAndConflictingTerminalFactsDoNotMutateTheOriginalCommand() {
        val intent = message(); val started = CommandEvolution.begin(CommandEvolution.created(intent, 1000), 1001)
        val settled = CommandEvolution.receipt(started, receipt(intent, RemoteCommandState.SETTLED))
        assertThrows(CommandDataException::class.java) { CommandEvolution.receipt(settled, receipt(intent, RemoteCommandState.REJECTED, "2026-10-25T00:00:00.000000002Z")) }
        assertThrows(CommandDataException::class.java) { CommandEvolution.receipt(started, CommandReceipt(request, session, "a".repeat(64), RemoteCommandState.AGENT_QUEUED, "2026-10-25T00:00:00Z")) }
        assertEquals(RemoteCommandState.SETTLED, settled.remote)
    }
    @Test fun explicitRetryRequiresReceivedAndNeverRearmsAnUnknownOutcome() {
        val intent = message(); val started = CommandEvolution.begin(CommandEvolution.created(intent, 1000), 1001)
        val received = receipt(intent, RemoteCommandState.RECEIVED)
        val pending = CommandEvolution.rearm(started, received)
        assertEquals(CommandDelivery.PENDING, pending.delivery)
        assertEquals(2L, CommandEvolution.begin(pending, 1002).attempts)

        val unknown = CommandEvolution.receipt(started, receipt(intent, RemoteCommandState.OUTCOME_UNKNOWN))
        val weaker = receipt(intent, RemoteCommandState.RECEIVED, "2026-10-25T00:00:00.000000002Z")
        assertSame(unknown, CommandEvolution.receipt(unknown, weaker))
        assertThrows(CommandDataException::class.java) { CommandEvolution.rearm(unknown, weaker) }
        val recovered = CommandEvolution.receipt(unknown, receipt(intent, RemoteCommandState.HOST_ACCEPTED, "2026-10-25T00:00:00.000000003Z"))
        assertTrue(recovered.everHostSaved)
        assertThrows(CommandDataException::class.java) { CommandEvolution.rearm(recovered, weaker) }
    }
}
