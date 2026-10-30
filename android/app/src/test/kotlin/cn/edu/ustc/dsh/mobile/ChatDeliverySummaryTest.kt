package cn.edu.ustc.dsh.mobile

import cn.edu.ustc.dsh.command.*
import org.junit.Assert.*
import org.junit.Test

class ChatDeliverySummaryTest {
    private val runtime = "11111111-1111-4111-8111-111111111111"
    private val session = "22222222-2222-4222-8222-222222222222"
    private val other = "33333333-3333-4333-8333-333333333333"
    private fun record(request: String, kind: CommandKind = CommandKind.MESSAGE, created: Long = 1, updated: Long = 1,
        delivery: CommandDelivery = CommandDelivery.CONFIRMED, remote: RemoteCommandState? = RemoteCommandState.AGENT_QUEUED,
        attempts: Long = 1, sessionId: String = session): PendingCommand {
        val intent = when (kind) {
            CommandKind.CANCEL -> CommandIntent.cancel(request, runtime, sessionId, other)
            else -> CommandIntent.message(request, runtime, sessionId, "queue", "正文")
        }
        return PendingCommand(intent, delivery, remote, attempts, 1, created, updated, null,
            remote in setOf(RemoteCommandState.HOST_ACCEPTED, RemoteCommandState.DISPATCHING, RemoteCommandState.AGENT_QUEUED), false, null)
    }
    private fun id(value: Int) = "%08d-1111-4111-8111-111111111111".format(value)

    @Test fun newestRequestUsesCreationOrderNotStatusPollingAndStaysInsideOneSession() {
        val older = record(id(1), created = 100, updated = 900)
        val newer = record(id(2), created = 200, updated = 300)
        val foreignSession = record(id(3), created = 999, updated = 999, sessionId = other)
        assertEquals(newer, selectChatDeliveryRecord(listOf(older, newer, foreignSession), runtime, session))
        assertEquals(null, selectChatDeliveryRecord(listOf(older), runtime, "44444444-4444-4444-8444-444444444444"))
        val tieLow = record(id(4), created = 500, updated = 500)
        val tieHigh = record(id(5), created = 500, updated = 500)
        assertEquals(tieHigh, selectChatDeliveryRecord(listOf(tieLow, tieHigh), runtime, session))
    }
    @Test fun provenHostFactsAreNeverReplacedByReconciliation() {
        val saved = record(id(1), delivery = CommandDelivery.RECONCILE, remote = RemoteCommandState.HOST_ACCEPTED)
        assertEquals(R.string.chat_delivery_host_saved, commandLabel(saved))
        assertTrue(needsDeliveryReconciliation(saved))
        val unknown = record(id(2), delivery = CommandDelivery.RECONCILE, remote = RemoteCommandState.OUTCOME_UNKNOWN)
        assertEquals(R.string.chat_delivery_unknown, commandLabel(unknown))
        val queued = record(id(3), remote = RemoteCommandState.AGENT_QUEUED)
        assertEquals(R.string.chat_delivery_agent_queued, commandLabel(queued))
        val unsent = record(id(4), delivery = CommandDelivery.PENDING, remote = null, attempts = 0)
        assertEquals(R.string.chat_delivery_pending, commandLabel(unsent))
    }
    @Test fun settledMessagesAndInterruptionKeepDistinctNonCompletionMeanings() {
        val settled = record(id(1), remote = RemoteCommandState.SETTLED)
        assertEquals(R.string.chat_delivery_message_settled, commandLabel(settled))
        val cancel = record(id(2), CommandKind.CANCEL, created = 1, updated = 1, remote = RemoteCommandState.SETTLED)
        assertEquals(R.string.chat_delivery_cancel_settled, commandLabel(cancel))
        val rejected = record(id(3), remote = RemoteCommandState.REJECTED)
        assertEquals(R.string.chat_delivery_rejected, commandLabel(rejected))
    }
}
