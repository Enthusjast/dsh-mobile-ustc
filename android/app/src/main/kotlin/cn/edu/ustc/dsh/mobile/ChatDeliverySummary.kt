package cn.edu.ustc.dsh.mobile

import androidx.annotation.StringRes
import cn.edu.ustc.dsh.command.CommandDelivery
import cn.edu.ustc.dsh.command.CommandIntent
import cn.edu.ustc.dsh.command.CommandKind
import cn.edu.ustc.dsh.command.PendingCommand
import cn.edu.ustc.dsh.command.RemoteCommandState
import cn.edu.ustc.dsh.protocol.JsonBoolean

/** The newest message or interruption request in this session; never a claim about the running task. */
internal fun selectChatDeliveryRecord(records: List<PendingCommand>, runtimeId: String, sessionId: String): PendingCommand? =
    records.filter { it.intent.runtimeId == runtimeId && it.intent.sessionId == sessionId &&
        it.intent.kind in setOf(CommandKind.MESSAGE, CommandKind.CANCEL) }
        .maxWithOrNull(compareBy<PendingCommand>({ it.createdAt }, { it.intent.requestId }))

/** Proven delivery facts first; reconciliation never erases a fact the host already returned. */
@StringRes
internal fun commandLabel(record: PendingCommand): Int {
    if (record.delivery == CommandDelivery.PENDING && record.attempts == 0L) return R.string.chat_delivery_pending
    return when (record.remote) {
        RemoteCommandState.RECEIVED -> R.string.chat_delivery_received
        RemoteCommandState.HOST_ACCEPTED -> R.string.chat_delivery_host_saved
        RemoteCommandState.DISPATCHING -> if (record.intent.kind == CommandKind.ARCHIVE) R.string.chat_delivery_archive_dispatching else R.string.chat_delivery_dispatching
        RemoteCommandState.AGENT_QUEUED, RemoteCommandState.OBSERVED -> if (record.intent.kind == CommandKind.TIMED_QUESTION) R.string.chat_delivery_followup_queued else R.string.chat_delivery_agent_queued
        RemoteCommandState.SETTLED -> when {
            record.intent.kind == CommandKind.ARCHIVE -> if ((record.intent.payload["archived"] as? JsonBoolean)?.value == true) R.string.chat_delivery_archive_settled else R.string.chat_delivery_restore_settled
            record.intent.kind == CommandKind.CANCEL -> R.string.chat_delivery_cancel_settled
            record.intent.kind.question -> R.string.chat_delivery_answer_settled
            else -> R.string.chat_delivery_message_settled
        }
        RemoteCommandState.REJECTED -> R.string.chat_delivery_rejected
        RemoteCommandState.OUTCOME_UNKNOWN -> R.string.chat_delivery_unknown
        null -> R.string.chat_delivery_unknown
    }
}

internal fun needsDeliveryReconciliation(record: PendingCommand): Boolean =
    record.delivery == CommandDelivery.RECONCILE || record.remote == RemoteCommandState.OUTCOME_UNKNOWN

internal fun CommandIntent.isCurrentCancel(epoch: String?): Boolean =
    kind == CommandKind.CANCEL && epoch != null && this.epoch == epoch
