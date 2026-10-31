package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.command.CommandKind
import cn.edu.ustc.dsh.command.PendingCommand
import cn.edu.ustc.dsh.command.RemoteCommandState
import cn.edu.ustc.dsh.network.SessionMessageActionPhase
import cn.edu.ustc.dsh.network.SessionMessageActionState

/** Plain persisted visible text only. Share and fork callbacks must revalidate the selected anchor. */
@Composable
internal fun SessionMessageActionPreview(
    state: SessionMessageActionState,
    original: PendingCommand?,
    fork: () -> Unit,
    share: () -> Unit,
    queryOriginal: () -> Unit,
    openChild: (String) -> Unit,
    dismiss: () -> Unit,
) {
    val preview = state.preview
    val record = original?.takeIf { it.intent.kind == CommandKind.FORK }
    val sameAnchor = record != null && preview != null &&
        record.intent.payload.obj("anchor").string("anchor_sha256") == preview.anchor.anchorSha256
    val ready = state.phase == SessionMessageActionPhase.READY
    val sourceAvailable = when (state.phase) {
        SessionMessageActionPhase.READY, SessionMessageActionPhase.STALE, SessionMessageActionPhase.ERROR -> true
        else -> false
    }
    val mayFork = ready && state.canFork && !state.busy && preview?.complete == true &&
        record == null && state.originalRequestId == null
    val mayShare = ready && !state.busy && preview?.complete == true && preview.shareable && !preview.text.isNullOrEmpty()
    var confirmingFork by remember(preview?.anchor, record?.intent?.requestId) { mutableStateOf(false) }
    LaunchedEffect(mayFork) { if (!mayFork) confirmingFork = false }

    if (confirmingFork && mayFork) {
        AlertDialog(
            onDismissRequest = { confirmingFork = false },
            title = { Text(stringResource(R.string.changes_fork_confirm_title)) },
            text = {
                LazyColumn(Modifier.fillMaxWidth().heightIn(max = 400.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    item { Text(stringResource(R.string.changes_fork_confirm_prefix)) }
                    item { Text(stringResource(R.string.changes_fork_confirm_workspace)) }
                    item { Text(stringResource(R.string.changes_fork_confirm_model)) }
                    item { Text(stringResource(R.string.changes_fork_confirm_once)) }
                }
            },
            confirmButton = { TextButton({ confirmingFork = false; fork() }, enabled = mayFork,
                modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.changes_fork_confirm_action)) } },
            dismissButton = { TextButton({ confirmingFork = false }, Modifier.heightIn(min = 48.dp)) {
                Text(stringResource(R.string.changes_fork_cancel))
            } },
        )
        return
    }

    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(stringResource(R.string.changes_fork_message_title)) },
        text = {
            LazyColumn(Modifier.fillMaxWidth().heightIn(max = 520.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)) {
                item("message-status") {
                    Text(stringResource(messageActionPhaseText(state.phase)),
                        Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                    if (state.busy) LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
                }
                if (preview != null) {
                    item("message-scope") {
                        Text(stringResource(R.string.changes_fork_message_scope), style = MaterialTheme.typography.bodySmall)
                        Text(stringResource(R.string.changes_fork_message_seq, preview.anchor.nativeSeq),
                            style = MaterialTheme.typography.bodySmall)
                        Text(stringResource(R.string.changes_fork_message_version, preview.anchor.messageVersionSha256),
                            style = MaterialTheme.typography.bodySmall)
                    }
                    item("exact-preview") {
                        Surface(color = MaterialTheme.colorScheme.surfaceContainer, shape = MaterialTheme.shapes.small) {
                            Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text(stringResource(R.string.changes_fork_exact_preview), style = MaterialTheme.typography.titleSmall,
                                    modifier = Modifier.semantics { heading() })
                                val text = preview.text
                                if (text != null) Text(text, style = MaterialTheme.typography.bodyMedium)
                                else Text(stringResource(R.string.changes_fork_no_share_text), style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                    }
                    item("share-scope") {
                        Text(stringResource(R.string.changes_fork_share_scope), style = MaterialTheme.typography.bodySmall)
                        if (!preview.shareable || preview.text.isNullOrEmpty()) Text(stringResource(R.string.changes_fork_not_shareable),
                            style = MaterialTheme.typography.bodySmall)
                        OutlinedButton(share, enabled = mayShare, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                            Text(stringResource(R.string.changes_fork_share_action))
                        }
                    }
                }
                if (record == null) item("new-fork") {
                    if (state.originalRequestId != null) {
                        Text(stringResource(R.string.changes_fork_original_unknown),
                            Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                        TextButton(queryOriginal, enabled = sourceAvailable && !state.busy, modifier = Modifier.heightIn(min = 48.dp)) {
                            Text(stringResource(R.string.changes_fork_query_original))
                        }
                    } else {
                        Text(stringResource(R.string.changes_fork_new_child_hint), style = MaterialTheme.typography.bodySmall)
                        Button({ confirmingFork = true }, enabled = mayFork, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                            Text(stringResource(R.string.changes_fork_new_child))
                        }
                    }
                } else item("original-fork") {
                    ForkOriginalRequest(record, sameAnchor, state.busy, sourceAvailable, queryOriginal, openChild)
                }
                state.error?.let { code -> item("action-error") {
                    Text(changesForkErrorText(code), color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                } }
            }
        },
        confirmButton = { TextButton(dismiss, Modifier.heightIn(min = 48.dp)) {
            Text(stringResource(R.string.changes_fork_close))
        } },
    )
}

@Composable
private fun ForkOriginalRequest(record: PendingCommand, sameAnchor: Boolean, busy: Boolean, current: Boolean,
    query: () -> Unit, openChild: (String) -> Unit) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(if (sameAnchor) R.string.changes_fork_original else R.string.changes_fork_other_original),
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.semantics { heading() })
            if (!sameAnchor) Text(stringResource(R.string.changes_fork_other_original_detail), style = MaterialTheme.typography.bodyMedium)
            Text(stringResource(when (record.remote) {
                RemoteCommandState.SETTLED -> R.string.changes_fork_original_settled
                RemoteCommandState.REJECTED -> R.string.changes_fork_original_rejected
                RemoteCommandState.RECEIVED -> R.string.changes_fork_original_received
                RemoteCommandState.HOST_ACCEPTED, RemoteCommandState.DISPATCHING -> R.string.changes_fork_original_accepted
                else -> R.string.changes_fork_original_unknown
            }), Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            Text(stringResource(R.string.changes_fork_request_id, record.intent.requestId), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.changes_fork_original_once), style = MaterialTheme.typography.bodySmall)
            record.createdSessionId?.let { child ->
                Text(stringResource(R.string.changes_fork_child_id, child), style = MaterialTheme.typography.bodySmall)
                if (record.remote != RemoteCommandState.SETTLED) Text(stringResource(R.string.changes_fork_child_partial),
                    style = MaterialTheme.typography.bodyMedium)
                record.forkOutcome?.let { outcome ->
                    Text(stringResource(when (outcome.workspaceAttachment) {
                        "attached" -> R.string.changes_fork_attachment_attached
                        "failed" -> R.string.changes_fork_attachment_failed
                        else -> R.string.changes_fork_attachment_unknown
                    }), style = MaterialTheme.typography.bodyMedium)
                    Text(stringResource(when (outcome.checkpoint) {
                        "persisted" -> R.string.changes_fork_checkpoint_persisted
                        "unavailable" -> R.string.changes_fork_checkpoint_unavailable
                        "failed" -> R.string.changes_fork_checkpoint_failed
                        else -> R.string.changes_fork_checkpoint_unknown
                    }), style = MaterialTheme.typography.bodyMedium)
                }
                OutlinedButton({ openChild(child) }, enabled = current && !busy,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                    Text(stringResource(R.string.changes_fork_open_child))
                }
                Text(stringResource(R.string.changes_fork_open_child_scope), style = MaterialTheme.typography.bodySmall)
            }
            if (record.remote != RemoteCommandState.SETTLED && record.remote != RemoteCommandState.REJECTED) {
                TextButton(query, enabled = current && !busy, modifier = Modifier.heightIn(min = 48.dp)) {
                    Text(stringResource(R.string.changes_fork_query_original))
                }
            }
        }
    }
}

private fun messageActionPhaseText(phase: SessionMessageActionPhase): Int = when (phase) {
    SessionMessageActionPhase.UNAVAILABLE -> R.string.changes_fork_message_unavailable
    SessionMessageActionPhase.SNAPSHOT_REQUIRED -> R.string.changes_fork_snapshot_required
    SessionMessageActionPhase.IDLE -> R.string.changes_fork_message_idle
    SessionMessageActionPhase.LOADING -> R.string.changes_fork_message_loading
    SessionMessageActionPhase.READY -> R.string.changes_fork_message_ready
    SessionMessageActionPhase.STALE -> R.string.changes_fork_message_stale
    SessionMessageActionPhase.OFFLINE -> R.string.changes_fork_offline
    SessionMessageActionPhase.DENIED -> R.string.changes_fork_denied
    SessionMessageActionPhase.ERROR -> R.string.changes_fork_error
    SessionMessageActionPhase.CLOSED -> R.string.changes_fork_closed
}
