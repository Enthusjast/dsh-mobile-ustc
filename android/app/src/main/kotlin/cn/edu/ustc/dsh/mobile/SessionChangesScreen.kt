package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.network.SessionChangesPhase
import cn.edu.ustc.dsh.network.SessionChangesState
import cn.edu.ustc.dsh.protocol.SessionChangeFile
import cn.edu.ustc.dsh.ui.DshSpacing
import cn.edu.ustc.dsh.ui.DshTopBar

/** Read-only configured-workspace snapshots; display paths never become executable selectors. */
@Composable
internal fun SessionChangesScreen(
    state: SessionChangesState,
    loadInitial: () -> Unit,
    loadNext: () -> Unit,
    reload: () -> Unit,
    loadPatch: (String) -> Unit,
    loadNextPatch: () -> Unit,
    copyComplete: () -> Unit,
    back: () -> Unit,
) {
    val available = state.phase == SessionChangesPhase.READY || state.phase == SessionChangesPhase.EMPTY
    val patch = state.patch
    val exactPatchText = patch?.takeUnless { it.partial }?.patchUtf8
    val patchLines = remember(state.contextId, exactPatchText) { exactPatchText?.splitToSequence('\n')?.toList().orEmpty() }
    val noFinalNewline = remember(patch) { patch?.hunks?.any { hunk -> hunk.lines.any { it.kind == "no_final_newline" } } == true }
    Scaffold(topBar = {
        DshTopBar(stringResource(R.string.changes_fork_changes_title),
            subtitle = stringResource(R.string.changes_fork_changes_subtitle),
            navigationIcon = { IconButton(back, Modifier.size(48.dp)) {
                Icon(painterResource(R.drawable.ic_back), stringResource(R.string.changes_fork_back))
            } })
    }) { insets ->
        Box(Modifier.fillMaxSize().padding(insets).consumeWindowInsets(insets), contentAlignment = Alignment.TopCenter) {
            LazyColumn(Modifier.widthIn(max = 800.dp).fillMaxSize(), contentPadding = PaddingValues(DshSpacing.page),
                verticalArrangement = Arrangement.spacedBy(DshSpacing.medium)) {
                item("scope") {
                    Text(stringResource(R.string.changes_fork_scope), style = MaterialTheme.typography.bodyMedium)
                    Text(stringResource(R.string.changes_fork_excluded), style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(stringResource(R.string.changes_fork_read_only), style = MaterialTheme.typography.bodySmall)
                }
                item("status") {
                    Text(stringResource(changesPhaseText(state.phase)),
                        Modifier.semantics { liveRegion = LiveRegionMode.Polite }, style = MaterialTheme.typography.bodyMedium)
                    if (state.loading) LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
                    if (state.phase == SessionChangesPhase.IDLE) OutlinedButton(loadInitial, enabled = !state.loading,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                        Text(stringResource(R.string.changes_fork_load))
                    }
                    if (state.phase in setOf(SessionChangesPhase.READY, SessionChangesPhase.EMPTY,
                            SessionChangesPhase.STALE, SessionChangesPhase.ERROR)) {
                        TextButton(reload, enabled = !state.loading, modifier = Modifier.heightIn(min = 48.dp)) {
                            Text(stringResource(R.string.changes_fork_reload))
                        }
                    }
                }
                state.error?.let { code -> item("error") {
                    Text(changesForkErrorText(code), color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                } }
                state.manifest?.let { manifest -> item("manifest") {
                    OutlinedCard(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(stringResource(R.string.changes_fork_snapshot), style = MaterialTheme.typography.titleSmall,
                                modifier = Modifier.semantics { heading() })
                            SelectionContainer { Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text(stringResource(R.string.changes_fork_base, manifest.baseOid), style = MaterialTheme.typography.bodySmall)
                                Text(stringResource(R.string.changes_fork_version, manifest.version), style = MaterialTheme.typography.bodySmall)
                                Text(stringResource(R.string.changes_fork_manifest, manifest.manifestSha256), style = MaterialTheme.typography.bodySmall)
                                Text(stringResource(R.string.changes_fork_snapshot_id, manifest.snapshotId), style = MaterialTheme.typography.bodySmall)
                            } }
                            Text(stringResource(R.string.changes_fork_manifest_scope), style = MaterialTheme.typography.bodySmall)
                        }
                    }
                } }
                if (state.files.isNotEmpty()) item("files-heading") {
                    Text(stringResource(R.string.changes_fork_files, state.files.size), style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.semantics { heading() })
                    Text(stringResource(if (state.hasMore) R.string.changes_fork_files_partial else R.string.changes_fork_files_complete),
                        style = MaterialTheme.typography.bodySmall)
                }
                items(state.files, key = { it.fileId }) { file ->
                    ChangeFileCard(file, patch?.fileId == file.fileId, available && !state.loading) { loadPatch(file.fileId) }
                }
                if (state.hasMore) item("files-next") {
                    OutlinedButton(loadNext, enabled = available && !state.loading,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                        Text(stringResource(R.string.changes_fork_files_next))
                    }
                }
                if (patch != null) {
                    item("patch-heading") {
                        HorizontalDivider()
                        Text(stringResource(R.string.changes_fork_patch_title), style = MaterialTheme.typography.titleMedium,
                            modifier = Modifier.semantics { heading() })
                        val file = state.files.firstOrNull { it.fileId == patch.fileId }
                        Text(file?.newPath?.display ?: file?.oldPath?.display ?: patch.fileId,
                            style = MaterialTheme.typography.bodyMedium)
                        Text(stringResource(R.string.changes_fork_version, patch.version), style = MaterialTheme.typography.bodySmall)
                        Text(stringResource(if (state.canCopyComplete) R.string.changes_fork_patch_complete else R.string.changes_fork_patch_partial),
                            style = MaterialTheme.typography.bodyMedium)
                        Text(stringResource(R.string.changes_fork_selection_partial), style = MaterialTheme.typography.bodySmall)
                        if (patch.partial) Text(stringResource(R.string.changes_fork_structured_fragments), style = MaterialTheme.typography.bodySmall)
                        if (noFinalNewline) Text(stringResource(R.string.changes_fork_no_final_newline), style = MaterialTheme.typography.bodyMedium)
                        if (patch.kind != "text") Text(changeKindText(patch.kind), style = MaterialTheme.typography.bodyMedium)
                        if (patch.patchUtf8 == null) Text(stringResource(R.string.changes_fork_patch_unavailable),
                            style = MaterialTheme.typography.bodyMedium)
                    }
                    if (patch.partial) {
                        patch.hunks.forEachIndexed { hunkIndex, hunk ->
                            item("patch-hunk:$hunkIndex") {
                                Text("@@ -${hunk.oldStart},${hunk.oldCount} +${hunk.newStart},${hunk.newCount} @@",
                                    modifier = Modifier.fillMaxWidth(),
                                    style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace))
                            }
                            items(hunk.lines.size, key = { "patch-hunk:$hunkIndex:$it" }) { index ->
                                val line = hunk.lines[index]
                                val text = line.text
                                SelectionContainer {
                                    Text(if (text == null) stringResource(R.string.changes_fork_line_unavailable) else when (line.kind) {
                                        "add" -> "+$text"
                                        "delete" -> "-$text"
                                        "context" -> " $text"
                                        else -> text
                                    }, modifier = Modifier.fillMaxWidth(),
                                        style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace), softWrap = true)
                                }
                            }
                        }
                    } else {
                        items(patchLines.size, key = { "patch-line:$it" }) { index ->
                            SelectionContainer {
                                Text(patchLines[index], modifier = Modifier.fillMaxWidth(),
                                    style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace), softWrap = true)
                            }
                        }
                    }
                    if (state.patchHasMore) item("patch-next") {
                        OutlinedButton(loadNextPatch, enabled = available && !state.loading,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                            Text(stringResource(R.string.changes_fork_patch_next))
                        }
                    }
                    item("patch-copy") {
                        Button(copyComplete, enabled = available && !state.loading && state.canCopyComplete,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                            Text(stringResource(R.string.changes_fork_copy_complete))
                        }
                        Text(stringResource(R.string.changes_fork_copy_proof), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
private fun ChangeFileCard(file: SessionChangeFile, selected: Boolean, enabled: Boolean, open: () -> Unit) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(changeStatusText(file.status), style = MaterialTheme.typography.titleSmall)
            file.oldPath?.let { Text(stringResource(R.string.changes_fork_old_path, it.display)) }
            file.newPath?.let { Text(stringResource(R.string.changes_fork_new_path, it.display)) }
            Text(stringResource(R.string.changes_fork_special_path), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(changeKindText(file.kind), style = MaterialTheme.typography.bodyMedium)
            Text(stringResource(R.string.changes_fork_modes, file.oldMode, file.newMode), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.changes_fork_patch_bytes, file.patchBytes), style = MaterialTheme.typography.bodySmall)
            if (!file.complete) Text(stringResource(R.string.changes_fork_file_partial), style = MaterialTheme.typography.bodySmall)
            OutlinedButton(open, enabled = enabled,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                Text(stringResource(if (selected) R.string.changes_fork_patch_reopen else R.string.changes_fork_patch_open))
            }
        }
    }
}

private fun changesPhaseText(phase: SessionChangesPhase): Int = when (phase) {
    SessionChangesPhase.UNAVAILABLE -> R.string.changes_fork_unavailable
    SessionChangesPhase.SNAPSHOT_REQUIRED -> R.string.changes_fork_snapshot_required
    SessionChangesPhase.IDLE -> R.string.changes_fork_idle
    SessionChangesPhase.LOADING -> R.string.changes_fork_loading
    SessionChangesPhase.READY -> R.string.changes_fork_ready
    SessionChangesPhase.EMPTY -> R.string.changes_fork_empty
    SessionChangesPhase.STALE -> R.string.changes_fork_stale
    SessionChangesPhase.OFFLINE -> R.string.changes_fork_offline
    SessionChangesPhase.DENIED -> R.string.changes_fork_denied
    SessionChangesPhase.ERROR -> R.string.changes_fork_error
    SessionChangesPhase.CLOSED -> R.string.changes_fork_closed
}

@Composable
private fun changeStatusText(status: String): String = stringResource(when (status) {
    "added" -> R.string.changes_fork_added
    "modified" -> R.string.changes_fork_modified
    "deleted" -> R.string.changes_fork_deleted
    "renamed" -> R.string.changes_fork_renamed
    "type_changed" -> R.string.changes_fork_type_changed
    else -> R.string.changes_fork_file_changed
})

@Composable
private fun changeKindText(kind: String): String = stringResource(when (kind) {
    "binary" -> R.string.changes_fork_binary
    "symlink" -> R.string.changes_fork_symlink
    "gitlink" -> R.string.changes_fork_gitlink
    else -> R.string.changes_fork_text
})

@Composable
internal fun changesForkErrorText(code: String): String = stringResource(when (code) {
    "access.denied", "access.revoked", "device.invalid", "auth.identity_mismatch" -> R.string.changes_fork_denied
    "runtime.offline", "client.not_ready" -> R.string.changes_fork_offline
    "session.changes.stale", "changes.stale", "message.stale", "message.preview_stale", "session.message.stale",
    "protocol.resync_required", "runtime.changed" -> R.string.changes_fork_stale
    "command.reconcile_required", "command.delivery_unconfirmed" -> R.string.changes_fork_original_unknown
    else -> R.string.changes_fork_action_failed
})
