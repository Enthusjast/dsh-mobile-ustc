package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.network.SessionModelCatalogPhase
import cn.edu.ustc.dsh.network.SessionModelCatalogState
import cn.edu.ustc.dsh.protocol.SessionModelSelection
import cn.edu.ustc.dsh.ui.DshSpacing
import cn.edu.ustc.dsh.ui.DshTopBar

/** Catalog labels are plain display text. Only the original opaque identifiers form a selection. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun SessionModelsScreen(
    state: SessionModelCatalogState,
    original: PendingCommand?,
    busy: Boolean,
    error: String?,
    loadInitial: () -> Unit,
    loadNext: () -> Unit,
    reload: () -> Unit,
    select: (SessionModelSelection) -> Unit,
    queryOriginal: () -> Unit,
    sendOriginal: (String) -> Unit,
    discardUnsent: (String) -> Unit,
    back: () -> Unit,
) {
    var query by remember(state.contextId) { mutableStateOf("") }
    var choice by remember(state.contextId) { mutableStateOf<Pair<String, String>?>(null) }
    var effort by remember(state.contextId) { mutableStateOf<String?>(null) }
    val selected = state.items.firstOrNull { choice == it.provider.id to it.model.id }
    LaunchedEffect(selected?.provider?.id, selected?.model?.id, selected?.reasoningEfforts) {
        if (selected == null || effort != null && selected.reasoningEfforts.none { it.id == effort }) effort = null
    }
    val groups = remember(state.items, query) {
        val needle = query.trim()
        state.items.asSequence().filter { item -> needle.isEmpty() ||
            item.provider.label.contains(needle, true) || item.provider.id.contains(needle, true) ||
            item.model.label.contains(needle, true) || item.model.id.contains(needle, true)
        }.groupBy { it.provider.id }
    }
    val request = original?.takeIf { it.intent.kind == CommandKind.MODEL_SELECT }
    val unresolved = request != null && request.remote !in setOf(RemoteCommandState.SETTLED, RemoteCommandState.REJECTED)
    val available = state.phase in setOf(SessionModelCatalogPhase.READY, SessionModelCatalogPhase.PARTIAL)
    val loading = state.inFlight > 0 || state.phase == SessionModelCatalogPhase.LOADING
    Scaffold(topBar = {
        DshTopBar(stringResource(R.string.models_title), subtitle = stringResource(R.string.models_not_current),
            navigationIcon = { IconButton(back, Modifier.size(48.dp)) {
                Icon(painterResource(R.drawable.ic_back), stringResource(R.string.models_back))
            } })
    }) { insets ->
        Column(Modifier.fillMaxSize().padding(insets).consumeWindowInsets(insets).imePadding(),
            horizontalAlignment = Alignment.CenterHorizontally) {
            LazyColumn(Modifier.widthIn(max = 800.dp).fillMaxWidth().weight(1f),
                contentPadding = PaddingValues(DshSpacing.page), verticalArrangement = Arrangement.spacedBy(DshSpacing.medium)) {
                item("catalog-state") {
                    Text(stringResource(when (state.phase) {
                        SessionModelCatalogPhase.UNAVAILABLE -> R.string.models_unsupported
                        SessionModelCatalogPhase.SNAPSHOT_REQUIRED -> R.string.models_snapshot_required
                        SessionModelCatalogPhase.IDLE -> R.string.models_idle
                        SessionModelCatalogPhase.LOADING -> R.string.models_loading
                        SessionModelCatalogPhase.READY -> R.string.models_ready
                        SessionModelCatalogPhase.EMPTY -> R.string.models_empty
                        SessionModelCatalogPhase.PARTIAL -> R.string.models_partial
                        SessionModelCatalogPhase.OFFLINE -> R.string.models_offline
                        SessionModelCatalogPhase.CATALOG_CHANGED -> R.string.models_changed
                        SessionModelCatalogPhase.DENIED -> R.string.models_denied
                        SessionModelCatalogPhase.ERROR -> R.string.models_error
                        SessionModelCatalogPhase.CLOSED -> R.string.models_closed
                    }), Modifier.semantics { liveRegion = LiveRegionMode.Polite }, style = MaterialTheme.typography.bodyMedium)
                    if (loading) LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
                    if (state.unavailableProviderCount > 0) Text(stringResource(R.string.models_provider_failures, state.unavailableProviderCount),
                        color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
                    if (state.phase == SessionModelCatalogPhase.IDLE) TextButton(loadInitial, enabled = !busy && !loading,
                        modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.models_load)) }
                    if (state.phase in setOf(SessionModelCatalogPhase.READY, SessionModelCatalogPhase.PARTIAL,
                            SessionModelCatalogPhase.EMPTY, SessionModelCatalogPhase.CATALOG_CHANGED, SessionModelCatalogPhase.ERROR)) {
                        TextButton(reload, enabled = !busy && !loading, modifier = Modifier.heightIn(min = 48.dp)) {
                            Text(stringResource(R.string.models_reload))
                        }
                    }
                }
                if (state.items.isNotEmpty()) item("search") {
                    OutlinedTextField(query, { query = it }, label = { Text(stringResource(R.string.models_search)) },
                        supportingText = { Text(stringResource(R.string.models_search_scope)) },
                        modifier = Modifier.fillMaxWidth(), singleLine = true)
                }
                if (request != null) item("original-selection") {
                    ModelOriginalRequest(request, busy, queryOriginal, sendOriginal, discardUnsent, available && state.canSelect)
                }
                if (state.items.isNotEmpty() && groups.isEmpty()) item("no-local-matches") {
                    Text(stringResource(R.string.models_no_matches), color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                for ((providerId, models) in groups) {
                    item("provider:$providerId") {
                        Text(models.first().provider.label, Modifier.semantics { heading() }, style = MaterialTheme.typography.titleSmall)
                        SelectionContainer { Text(providerId, style = MaterialTheme.typography.bodySmall) }
                    }
                    items(models, key = { it.provider.id to it.model.id }) { item ->
                        val checked = choice == item.provider.id to item.model.id
                        Row(Modifier.fillMaxWidth().heightIn(min = 64.dp).selectable(checked,
                            enabled = available && state.canSelect && !busy && !unresolved,
                            role = Role.RadioButton, onClick = {
                                if (!checked) { choice = item.provider.id to item.model.id; effort = null }
                            }).padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(checked, onClick = null, enabled = available && state.canSelect && !busy && !unresolved)
                            Column(Modifier.weight(1f).padding(start = 8.dp)) {
                                Text(item.model.label, style = MaterialTheme.typography.bodyLarge)
                                Text(item.model.id, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
                if (state.hasMore) item("next-page") {
                    OutlinedButton(loadNext, enabled = !busy && !loading && available,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.models_next_page)) }
                }
                selected?.let { model -> item("selection-preview") {
                    HorizontalDivider()
                    Text(stringResource(R.string.models_selected), style = MaterialTheme.typography.titleSmall)
                    SelectionContainer { Text("${model.provider.id}\n${model.model.id}", style = MaterialTheme.typography.bodyMedium) }
                    if (model.reasoningEfforts.isNotEmpty()) {
                        Text(stringResource(R.string.models_effort), style = MaterialTheme.typography.bodyMedium)
                        FlowRow(Modifier.fillMaxWidth().selectableGroup(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            FilterChip(effort == null, { effort = null }, enabled = !busy && !unresolved,
                                label = { Text(stringResource(R.string.models_effort_none)) }, modifier = Modifier.heightIn(min = 48.dp))
                            model.reasoningEfforts.forEach { option ->
                                FilterChip(effort == option.id, { effort = option.id }, enabled = !busy && !unresolved,
                                    label = { Text(option.label) }, modifier = Modifier.heightIn(min = 48.dp))
                            }
                        }
                    } else Text(stringResource(R.string.models_no_effort), style = MaterialTheme.typography.bodySmall)
                } }
                if (error != null) item("selection-error") {
                    Text(modelActionError(error), color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                }
            }
            Surface(Modifier.fillMaxWidth(), tonalElevation = 3.dp) {
                Column(Modifier.fillMaxWidth().padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    Button({ selected?.let { select(SessionModelSelection(it.provider.id, it.model.id, effort)) } },
                        enabled = selected != null && available && state.canSelect && !busy && !unresolved,
                        modifier = Modifier.widthIn(max = 768.dp).fillMaxWidth().heightIn(min = 48.dp)) {
                        Text(stringResource(if (busy) R.string.models_saving else R.string.models_apply))
                    }
                    Text(stringResource(R.string.models_checkpoint_scope), style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.widthIn(max = 768.dp).fillMaxWidth())
                }
            }
        }
    }
}

@Composable
private fun ModelOriginalRequest(record: PendingCommand, busy: Boolean, query: () -> Unit, send: (String) -> Unit, discard: (String) -> Unit, selectable: Boolean) {
    val selection = record.intent.modelSelection() ?: return
    val unsent = record.delivery == CommandDelivery.PENDING && record.attempts == 0L && record.remote == null && !record.everHostSaved && !record.everAgentQueued
    var abandoning by remember(record.intent.requestId) { mutableStateOf(false) }
    LaunchedEffect(unsent) { if (!unsent) abandoning = false }
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(if (record.remote == RemoteCommandState.SETTLED) R.string.models_recent_confirmed else R.string.models_original),
                style = MaterialTheme.typography.titleSmall)
            Text(stringResource(when (record.remote) {
                RemoteCommandState.SETTLED -> R.string.models_settled
                RemoteCommandState.REJECTED -> R.string.models_rejected
                RemoteCommandState.OUTCOME_UNKNOWN -> R.string.models_unknown
                RemoteCommandState.RECEIVED -> R.string.models_relay_received
                RemoteCommandState.HOST_ACCEPTED, RemoteCommandState.DISPATCHING -> R.string.models_host_saved
                else -> if (record.delivery == CommandDelivery.BLOCKED) R.string.models_blocked
                    else if (record.attempts == 0L) R.string.models_saved else R.string.models_unknown
            }), Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            SelectionContainer { Text("${selection.providerId}\n${selection.modelId}" +
                (selection.reasoningEffortId?.let { "\n$it" } ?: ""), style = MaterialTheme.typography.bodyMedium) }
            SelectionContainer { Text(stringResource(R.string.models_request_id, record.intent.requestId), style = MaterialTheme.typography.bodySmall) }
            if (record.remote !in setOf(RemoteCommandState.SETTLED, RemoteCommandState.REJECTED)) {
                if (record.attempts > 0L) TextButton(query, enabled = !busy, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.models_query)) }
                if (record.delivery == CommandDelivery.PENDING) OutlinedButton({ send(record.intent.requestId) },
                    enabled = !busy && selectable, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.models_send_original)) }
                if (unsent) TextButton({ abandoning = true }, enabled = !busy, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.models_discard_unsent)) }
            }
        }
    }
    if (abandoning && unsent) AlertDialog(onDismissRequest = { abandoning = false },
        title = { Text(stringResource(R.string.models_discard_unsent)) },
        text = { Text(stringResource(R.string.models_discard_unsent_detail)) },
        confirmButton = { TextButton({ abandoning = false; discard(record.intent.requestId) }, enabled = !busy,
            modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.models_confirm_discard)) } },
        dismissButton = { TextButton({ abandoning = false }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.action_cancel)) } })
}

@Composable
private fun modelActionError(code: String): String = stringResource(when (code) {
    "access.denied" -> R.string.models_denied
    "runtime.offline", "client.not_ready" -> R.string.models_offline
    "protocol.resync_required", "runtime.changed" -> R.string.models_changed
    "command.reconcile_required", "command.delivery_unconfirmed" -> R.string.models_unknown
    else -> R.string.models_action_failed
})
