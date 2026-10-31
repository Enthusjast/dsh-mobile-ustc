package cn.edu.ustc.dsh.mobile

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.network.SessionUploadState
import cn.edu.ustc.dsh.network.UploadPhase

@Composable
fun SessionImagesPanel(
    state: SessionImageState,
    uploads: SessionUploadState?,
    canAttachImages: Boolean,
    onGallery: () -> Unit,
    onCamera: () -> Unit,
    onToggle: (String) -> Unit,
    onQuery: (String) -> Unit,
    onRemove: (String) -> Unit,
    onCancel: () -> Unit,
    onDismissPreview: () -> Unit,
    onReselect: ((String) -> Unit)? = null,
) {
    val rows = uploads?.rows.orEmpty().filter { it.stored.intent.image != null }
    val busy = state.preparing || uploads?.busy == true
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.media_panel_title), style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.semantics { heading() })
            Text(stringResource(R.string.media_panel_hint), style = MaterialTheme.typography.bodySmall)
            if (!canAttachImages) Text(stringResource(R.string.media_unsupported), style = MaterialTheme.typography.bodyMedium)
            Button(onGallery, enabled = canAttachImages && !busy,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                Text(stringResource(R.string.media_gallery))
            }
            OutlinedButton(onCamera, enabled = canAttachImages && !busy,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                Text(stringResource(R.string.media_camera))
            }
            if (state.preparing || uploads?.hashing == true) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text(stringResource(R.string.media_preparing), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            }
            if (busy) OutlinedButton(onCancel, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.media_cancel)) }
            state.error?.let { Text(stringResource(imageErrorResource(it)), color = MaterialTheme.colorScheme.error,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
            uploads?.error?.takeIf { it != state.error }?.let {
                Text(fileErrorText(it), color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            }
            HorizontalDivider()
            Text(stringResource(R.string.media_records), style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.semantics { heading() })
            Text(stringResource(R.string.media_selected, rows.count { it.stored.intent.requestId in uploads?.selected.orEmpty() }))
            if (rows.isEmpty()) Text(stringResource(R.string.media_empty), style = MaterialTheme.typography.bodySmall)
            rows.forEach { row -> key(row.stored.intent.requestId) {
                val id = row.stored.intent.requestId
                val name = row.stored.intent.manifest.name
                val selected = id in uploads?.selected.orEmpty()
                var deleting by remember { mutableStateOf(false) }
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(name, style = MaterialTheme.typography.titleSmall)
                    Text(fileSizeText(row.stored.intent.manifest.sizeBytes), style = MaterialTheme.typography.bodySmall)
                    Text(stringResource(when (row.phase) {
                        UploadPhase.NEEDS_SOURCE -> R.string.file_ux_resume_needed
                        UploadPhase.REGISTERING -> R.string.file_ux_registering
                        UploadPhase.UPLOADING -> R.string.media_uploading
                        UploadPhase.SCANNING -> R.string.media_scanning
                        UploadPhase.WAITING -> R.string.media_waiting
                        UploadPhase.READY -> if (row.ready()) R.string.media_ready else R.string.media_stale
                        UploadPhase.BOUND -> R.string.media_bound
                        UploadPhase.REJECTED -> R.string.file_ux_rejected
                        UploadPhase.EXPIRED -> R.string.file_ux_expired
                        UploadPhase.ERROR -> R.string.file_ux_unknown
                    }))
                    if (row.phase == UploadPhase.UPLOADING) {
                        LinearProgressIndicator(progress = {
                            if (row.stored.intent.manifest.sizeBytes == 0L) 0f
                            else (row.bytes.toDouble() / row.stored.intent.manifest.sizeBytes).toFloat().coerceIn(0f, 1f)
                        }, modifier = Modifier.fillMaxWidth())
                        Text(stringResource(R.string.file_ux_uploading, fileSizeText(row.bytes), fileSizeText(row.stored.intent.manifest.sizeBytes)))
                    }
                    row.error?.let { Text(fileErrorText(it), color = MaterialTheme.colorScheme.error) }
                    if (selected && !row.ready()) Text(stringResource(R.string.media_selected_stale), color = MaterialTheme.colorScheme.error)
                    if (row.ready() || selected) {
                        val action = stringResource(if (selected) R.string.media_unselect_action else R.string.media_select_action, name)
                        Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).toggleable(
                            value = selected,
                            enabled = selected || canAttachImages && row.ready(),
                            role = Role.Checkbox,
                            onValueChange = { onToggle(id) },
                        ).semantics { contentDescription = action }, verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(selected, null, enabled = selected || canAttachImages && row.ready())
                            Text(stringResource(if (selected) R.string.file_ux_unselect else R.string.media_select),
                                Modifier.weight(1f).padding(start = 8.dp))
                        }
                    }
                    if (row.stored.messageId == null && row.phase in setOf(UploadPhase.NEEDS_SOURCE, UploadPhase.ERROR)) {
                        val reselectAction = stringResource(R.string.media_reselect_action, name)
                        OutlinedButton({ onReselect?.invoke(id) }, enabled = onReselect != null && canAttachImages && !busy,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).semantics { contentDescription = reselectAction }) {
                            Text(stringResource(R.string.media_reselect))
                        }
                    }
                    val queryAction = stringResource(R.string.media_query_action, name)
                    TextButton({ onQuery(id) }, enabled = !busy,
                        modifier = Modifier.heightIn(min = 48.dp).semantics { contentDescription = queryAction }) {
                        Text(stringResource(R.string.file_ux_query))
                    }
                    val removeAction = stringResource(R.string.media_remove_action, name)
                    TextButton({ deleting = true }, enabled = !busy,
                        modifier = Modifier.heightIn(min = 48.dp).semantics { contentDescription = removeAction }) {
                        Text(stringResource(R.string.file_ux_delete_record), color = MaterialTheme.colorScheme.error)
                    }
                }
                if (deleting) AlertDialog(
                    onDismissRequest = { deleting = false },
                    title = { Text(stringResource(R.string.media_delete_title)) },
                    text = { Text(stringResource(R.string.media_delete_body, name)) },
                    confirmButton = { TextButton({ deleting = false; onRemove(id) }, enabled = !busy,
                        modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.file_ux_delete_record)) } },
                    dismissButton = { TextButton({ deleting = false }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.file_ux_keep)) } },
                )
                HorizontalDivider()
            } }
        }
    }
}

@StringRes
internal fun imageErrorResource(code: String): Int = when (code) {
    "image.too_large", "media.too_large" -> R.string.media_error_too_large
    "image.dimensions", "image.too_many_pixels", "image.decode_limit" -> R.string.media_error_dimensions
    "image.invalid", "image.unsupported", "image.decode_failed", "image.invalid_format", "image.metadata_mismatch", "image.invalid_exif" -> R.string.media_error_format
    "image.source_unavailable", "camera.unavailable", "camera.empty" -> R.string.media_error_source
    "image.capability_required", "image.unsupported_peer", "image.model_unsupported" -> R.string.media_error_unsupported
    "image.picker_failed" -> R.string.media_error_picker
    "image.picker_pending" -> R.string.media_error_pending
    "access.denied", "access_revoked", "image.stale", "data.locked", "data.closed" -> R.string.media_error_access
    else -> R.string.media_error_generic
}
