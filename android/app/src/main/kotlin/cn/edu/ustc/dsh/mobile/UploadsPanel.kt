package cn.edu.ustc.dsh.mobile

import android.text.format.Formatter
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.network.*

@Composable
fun UploadsPanel(state: SessionUploadState, online: Boolean, onPick: (String?) -> Unit, onToggle: (String) -> Unit, onQuery: (String) -> Unit,
    onRemove: (String) -> Unit, onCancel: () -> Unit) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(
            Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(stringResource(R.string.file_ux_upload_title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
            Text(stringResource(R.string.file_ux_upload_hint), style = MaterialTheme.typography.bodySmall)
            Button({ onPick(null) }, enabled = online && !state.busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                Text(stringResource(R.string.file_ux_choose))
            }
            if (!online) Text(stringResource(R.string.file_ux_offline), style = MaterialTheme.typography.bodySmall)
            if (state.hashing) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text(stringResource(R.string.file_ux_preparing_local), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            }
            if (state.busy) OutlinedButton(onCancel, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.file_ux_stop_upload)) }
            state.error?.let { Text(fileErrorText(it), color = MaterialTheme.colorScheme.error) }

            HorizontalDivider()
            Text(stringResource(R.string.file_ux_selection, state.selected.size), style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
            if (state.selected.isEmpty()) Text(stringResource(R.string.file_ux_selection_empty), style = MaterialTheme.typography.bodySmall)
            state.rows.filter { it.stored.intent.requestId in state.selected }.forEach { row ->
                key("selected", row.stored.intent.requestId) {
                    Column {
                        Text(row.stored.intent.manifest.name, style = MaterialTheme.typography.bodyMedium)
                        if (!row.ready()) Text(stringResource(R.string.file_ux_selection_stale), color = MaterialTheme.colorScheme.error)
                        TextButton(
                            { onToggle(row.stored.intent.requestId) },
                            enabled = true,
                            modifier = Modifier.heightIn(min = 48.dp),
                        ) { Text(stringResource(R.string.file_ux_unselect)) }
                    }
                }
            }
            HorizontalDivider()
            Text(stringResource(R.string.file_ux_records), style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
            if (state.rows.isEmpty()) Text(stringResource(R.string.file_ux_records_empty), style = MaterialTheme.typography.bodySmall)
            state.rows.forEach { row -> key(row.stored.intent.requestId) {
                val id = row.stored.intent.requestId
                var details by remember { mutableStateOf(false) }
                var deleting by remember { mutableStateOf(false) }
                val queryName = stringResource(R.string.file_ux_query_upload_action, row.stored.intent.manifest.name)
                val detailName = stringResource(if (details) R.string.file_ux_collapse_action else R.string.file_ux_expand_action, row.stored.intent.manifest.name)
                val expansion = stringResource(if (details) R.string.detail_expanded else R.string.detail_collapsed)
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(row.stored.intent.manifest.name, style = MaterialTheme.typography.titleSmall)
                    val size = fileSizeText(row.stored.intent.manifest.sizeBytes)
                    Text(size, style = MaterialTheme.typography.bodySmall)
                    Text(when (row.phase) {
                        UploadPhase.NEEDS_SOURCE -> stringResource(R.string.file_ux_resume_needed)
                        UploadPhase.REGISTERING -> stringResource(R.string.file_ux_registering)
                        UploadPhase.UPLOADING -> stringResource(R.string.file_ux_uploading, fileSizeText(row.bytes), size)
                        UploadPhase.SCANNING -> stringResource(R.string.file_ux_scanning)
                        UploadPhase.WAITING -> stringResource(R.string.file_ux_waiting)
                        UploadPhase.READY -> stringResource(if (row.ready()) R.string.file_ux_ready else R.string.file_ux_selection_stale)
                        UploadPhase.BOUND -> stringResource(R.string.file_ux_bound)
                        UploadPhase.REJECTED -> stringResource(R.string.file_ux_rejected)
                        UploadPhase.EXPIRED -> stringResource(R.string.file_ux_expired)
                        UploadPhase.ERROR -> stringResource(R.string.file_ux_unknown)
                    })
                    if (row.phase == UploadPhase.UPLOADING) LinearProgressIndicator(
                        progress = { if (row.stored.intent.manifest.sizeBytes == 0L) 0f else (row.bytes.toDouble() / row.stored.intent.manifest.sizeBytes).toFloat().coerceIn(0f, 1f) },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    row.error?.let { Text(fileErrorText(it), color = MaterialTheme.colorScheme.error) }
                    if (row.ready()) Row(
                        Modifier.fillMaxWidth().heightIn(min = 48.dp).toggleable(
                            value = id in state.selected,
                            enabled = online || id in state.selected,
                            role = Role.Checkbox,
                            onValueChange = { if (id in state.selected || row.ready()) onToggle(id) },
                        ),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(id in state.selected, null, enabled = online || id in state.selected)
                        Text(stringResource(R.string.file_ux_select), Modifier.weight(1f).padding(start = 8.dp))
                    }
                    if (row.phase in setOf(UploadPhase.NEEDS_SOURCE, UploadPhase.ERROR) && row.stored.messageId == null) {
                        OutlinedButton({ onPick(id) }, enabled = online && !state.busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                            Text(stringResource(R.string.file_ux_resume))
                        }
                    }
                    TextButton({ onQuery(id) }, enabled = !state.busy, modifier = Modifier.heightIn(min = 48.dp).semantics { contentDescription = queryName }) { Text(stringResource(R.string.file_ux_query)) }
                    TextButton({ details = !details }, Modifier.heightIn(min = 48.dp).semantics { contentDescription = detailName; stateDescription = expansion }) {
                        Text(stringResource(if (details) R.string.file_ux_hide_details else R.string.file_ux_details))
                    }
                    if (details) {
                        Text(stringResource(R.string.file_ux_request_id, id), style = MaterialTheme.typography.bodySmall)
                        Text(stringResource(R.string.file_ux_digest, row.stored.intent.manifest.sha256), style = MaterialTheme.typography.bodySmall)
                        row.stored.messageId?.let { Text(stringResource(R.string.file_ux_message_id, it), style = MaterialTheme.typography.bodySmall) }
                        TextButton({ deleting = true }, enabled = !state.busy, modifier = Modifier.heightIn(min = 48.dp)) {
                            Text(stringResource(R.string.file_ux_delete_record), color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
                if (deleting) AlertDialog(
                    onDismissRequest = { deleting = false },
                    title = { Text(stringResource(R.string.file_ux_delete_upload_title)) },
                    text = { Text(stringResource(R.string.file_ux_delete_upload_body, row.stored.intent.manifest.name)) },
                    confirmButton = { TextButton({ deleting = false; onRemove(id) }, enabled = !state.busy, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.file_ux_delete_record)) } },
                    dismissButton = { TextButton({ deleting = false }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.file_ux_keep)) } },
                )
                HorizontalDivider()
            } }
            if (state.rows.isNotEmpty()) Text(stringResource(R.string.file_ux_upload_lifecycle), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
internal fun fileSizeText(bytes: Long?): String = if (bytes == null) stringResource(R.string.file_ux_size_unknown)
    else Formatter.formatFileSize(LocalContext.current, bytes)

internal fun fileErrorText(code: String) = when (code) {
    "file.too_large" -> "文件超过 200 MB 上限。"
    "file.integrity_mismatch" -> "文件内容已变化，请选择原文件或重新添加。"
    "file.source_unavailable" -> "无法读取文件，请重新选择并允许读取。"
    "file.upload_expired", "expired" -> "本次上传地址已到期，请核对原上传状态后继续。"
    "content_rejected" -> "文件未通过安全检查。"
    "scan_unavailable", "storage_unavailable", "file.scanner_unavailable" -> "检查服务暂时不可用，稍后可核对原上传。"
    "file.local_limit", "file.quota_exceeded" -> "文件记录或空间已达到上限，请处理已有文件后再试。"
    "file.already_bound" -> "附件已加入原请求，请先核对该请求。"
    "file.too_many" -> "一条消息最多选择 15 个附件。"
    "access.denied", "access_revoked" -> "附件权限已变化，请刷新会话授权。"
    "file.staging_required" -> "电脑暂存已失效，请核对状态后再发送。"
    "data.locked", "data.closed" -> "请解锁设备并重新进入会话。"
    else -> "暂时无法处理文件，请核对原上传状态。"
}
