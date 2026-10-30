package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*

@Composable
internal fun ExportsPanel(state: SessionExportState, browse: (ExportSource?, Boolean) -> Unit, request: (ExportSource) -> Unit,
    query: () -> Unit, cancel: (String) -> Unit, remove: (String) -> Unit, save: (String) -> Unit = {}, saving: Boolean = false) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.file_ux_export_title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
            Text(stringResource(R.string.file_ux_sources), style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
            Text(stringResource(R.string.file_ux_sources_hint), style = MaterialTheme.typography.bodySmall)
            OutlinedButton({ browse(null, false) }, enabled = state.connected && !state.listing, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                Text(stringResource(if (state.listing) R.string.file_ux_browsing else R.string.file_ux_browse))
            }
            if (!state.connected) Text(stringResource(R.string.file_ux_source_offline), style = MaterialTheme.typography.bodySmall)
            val page = state.page
            if (page == null && !state.listing) Text(stringResource(R.string.file_ux_sources_unopened), style = MaterialTheme.typography.bodySmall)
            page?.let {
                if (page.items.isEmpty()) Text(stringResource(R.string.file_ux_sources_empty))
                page.items.forEach { source -> key(source.id) {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(source.name, style = MaterialTheme.typography.titleSmall)
                        Text(stringResource(if (source.origin == ExportOrigin.SESSION_ATTACHMENT) R.string.file_ux_attachment_origin else R.string.file_ux_workspace_origin), style = MaterialTheme.typography.bodySmall)
                        Text(if (source.directory) stringResource(R.string.file_ux_directory) else fileSizeText(source.sizeBytes), style = MaterialTheme.typography.bodySmall)
                        if (source.unavailable) Text(stringResource(R.string.file_ux_source_limit), color = MaterialTheme.colorScheme.error)
                        else if (!source.current()) Text(stringResource(R.string.file_ux_source_stale), color = MaterialTheme.colorScheme.error)
                        OutlinedButton(
                            { if (source.current() && !source.unavailable) { if (source.directory) browse(source, false) else request(source) } },
                            enabled = state.connected && !state.listing && !state.preparing && !source.unavailable && source.current(),
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                        ) { Text(stringResource(if (source.directory) R.string.file_ux_open_directory else R.string.file_ux_prepare_export)) }
                    }
                    HorizontalDivider()
                } }
                if (page.cursor != null) OutlinedButton({ browse(null, true) }, enabled = state.connected && !state.listing, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                    Text(stringResource(R.string.file_ux_next_sources))
                }
            }
            if (state.preparing) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text(stringResource(R.string.file_ux_export_preparing), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            }
            HorizontalDivider()
            Text(stringResource(R.string.file_ux_export_records), style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
            if (state.rows.isEmpty()) Text(stringResource(R.string.file_ux_export_records_empty), style = MaterialTheme.typography.bodySmall)
            else TextButton(query, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.file_ux_query_exports)) }
            if (saving) Text(stringResource(R.string.file_ux_saving), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            state.rows.forEach { row -> key(row.stored.intent.requestId) {
                val id = row.stored.intent.requestId
                var details by remember { mutableStateOf(false) }
                var deleting by remember { mutableStateOf(false) }
                val saveName = stringResource(R.string.file_ux_save_action, row.stored.intent.name)
                val detailName = stringResource(if (details) R.string.file_ux_collapse_action else R.string.file_ux_expand_action, row.stored.intent.name)
                val expansion = stringResource(if (details) R.string.detail_expanded else R.string.detail_collapsed)
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(row.stored.intent.name, style = MaterialTheme.typography.titleSmall)
                    Text(fileSizeText(row.stored.intent.sizeBytes), style = MaterialTheme.typography.bodySmall)
                    Text(stringResource(when (row.status?.state) {
                        FileTransferState.UPLOADING -> R.string.file_ux_host_uploading
                        FileTransferState.SCANNING -> R.string.file_ux_export_scanning
                        FileTransferState.CLEAN -> if (row.status?.downloadable() == true) R.string.file_ux_export_ready else R.string.file_ux_export_expired
                        FileTransferState.REJECTED -> R.string.file_ux_export_rejected
                        FileTransferState.EXPIRED -> R.string.file_ux_export_expired
                        null -> R.string.file_ux_export_unknown
                    }))
                    if (row.status?.state in setOf(FileTransferState.UPLOADING, FileTransferState.SCANNING)) LinearProgressIndicator(Modifier.fillMaxWidth())
                    if (row.status?.downloadable() == true) Button(
                        { if (row.status?.downloadable() == true) save(id) },
                        enabled = !saving,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).semantics { contentDescription = saveName },
                    ) { Text(stringResource(R.string.file_ux_save)) }
                    val error = row.error ?: row.status?.error
                    error?.let { Text(exportReasonText(it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                    if (row.status?.state in setOf(FileTransferState.UPLOADING, FileTransferState.SCANNING) || row.stored.fileId == null) {
                        TextButton({ cancel(id) }, enabled = state.connected, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.file_ux_stop_export)) }
                    }
                    TextButton({ details = !details }, Modifier.heightIn(min = 48.dp).semantics { contentDescription = detailName; stateDescription = expansion }) {
                        Text(stringResource(if (details) R.string.file_ux_hide_details else R.string.file_ux_details))
                    }
                    if (details) {
                        Text(stringResource(R.string.file_ux_request_id, id), style = MaterialTheme.typography.bodySmall)
                        row.status?.manifest?.sha256?.let { Text(stringResource(R.string.file_ux_digest, it), style = MaterialTheme.typography.bodySmall) }
                        TextButton({ deleting = true }, Modifier.heightIn(min = 48.dp)) {
                            Text(stringResource(R.string.file_ux_delete_record), color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
                if (deleting) AlertDialog(
                    onDismissRequest = { deleting = false },
                    title = { Text(stringResource(R.string.file_ux_delete_export_title)) },
                    text = { Text(stringResource(R.string.file_ux_delete_export_body, row.stored.intent.name)) },
                    confirmButton = { TextButton({ deleting = false; remove(id) }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.file_ux_delete_record)) } },
                    dismissButton = { TextButton({ deleting = false }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.file_ux_keep)) } },
                )
                HorizontalDivider()
            } }
            state.error?.let { Text(exportReasonText(it), color = MaterialTheme.colorScheme.error) }
        }
    }
}

@Composable
private fun exportReasonText(code: String): String = when (code) {
    "scan_unavailable", "storage_unavailable" -> stringResource(R.string.file_ux_scan_unavailable)
    "content_rejected" -> stringResource(R.string.file_ux_content_rejected)
    "integrity_mismatch" -> stringResource(R.string.file_ux_integrity_mismatch)
    "access_revoked" -> stringResource(R.string.file_ux_access_revoked)
    "expired" -> stringResource(R.string.file_ux_export_expired)
    else -> exportErrorText(code)
}


internal fun exportErrorText(code: String) = when (code) {
    "file.export_reconcile" -> "结果尚未确认，请核对原导出请求。"
    "file.export_stale", "file.export_changed", "file.export_unavailable" -> "来源已失效或发生变化，请重新浏览。"
    "file.export_cancelled" -> "已请求停止作业；已经登记的文件仍按原到期时间清理。"
    "file.request_conflict", "command.request_conflict", "file.integrity_mismatch" -> "文件与原请求不一致，已停止处理。"
    "file.quota_exceeded", "file.local_limit" -> "文件配额已满，请清理记录或稍后重试。"
    "file.save_cancelled" -> "已取消保存，未完成的目标文档会清理。"
    "file.save_cleanup_required" -> "保存失败，目标文档可能不完整，请在所选位置删除。"
    "file.destination_unsupported" -> "所选位置不支持安全保存和失败清理，请选择其他文档位置。"
    "file.save_failed", "file.download_failed" -> "文件未保存成功，请重新选择位置后再试。"
    "file.too_large" -> "文件超过 2 GB 导出上限。"
    "access.denied", "access.revoked", "auth.identity_mismatch", "device.invalid" -> "当前账号或设备没有此文件的访问权限。"
    else -> "暂时无法完成文件操作，请检查连接后核对原请求。"
}
