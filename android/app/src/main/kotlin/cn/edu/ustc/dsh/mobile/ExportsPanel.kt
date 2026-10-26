package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*

@Composable
internal fun ExportsPanel(state: SessionExportState, browse: (ExportSource?, Boolean) -> Unit, request: (ExportSource) -> Unit,
    query: () -> Unit, cancel: (String) -> Unit, remove: (String) -> Unit, save: (String) -> Unit = {}, saving: Boolean = false) {
    OutlinedCard(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("电脑文件导出", style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
        Text("浏览会话附件和授权的工作区目录。导出登记后需等待安全检查。", style = MaterialTheme.typography.bodySmall)
        OutlinedButton({ browse(null, false) }, enabled = state.connected && !state.listing, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
            Text(if (state.listing) "正在读取来源…" else "浏览导出来源")
        }
        if (!state.connected) Text("来源浏览需要电脑在线并支持文件导出。已有记录可在线核对。", style = MaterialTheme.typography.bodySmall)
        state.page?.let { page ->
            if (page.items.isEmpty()) Text("本页没有可显示的来源。")
            page.items.forEach { source -> key(source) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(source.name, style = MaterialTheme.typography.titleSmall)
                    Text(if (source.origin == ExportOrigin.SESSION_ATTACHMENT) "会话附件" else "授权工作区", style = MaterialTheme.typography.bodySmall)
                    if (!source.directory) Text("${source.sizeBytes} 字节" + if (source.unavailable) " · 超过 2 GB 上限" else "", style = MaterialTheme.typography.bodySmall)
                    OutlinedButton({ if (source.directory) browse(source, false) else request(source) }, enabled = state.connected && !state.listing && !state.preparing && !source.unavailable && source.current(), modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                        Text(if (source.directory) "打开目录" else "准备导出")
                    }
                }
            } }
            if (page.cursor != null) OutlinedButton({ browse(null, true) }, enabled = state.connected && !state.listing, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("下一页来源") }
        }
        if (state.preparing) Text("正在准备原导出请求…", modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
        if (state.rows.isNotEmpty()) {
            Text("本机导出记录", style = MaterialTheme.typography.titleSmall)
            TextButton(query, Modifier.heightIn(min = 48.dp)) { Text("核对原导出请求") }
        }
        state.rows.forEach { row -> key(row.stored.intent.requestId) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(row.stored.intent.name, style = MaterialTheme.typography.titleSmall)
                Text(when (row.status?.state) {
                    FileTransferState.UPLOADING -> "电脑正在上传原文件"
                    FileTransferState.SCANNING -> "等待安全检查"
                    FileTransferState.CLEAN -> "安全检查通过，可继续保存"
                    FileTransferState.REJECTED -> "文件已被拒绝"
                    FileTransferState.EXPIRED -> "导出已过期"
                    null -> "原请求结果待核对；不会自动重新导出"
                })
                if (row.status?.downloadable() == true) Button({ save(row.stored.intent.requestId) }, enabled = !saving, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("保存到本机文档") }
                row.error?.let { Text(exportErrorText(it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                if (row.status?.state in setOf(FileTransferState.UPLOADING, FileTransferState.SCANNING) || row.stored.fileId == null)
                    TextButton({ cancel(row.stored.intent.requestId) }, enabled = state.connected, modifier = Modifier.heightIn(min = 48.dp)) { Text("停止原导出作业") }
                var forget by remember { mutableStateOf(false) }
                TextButton({ forget = true }, Modifier.heightIn(min = 48.dp)) { Text("移除此本机记录") }
                if (forget) AlertDialog(onDismissRequest = { forget = false }, title = { Text("移除本机导出记录？") }, text = { Text("移除后将无法在此处对账。此操作不会删除云端文件或停止已开始的作业。") },
                    confirmButton = { TextButton({ forget = false; remove(row.stored.intent.requestId) }) { Text("移除记录") } }, dismissButton = { TextButton({ forget = false }) { Text("保留") } })
            }
        } }
        state.error?.let { Text(exportErrorText(it), color = MaterialTheme.colorScheme.error) }
    } }
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
