package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.network.*

@Composable
fun UploadsPanel(state: SessionUploadState, online: Boolean, onPick: (String?) -> Unit, onToggle: (String) -> Unit, onQuery: (String) -> Unit,
    onRemove: (String) -> Unit, onCancel: () -> Unit) {
    OutlinedCard(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("会话附件", style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
        Text("上传和检查通过后，还需电脑接收，再勾选加入消息。", style = MaterialTheme.typography.bodySmall)
        Button({ onPick(null) }, enabled = online && !state.busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("选择文件上传") }
        if (state.hashing) { LinearProgressIndicator(Modifier.fillMaxWidth()); Text("正在读取并校验文件…") }
        if (state.busy) OutlinedButton(onCancel, Modifier.heightIn(min = 48.dp)) { Text("停止本次上传") }
        state.error?.let { Text(fileErrorText(it), color = MaterialTheme.colorScheme.error) }
        state.rows.forEach { row ->
            val id = row.stored.intent.requestId
            HorizontalDivider()
            Text(row.stored.intent.manifest.name, style = MaterialTheme.typography.titleSmall)
            Text("${row.stored.intent.manifest.sizeBytes} 字节", style = MaterialTheme.typography.bodySmall)
            Text(when (row.phase) {
                UploadPhase.NEEDS_SOURCE -> "等待上传，请重新选择原文件继续。"
                UploadPhase.REGISTERING -> "正在登记这次上传…"
                UploadPhase.UPLOADING -> "正在上传：${row.bytes} 字节"
                UploadPhase.SCANNING -> "已上传，正在安全检查。"
                UploadPhase.WAITING -> "检查通过，等待电脑接收。"
                UploadPhase.READY -> "电脑已暂存，可加入消息。"
                UploadPhase.BOUND -> "已加入原请求，请核对发送记录；不代表任务完成。"
                UploadPhase.REJECTED -> "文件未通过检查。"
                UploadPhase.EXPIRED -> "上传已到期，请重新添加文件。"
                UploadPhase.ERROR -> "上传结果需要核对。"
            })
            if (row.phase == UploadPhase.UPLOADING) LinearProgressIndicator(progress = { if (row.stored.intent.manifest.sizeBytes == 0L) 0f else (row.bytes.toDouble() / row.stored.intent.manifest.sizeBytes).toFloat().coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
            row.error?.let { Text(fileErrorText(it), color = MaterialTheme.colorScheme.error) }
            if (row.ready()) Row(Modifier.fillMaxWidth()) {
                Checkbox(id in state.selected, { onToggle(id) }, enabled = online)
                Text("加入下一条消息", Modifier.padding(top = 12.dp))
            }
            if (row.phase in setOf(UploadPhase.NEEDS_SOURCE, UploadPhase.ERROR) && row.stored.messageId == null) {
                OutlinedButton({ onPick(id) }, enabled = online && !state.busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("重新选择同一文件继续") }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton({ onQuery(id) }, enabled = !state.busy, modifier = Modifier.heightIn(min = 48.dp)) { Text("核对状态") }
                TextButton({ onRemove(id) }, enabled = !state.busy, modifier = Modifier.heightIn(min = 48.dp)) { Text("移除本机记录") }
            }
        }
        if (state.rows.isNotEmpty()) Text("离开页面会停止当前读取；回来后可核对状态，必要时重新选择原文件。", style = MaterialTheme.typography.bodySmall)
    } }
}
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
