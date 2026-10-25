package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

@Composable
internal fun SessionArchiveActions(archived: Boolean, epoch: String?, enabled: Boolean, authority: Boolean, onArchive: (String, Boolean, Boolean) -> Unit, onRefresh: () -> Unit) {
    var confirm by remember(archived, epoch) { mutableStateOf(false) }
    var stopActivity by remember(archived, epoch) { mutableStateOf(false) }
    LaunchedEffect(enabled, authority) {
        if (!enabled || !authority) { confirm = false; stopActivity = false }
    }
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(if (archived) "已归档，仍可读取历史" else "会话归档", style = MaterialTheme.typography.titleMedium)
            Text(if (archived) "恢复后可继续对话。归档状态与电脑端共用。" else "保留历史和工作区位置；有活动的会话默认拒绝归档。", style = MaterialTheme.typography.bodySmall)
            if (authority) OutlinedButton({ stopActivity = false; confirm = true }, enabled = enabled && epoch != null, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                Text(if (archived) "恢复会话" else "归档会话")
            }
            TextButton(onRefresh, modifier = Modifier.heightIn(min = 48.dp)) { Text("刷新会话状态") }
        }
    }
    if (confirm && enabled && authority && epoch != null) AlertDialog(onDismissRequest = { confirm = false }, title = { Text(if (archived) "恢复此会话？" else "归档此会话？") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(if (archived) "恢复同一会话并保留历史，不会重发已有命令。" else "归档后需先恢复才能继续发送消息。")
                if (!archived) {
                    Row(Modifier.fillMaxWidth().toggleable(stopActivity, role = Role.Checkbox, onValueChange = { stopActivity = it }), verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(stopActivity, null)
                        Text("同时请求停止当前活动")
                    }
                    Text("归档确认只表示状态已保存。停止可能仍在处理中，已产生的外部操作不会撤销。", style = MaterialTheme.typography.bodySmall)
                }
            }
        }, confirmButton = { TextButton({ confirm = false; onArchive(epoch, !archived, !archived && stopActivity) }) { Text(if (archived) "确认恢复" else "确认归档") } },
        dismissButton = { TextButton({ confirm = false }) { Text("取消") } })
}
