package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.session.*

@Composable
fun SessionsScreen(state: HomeState, onSession: (String) -> Unit, onBack: () -> Unit, onRefresh: () -> Unit, onOlder: () -> Unit, onRetry: () -> Unit, onExit: () -> Unit) {
    val runtime = state.runtimes.firstOrNull { it.id == state.selectedRuntimeId }
    val opened = state.selectedSessionId
    Scaffold { insets ->
        Box(Modifier.fillMaxSize().padding(insets), contentAlignment = Alignment.TopCenter) {
            LazyColumn(Modifier.widthIn(max = 800.dp).fillMaxSize(), contentPadding = PaddingValues(horizontal = 20.dp, vertical = 24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                item("navigation") {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        TextButton(onBack, Modifier.heightIn(min = 48.dp)) { Text(if (opened == null) "返回电脑列表" else "返回会话列表") }
                        TextButton(onExit, Modifier.heightIn(min = 48.dp)) { Text("退出本机登录") }
                    }
                    Text(runtime?.hostAlias ?: "已授权的电脑", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.semantics { heading() })
                    Text(if (opened == null) "授权范围内的会话" else "会话 ${opened.take(8)}", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                if (opened == null) {
                    item("refresh") { OutlinedButton(onRefresh, enabled = !state.loadingSessions, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("刷新会话") } }
                    if (state.loadingSessions) item("loading") { ProgressText("正在读取会话目录") }
                    state.sessionError?.let { error -> item("error") { Text(if (error == "access.denied") "当前授权无法读取会话目录。" else "暂时无法读取会话目录，请检查网络后刷新。", color = MaterialTheme.colorScheme.error) } }
                    if (!state.loadingSessions && state.sessionError == null && state.sessions.isEmpty()) item("empty") { Text("当前授权范围内没有会话。", color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    items(state.sessions, key = { it.id }) { session ->
                        OutlinedCard(Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                Text("会话 ${session.id.take(8)}", style = MaterialTheme.typography.titleMedium)
                                Text(when (session.state) { "running" -> "任务进行中"; "archived" -> "已归档"; "unavailable" -> "电脑离线或会话不可用"; else -> "可继续查看" }, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Button({ onSession(session.id) }, enabled = runtime?.access?.let(session::readScope) != null, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("读取会话") }
                                if (session.state != "unavailable" && runtime?.access?.let(session::readScope) == null) Text("当前授权仅可查看目录。", style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                } else {
                    val read = state.reader ?: SessionReadState(SessionReadPhase.CONNECTING)
                    item("connection") {
                        Surface(color = MaterialTheme.colorScheme.surfaceContainerLow, shape = MaterialTheme.shapes.medium) {
                            Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                val label = when (read.phase) {
                                    SessionReadPhase.CONNECTING -> "正在连接电脑"
                                    SessionReadPhase.SYNCING -> "正在同步会话"
                                    SessionReadPhase.READY -> "实时连接"
                                    SessionReadPhase.BACKOFF -> "连接中断，正在重连"
                                    SessionReadPhase.OFFLINE -> "电脑离线"
                                    SessionReadPhase.AUTH_REQUIRED -> "需要更新登录"
                                    SessionReadPhase.REVOKED -> "当前会话访问权限已撤销"
                                    SessionReadPhase.ERROR -> "暂时无法读取会话"
                                    SessionReadPhase.CLOSED -> "已暂停实时读取"
                                }
                                Text(label, style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                                if (read.window != null && read.phase != SessionReadPhase.READY) Text("显示上次确认保存的记录。", style = MaterialTheme.typography.bodySmall)
                                if (read.phase == SessionReadPhase.OFFLINE && read.window == null) Text("需要电脑上线后才能读取内容。")
                                if (read.error in setOf("protocol.snapshot_too_large", "client.history_limit")) Text("内容超过本机阅读窗口，请在电脑查看完整内容。")
                                if (read.phase in setOf(SessionReadPhase.ERROR, SessionReadPhase.OFFLINE, SessionReadPhase.BACKOFF)) {
                                    OutlinedButton(onRetry, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("重新读取") }
                                }
                            }
                        }
                    }
                    val transcript = read.window
                    if (transcript != null) {
                        if (transcript.hasMore && read.phase == SessionReadPhase.READY) item("older") {
                            OutlinedButton(onOlder, enabled = !read.loadingOlder && read.pageError != "client.history_limit", modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(if (read.loadingOlder) "正在读取更早消息…" else "读取更早消息") }
                            read.pageError?.let { Text(if (it == "client.history_limit") "已达到本机阅读窗口上限，请在电脑查看更早内容。" else "更早消息暂时无法读取，可以重试。", color = MaterialTheme.colorScheme.error) }
                        }
                        if (transcript.checkpoint != "persisted") item("persistence") { Text("保存状态暂不可用，部分内容尚未确认保存。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                        if (transcript.items.isEmpty() && read.phase == SessionReadPhase.READY) item("empty-session") { Text("会话还没有消息。") }
                        items(transcript.items, key = { it.id }) { entry -> ConversationBubble(entry) }
                        if (transcript.taskRunning) item("running") { Text("电脑上的任务仍在进行。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    }
                }
            }
        }
    }
}

@Composable
private fun ProgressText(label: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp); Text(label)
    }
}
@Composable
private fun ConversationBubble(item: ConversationItem) {
    val user = item.role == ConversationRole.USER
    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (user) Arrangement.End else Arrangement.Start) {
        Surface(Modifier.widthIn(max = 640.dp).fillMaxWidth(if (user) 0.94f else 1f), color = if (user) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surfaceContainerLow, shape = MaterialTheme.shapes.medium) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(when (item.role) { ConversationRole.USER -> "你"; ConversationRole.ASSISTANT -> "助手"; ConversationRole.TOOL -> "工具"; ConversationRole.NOTICE -> "状态" }, style = MaterialTheme.typography.labelLarge)
                for ((index, block) in item.blocks.withIndex()) key(index) {
                    when (block.kind) {
                        BlockKind.TEXT -> ReadingText(block.text)
                        BlockKind.REASONING -> {
                            var expanded by remember { mutableStateOf(false) }
                            TextButton({ expanded = !expanded }, Modifier.heightIn(min = 48.dp)) { Text(if (expanded) "收起思考过程" else "查看思考过程") }
                            if (expanded) ReadingText(block.text)
                        }
                        BlockKind.TOOL -> Text(if (block.name.isEmpty()) "正在准备工具调用" else "工具调用：${block.name}")
                        BlockKind.OTHER -> Text("此内容请在电脑端查看。", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                if (item.live) Text("正在回复…", style = MaterialTheme.typography.labelMedium, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                else if (item.interrupted) Text("此次回复未完成。", style = MaterialTheme.typography.labelMedium)
                if (!item.persisted && !item.live) Text("尚未确认保存", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
@Composable
private fun ReadingText(text: String) {
    var limit by remember { mutableIntStateOf(16 * 1024) }
    val end = minOf(limit, text.length).let { if (it in 1 until text.length && text[it - 1].isHighSurrogate() && text[it].isLowSurrogate()) it - 1 else it }
    SelectionContainer { Text(text.substring(0, end), style = MaterialTheme.typography.bodyLarge) }
    if (end < text.length) TextButton({ limit = (limit + 16 * 1024).coerceAtMost(text.length) }, Modifier.heightIn(min = 48.dp)) { Text("继续显示") }
}
