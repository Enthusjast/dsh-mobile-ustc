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
import cn.edu.ustc.dsh.command.*

@Composable
fun SessionsScreen(state: HomeState, onSession: (String) -> Unit, onBack: () -> Unit, onRefresh: () -> Unit, onOlder: () -> Unit, onRetry: () -> Unit, onExit: () -> Unit,
    onSubmit: (String, String, Boolean) -> Unit = { _, _, _ -> }, onSendPending: (String) -> Unit = {}, onQueryCommands: () -> Unit = {}, onCancelSession: (String) -> Unit = {}) {
    val runtime = state.runtimes.firstOrNull { it.id == state.selectedRuntimeId }
    val opened = state.selectedSessionId
    val canCompose = opened != null && state.outbox != null && runtime?.access?.role in setOf("operator", "owner") && runtime?.access?.scope?.actions?.containsAll(setOf("message.submit", "command.status")) == true
    Scaffold(bottomBar = {
        if (canCompose) SessionComposer(state, onSubmit)
    }) { insets ->
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
                                Button({ onSession(session.id) }, enabled = runtime?.access?.let(session::viewScope) != null, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(if (session.state == "unavailable") "查看会话与待发送记录" else "读取会话") }
                                if (runtime?.access?.let(session::viewScope) == null) Text("当前授权仅可查看目录。", style = MaterialTheme.typography.bodySmall)
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
                    state.commandError?.let { error -> item("command-error") { Text(commandErrorText(error), color = MaterialTheme.colorScheme.error) } }
                    state.outbox?.let { outbox ->
                        outbox.error?.let { error -> item("outbox-error") { Text(commandErrorText(error), color = MaterialTheme.colorScheme.error, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) } }
                        if (outbox.records.isNotEmpty()) item("outbox-heading") {
                            Text("本机发送记录", style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
                            Text("入队确认不代表任务完成。连接恢复后会先核对原请求状态。", style = MaterialTheme.typography.bodySmall)
                            OutlinedButton(onQueryCommands, Modifier.heightIn(min = 48.dp)) { Text("核对发送状态") }
                        }
                        items(outbox.records, key = { "command:${it.intent.requestId}" }) { record ->
                            OutlinedCard(Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                    Text(commandLabel(record), style = MaterialTheme.typography.titleSmall)
                                    if (!record.everAgentQueued) record.intent.text()?.let { ReadingText(it, 512) }
                                    if (record.delivery == CommandDelivery.PENDING && record.attempts == 0L) {
                                        OutlinedButton({ onSendPending(record.intent.requestId) }, enabled = outbox.connected, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("发送这条待发消息") }
                                    }
                                    if (record.remote == RemoteCommandState.RECEIVED && !record.everHostSaved && record.attempts > 0) {
                                        var retry by remember { mutableStateOf(false) }
                                        OutlinedButton({ retry = true }, enabled = outbox.connected, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("重新转交同一请求") }
                                        if (retry) AlertDialog(onDismissRequest = { retry = false }, title = { Text("重新转交这条原请求？") },
                                            text = { Text("会先核对状态并保留原请求编号。主机若已接收，将返回原状态，不会创建一条新消息。") },
                                            confirmButton = { TextButton({ retry = false; onSendPending(record.intent.requestId) }) { Text("核对并重试") } },
                                            dismissButton = { TextButton({ retry = false }) { Text("取消") } })
                                    }
                                    record.error?.let { Text(commandErrorText(it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                                }
                            }
                        }
                    }
                    val cancelEpoch = read.runtimeEpoch
                    if (read.phase == SessionReadPhase.READY && transcript?.taskRunning == true && cancelEpoch != null && runtime?.access?.scope?.actions?.containsAll(setOf("session.cancel", "command.status")) == true) item("cancel-task") {
                        var confirm by remember(cancelEpoch) { mutableStateOf(false) }
                        OutlinedButton({ confirm = true }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("中断当前任务") }
                        if (confirm) AlertDialog(onDismissRequest = { confirm = false }, title = { Text("中断电脑上的当前任务？") },
                            text = { Text("这不会清空已排队的消息。后续任务是否继续，以电脑端状态为准。") },
                            confirmButton = { TextButton({ confirm = false; onCancelSession(cancelEpoch) }) { Text("确认中断") } },
                            dismissButton = { TextButton({ confirm = false }) { Text("继续运行") } })
                    }
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
private fun ReadingText(text: String, initial: Int = 16 * 1024) {
    var limit by remember { mutableIntStateOf(initial) }
    val end = minOf(limit, text.length).let { if (it in 1 until text.length && text[it - 1].isHighSurrogate() && text[it].isLowSurrogate()) it - 1 else it }
    SelectionContainer { Text(text.substring(0, end), style = MaterialTheme.typography.bodyLarge) }
    if (end < text.length) TextButton({ limit = (limit + 16 * 1024).coerceAtMost(text.length) }, Modifier.heightIn(min = 48.dp)) { Text("继续显示") }
}

@Composable
private fun SessionComposer(state: HomeState, onSubmit: (String, String, Boolean) -> Unit) {
    var text by remember(state.composerRevision) { mutableStateOf("") }
    var mode by remember { mutableStateOf("queue") }
    val placeholder = "11111111-1111-4111-8111-111111111111"
    val valid = text.isNotBlank() && runCatching { CommandIntent.message(placeholder, placeholder, placeholder, mode, text) }.isSuccess
    val online = state.outbox?.connected == true && state.reader?.phase == SessionReadPhase.READY
    Surface(tonalElevation = 3.dp) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().imePadding().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(mode == "queue", { mode = "queue" }, label = { Text("排队") }, modifier = Modifier.heightIn(min = 48.dp))
                FilterChip(mode == "steer", { mode = "steer" }, label = { Text("插入当前任务") }, modifier = Modifier.heightIn(min = 48.dp))
            }
            OutlinedTextField(text, { if (it.length <= 65_536) text = it }, label = { Text("消息内容") }, minLines = 1, maxLines = 5,
                isError = text.isNotBlank() && !valid, supportingText = { Text(if (text.isNotBlank() && !valid) "内容过长或包含不支持的字符，请调整后重试。" else if (online) "先保存在本机，再发送到电脑。" else "离线时只保存到本机，上线后可手动发送。") }, modifier = Modifier.fillMaxWidth())
            Button({ onSubmit(mode, text, online) }, enabled = valid && !state.submitting, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                Text(if (state.submitting) "正在保存…" else if (online) "发送" else "保存待发送")
            }
        }
    }
}
private fun commandLabel(record: PendingCommand): String = when {
    record.delivery == CommandDelivery.PENDING -> "手机待发送"
    record.remote == RemoteCommandState.RECEIVED -> "中继已接收，尚未确认主机保存"
    record.remote == RemoteCommandState.HOST_ACCEPTED -> "主机已保存"
    record.remote == RemoteCommandState.DISPATCHING -> "主机已保存，正在交给 Agent"
    record.remote in setOf(RemoteCommandState.AGENT_QUEUED, RemoteCommandState.OBSERVED) -> "Agent 已入队"
    record.remote == RemoteCommandState.SETTLED -> if (record.intent.kind == CommandKind.CANCEL) "中断请求已确认" else "命令已完成"
    record.remote == RemoteCommandState.REJECTED -> "主机拒绝了此命令"
    else -> "结果待确认"
}
private fun commandErrorText(code: String) = when (code) {
    "data.locked", "data.lock_required" -> "请解锁设备并设置安全锁屏后，再使用本机发送记录。"
    "data.key_missing", "data.key_corrupt", "data.owner_mismatch", "data.corrupt", "data.unavailable" -> "本机发送记录无法读取，已停用发送。请先核对本机数据。"
    "data.outbox_limit" -> "本机发送记录已达到容量上限，请核对已有记录后再继续。"
    "command.busy" -> "待处理的发送操作较多，请稍后核对发送状态。"
    "command.too_large", "command.invalid" -> "消息过长或格式不支持，请调整后重试。"
    "command.reconcile_required", "command.delivery_unconfirmed", "command.status_unavailable" -> "尚未核对发送结果，请查询原请求状态；不会自动重复发送。"
    "runtime.changed" -> "电脑运行环境已重新启动，原中断请求不会用于新的任务。"
    else -> "暂时无法处理此发送操作，请先核对发送状态。"
}
