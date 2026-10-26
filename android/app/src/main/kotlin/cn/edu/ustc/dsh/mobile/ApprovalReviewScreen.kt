package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*

private val actionFields = setOf("tool", "arguments", "workspace", "resources")
private fun reviewText(value: String): String = buildString {
    var index = 0
    while (index < value.length) {
        val point = value.codePointAt(index)
        if (Character.getType(point) == Character.FORMAT.toInt() || Character.isISOControl(point) || point in 0x2028..0x2029) {
            Character.toChars(point).forEach { append("\\u%04x".format(it.code)) }
        } else appendCodePoint(point)
        index += Character.charCount(point)
    }
}
private fun pages(text: String): List<String> = buildList {
    var start = 0
    while (start < text.length) {
        var end = minOf(start + 8192, text.length)
        if (end < text.length && text[end - 1].isHighSurrogate() && text[end].isLowSurrogate()) end--
        add(text.substring(start, end)); start = end
    }
}

@Composable
fun ApprovalReviewScreen(state: HomeState, onBack: () -> Unit, onDetails: (String) -> Unit,
    onDecide: (ApprovalReviewHandle, ApprovalChoice) -> Unit, onSend: (ApprovalReviewHandle, String) -> Unit,
    onQuery: () -> Unit, onDiscard: (String) -> Unit, onRefresh: () -> Unit, onReauthenticate: () -> Unit) {
    val id = state.reviewingApprovalId ?: return
    val runtime = state.runtimeRow(state.selectedRuntimeId)
    val authorized = runtime?.access?.role == "owner" && runtime.access.scope?.actions?.containsAll(setOf("session.read", "approval.decide")) == true
    val client = state.approvals
    val current = client?.view?.items?.firstOrNull { it.status.id == id }
    val original = client?.records?.firstOrNull { authorized && it.intent.approvalId == id }
    val handle = current?.handle
    val body = if (authorized) current?.context ?: original?.intent?.context else null
    val busy = state.approvalStage != ApprovalUiStage.IDLE || client?.sending == true || client?.signing == true
    val ready = authorized && handle != null && current?.canReview == true && client?.connected == true && client.contentReady && !busy
    val reviewKey = handle ?: original?.intent?.requestId ?: id
    var page by remember(reviewKey) { mutableIntStateOf(0) }
    var reviewed by remember(reviewKey) { mutableStateOf(emptySet<Int>()) }
    var acknowledged by remember(reviewKey) { mutableStateOf(false) }
    var binding by remember(reviewKey) { mutableStateOf(false) }
    var retry by remember(reviewKey) { mutableStateOf(false) }
    var discard by remember(reviewKey) { mutableStateOf(false) }
    val raw = remember(body?.bindingSha256) { body?.let { JsonDocument.of(JsonObject(it.root.fields.filterKeys { key -> key in actionFields })).canonicalText() } }
    val displayed = remember(raw) { raw?.let(::reviewText) }
    val parts = remember(displayed) { displayed?.let(::pages) ?: emptyList() }
    val allReviewed = parts.isNotEmpty() && reviewed.size == parts.size
    val scroll = rememberScrollState()
    LaunchedEffect(reviewKey, page) { scroll.scrollTo(0) }
    Scaffold { insets ->
        Column(Modifier.fillMaxSize().padding(insets).verticalScroll(scroll).padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text("工具审批", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.semantics { heading() })
            Text(reviewText(runtime?.hostAlias ?: "当前电脑"), style = MaterialTheme.typography.titleMedium)
            Text("电脑：${runtime?.hostId.orEmpty()}\n运行实例：${state.selectedRuntimeId.orEmpty()}\n会话：${state.selectedSessionId.orEmpty()}", style = MaterialTheme.typography.bodySmall)
            Text("请核对工具、实际参数和资源范围。决定仅适用于这一次调用。")
            if (!authorized) Text("当前没有本次工具审批权限，请在电脑处理或重新核对授权。", color = MaterialTheme.colorScheme.error)
            Text(when (state.approvalStage) {
                ApprovalUiStage.PREPARING -> "正在准备本机身份确认…"
                ApprovalUiStage.AUTHENTICATING -> "请在 30 秒内完成本机身份确认。"
                ApprovalUiStage.SENDING -> "正在转交原决定；尚不能据此判断工具执行结果。"
                else -> if (current?.context != null) "在线详情，剩余约 ${(current.remainingMillis + 999) / 1000} 秒" else if (original != null) "显示本机原决定，仅供核对。" else "尚未取得当前可核对的完整详情。"
            }, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            (state.approvalError ?: client?.error ?: client?.view?.error)?.let { code ->
                Text(approvalErrorText(code), color = MaterialTheme.colorScheme.error)
                if (code == "approval.assurance_required") OutlinedButton(onReauthenticate, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("重新验证学校登录") }
            }
            original?.let {
                Text("本机原决定：${if (it.intent.decision.choice == ApprovalChoice.ALLOW_ONCE) "仅本次允许" else "拒绝"}", style = MaterialTheme.typography.titleMedium)
                Text(approvalRecordLabel(it))
                Text("原请求：${it.intent.requestId}", style = MaterialTheme.typography.bodySmall)
                OutlinedButton(onQuery, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("核对原决定结果") }
            }
            if (body != null && parts.isNotEmpty()) {
                Text("工具：${reviewText(body.root.string("tool"))}", style = MaterialTheme.typography.titleMedium)
                Text("完整动作与参数 · 第 ${page + 1} / ${parts.size} 页", style = MaterialTheme.typography.titleSmall)
                if (raw != displayed) Text("不可见的方向、格式和控制字符以 Unicode 转义显示。", style = MaterialTheme.typography.bodySmall)
                SelectionContainer { Text(parts[page], fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium) }
                Button({ reviewed = reviewed + page }, enabled = !busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(if (page in reviewed) "本页已核对" else "我已核对本页") }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedButton({ page-- }, enabled = page > 0 && !busy, modifier = Modifier.weight(1f).heightIn(min = 48.dp)) { Text("上一页") }
                    OutlinedButton({ page++ }, enabled = page + 1 < parts.size && !busy, modifier = Modifier.weight(1f).heightIn(min = 48.dp)) { Text("下一页") }
                }
                if (body.root.array("resources").isEmpty()) Text("本次未绑定额外的文件或仓库版本，工作区内容仍可能变化。", style = MaterialTheme.typography.bodySmall)
                TextButton({ binding = !binding }, Modifier.heightIn(min = 48.dp)) { Text(if (binding) "收起绑定信息" else "查看完整绑定信息") }
                if (binding) SelectionContainer { Text(reviewText(JsonDocument.of(JsonObject(body.root.fields.filterKeys { it !in actionFields })).canonicalText()), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall) }
                Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).toggleable(acknowledged, enabled = allReviewed && !busy, role = Role.Checkbox) { acknowledged = it }, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Checkbox(acknowledged, null, enabled = allReviewed && !busy)
                    Text("我已核对全部动作、参数及资源，仅为本次调用作出决定。", modifier = Modifier.weight(1f).padding(top = 12.dp))
                }
            }
            if (original == null) {
                Button({ handle?.let { onDecide(it, ApprovalChoice.ALLOW_ONCE) } }, enabled = ready && allReviewed && acknowledged,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("仅本次允许并确认身份") }
                OutlinedButton({ handle?.let { onDecide(it, ApprovalChoice.REJECT) } }, enabled = ready, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("拒绝并确认身份") }
            } else {
                val mayTransfer = original.delivery in setOf(ApprovalDecisionDelivery.PENDING, ApprovalDecisionDelivery.RECONCILE) && original.intent.current(System.currentTimeMillis())
                OutlinedButton({ retry = true }, enabled = ready && mayTransfer && (original.intent.decision.choice == ApprovalChoice.REJECT || allReviewed && acknowledged),
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("核对并转交同一原决定") }
                if (!original.intent.current(System.currentTimeMillis())) Text("原签名已过期，只能核对原请求结果。未转交的本机记录可删除后重新在线核对；已尝试转交的请求请在电脑处理。", style = MaterialTheme.typography.bodySmall)
                if (original.attempts == 0L) TextButton({ discard = true }, enabled = !busy && client?.connected == true, modifier = Modifier.heightIn(min = 48.dp)) { Text("删除本机未转交决定") }
            }
            OutlinedButton({ onDetails(id) }, enabled = client?.connected == true && client.contentReady && !busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("重新获取在线详情") }
            TextButton(onRefresh, Modifier.heightIn(min = 48.dp)) { Text("重新连接并核对权限") }
            OutlinedButton(onBack, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("关闭详情") }
            if (original?.attempts?.let { it > 0 } == true || state.approvalStage == ApprovalUiStage.SENDING) Text("关闭详情不会撤回已经转交的决定；执行结果请核对原请求。", style = MaterialTheme.typography.bodySmall)
            Text("本机身份确认用于签署当前决定；学校认证强度与远控权限仍由服务端核验。", style = MaterialTheme.typography.bodySmall)
        }
    }
    if (retry && handle != null && original != null) AlertDialog(onDismissRequest = { retry = false }, title = { Text("转交这份原决定？") },
        text = { Text("将先核对原请求状态，再使用原签名转交同一个决定。不会改换允许或拒绝，也不会创建新的决定。") },
        confirmButton = { TextButton({ retry = false; onSend(handle, original.intent.requestId) }) { Text("核对并转交") } }, dismissButton = { TextButton({ retry = false }) { Text("取消") } })
    if (discard && original != null) AlertDialog(onDismissRequest = { discard = false }, title = { Text("删除本机未转交决定？") },
        text = { Text("此操作不取消电脑上的待处理调用。之后需要重新在线获取详情，再确认新的决定。") },
        confirmButton = { TextButton({ discard = false; onDiscard(original.intent.requestId) }) { Text("删除本机记录") } }, dismissButton = { TextButton({ discard = false }) { Text("保留") } })
}

internal fun approvalRecordLabel(row: PendingApprovalDecision): String = when {
    row.remote?.hostState == ApprovalHostState.SETTLED -> when (row.remote?.outcome) { ApprovalExecutionOutcome.SUCCEEDED -> "工具执行成功，电脑已保存原生结果"; ApprovalExecutionOutcome.FAILED -> "工具执行失败，电脑已保存原生结果"; else -> "工具执行已取消，电脑已保存原生结果" }
    row.remote?.hostState == ApprovalHostState.CONSUMED -> "电脑已开始本次执行，最终结果待确认"
    row.remote?.hostState == ApprovalHostState.DENIED -> "电脑已拒绝本次调用"
    row.remote?.state == ApprovalRemoteState.OUTCOME_UNKNOWN -> "执行结果待确认，请查询原请求"
    row.delivery == ApprovalDecisionDelivery.ACCEPTED -> "服务端已接收原决定，等待电脑的执行结果"
    row.delivery == ApprovalDecisionDelivery.CONFLICT -> "已有另一份决定；本机原决定未获接收确认"
    row.delivery == ApprovalDecisionDelivery.ENDED -> "此审批已结束，不能再次转交本机决定"
    row.attempts > 0 -> "原决定结果待确认，不会自动重复转交"
    else -> "本机已保存原决定，尚未转交"
}
internal fun approvalErrorText(code: String): String = when (code) {
    "approval.assurance_required" -> "学校认证尚未满足本次策略要求。请重新登录后核对原决定；本机身份确认不能替代学校认证。"
    "approval.authentication_cancelled" -> "本机身份确认已取消，未因此转交新的决定。"
    "approval.authentication_expired", "approval.expired", "approval.signature_unavailable" -> "本机确认或签名已过期、不可用，请重新核对当前详情。原请求结果仍需单独确认。"
    "approval.stale", "approval.resync_required", "approval.conflict" -> "审批状态已更新，请重新获取当前详情并核对原决定。"
    "approval.unsupported" -> "电脑尚未开放签名审批，请在电脑处理。"
    "approval.reconcile_required", "approval.status_unavailable", "approval.delivery_unconfirmed" -> "尚未核对原决定结果，请先查询原请求。不会自动换用新的决定。"
    "device.key_invalidated", "device.key_missing", "device.wrong_key" -> "本机审批密钥已失效或不可用，请恢复设备登记后再处理。"
    "data.unavailable", "data.corrupt", "data.closed", "data.outbox_limit" -> "本机加密记录暂不可用，当前不能可靠转交新的决定。"
    else -> "暂时无法处理审批，请核对当前详情与原请求结果。"
}
