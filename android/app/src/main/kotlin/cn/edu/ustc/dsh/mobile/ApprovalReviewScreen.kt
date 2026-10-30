package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private data class ProjectedApproval(val context: ApprovalContext, val raw: Boolean, val result: ApprovalReadingProjection)

@Composable
private fun approvalProjectionLabels() = ApprovalProjectionLabels(
    stringResource(R.string.approval_ux_object_type), stringResource(R.string.approval_ux_array_type),
    stringResource(R.string.approval_ux_string_type), stringResource(R.string.approval_ux_number_type),
    stringResource(R.string.approval_ux_boolean_type), stringResource(R.string.approval_ux_null_type),
    mapOf(
        "tool" to stringResource(R.string.approval_ux_field_tool),
        "arguments" to stringResource(R.string.approval_ux_field_arguments),
        "workspace" to stringResource(R.string.approval_ux_field_workspace),
        "resources" to stringResource(R.string.approval_ux_field_resources),
        "domain" to stringResource(R.string.approval_ux_field_domain),
        "protocol_version" to stringResource(R.string.approval_ux_field_protocol),
        "host_id" to stringResource(R.string.approval_ux_field_host),
        "installation_id" to stringResource(R.string.approval_ux_field_installation),
        "runtime_id" to stringResource(R.string.approval_ux_field_runtime),
        "runtime_epoch" to stringResource(R.string.approval_ux_field_epoch),
        "session_id" to stringResource(R.string.approval_ux_field_session),
        "dsh_session_id" to stringResource(R.string.approval_ux_field_native_session),
        "approval_id" to stringResource(R.string.approval_ux_field_approval),
        "execution_id" to stringResource(R.string.approval_ux_field_execution),
        "call_id" to stringResource(R.string.approval_ux_field_call),
        "nonce" to stringResource(R.string.approval_ux_field_nonce),
        "policy_version" to stringResource(R.string.approval_ux_field_policy),
        "required_assurance" to stringResource(R.string.approval_ux_field_assurance),
        "created_at" to stringResource(R.string.approval_ux_field_created),
        "expires_at" to stringResource(R.string.approval_ux_field_expires),
    ),
)

@OptIn(ExperimentalLayoutApi::class)
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
    val valid = authorized && state.phase == HomePhase.READY && handle != null && current?.canReview == true &&
        current.remainingMillis > 0 && client?.connected == true && client.contentReady &&
        handle.runtimeId == state.selectedRuntimeId && handle.sessionId == state.selectedSessionId &&
        body != null && body.bindingSha256 == handle.bindingSha256 && body.current(System.currentTimeMillis()) &&
        runtime?.access?.expiresAt?.let { it <= System.currentTimeMillis() } != true
    val reviewKey = handle ?: original?.intent?.requestId ?: id
    var page by remember(reviewKey, valid) { mutableIntStateOf(0) }
    var reviewed by remember(reviewKey, valid) { mutableStateOf(emptySet<Int>()) }
    var acknowledged by remember(reviewKey, valid) { mutableStateOf(false) }
    var rawView by remember(reviewKey) { mutableStateOf(false) }
    var retired by remember(reviewKey) { mutableStateOf(false) }
    var retry by remember(reviewKey, valid) { mutableStateOf(false) }
    var discard by remember(reviewKey, valid) { mutableStateOf(false) }
    var fieldsOpen by remember(reviewKey) { mutableStateOf(false) }
    LaunchedEffect(reviewKey, rawView) { fieldsOpen = false }
    val ready = valid && !retired && !busy
    val labels = approvalProjectionLabels()
    val computed by produceState<ProjectedApproval?>(initialValue = null, body, labels, rawView) {
        value = null
        if (body != null) value = withContext(Dispatchers.Default) {
            ProjectedApproval(body, rawView, if (rawView) approvalRawProjection(body) else approvalStructuredProjection(body, labels))
        }
    }
    val projection = computed?.takeIf { it.context === body && it.raw == rawView }?.result
    val parts = projection?.pages.orEmpty()
    val allReviewed = projection?.completelyReviewed(reviewed) == true
    // Navigation only: every root field already covered by the validated projection.
    val fields = projection?.coverage?.filter { it.parent == 0 && it.key != null }.orEmpty()
    val nextUnreviewed = parts.indices.firstOrNull { it !in reviewed }
    val scroll = rememberScrollState()
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    DisposableEffect(lifecycle, reviewKey, valid) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP || event == Lifecycle.Event.ON_DESTROY) {
                reviewed = emptySet(); acknowledged = false; retry = false; discard = false; retired = true
            }
        }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }
    LaunchedEffect(reviewKey, page, rawView) { scroll.scrollTo(0) }
    BoxWithConstraints(Modifier.fillMaxSize()) {
        val actionsHeight = maxHeight * 0.45f
        Scaffold(topBar = {
            cn.edu.ustc.dsh.ui.DshTopBar(
                title = stringResource(R.string.approval_ux_title),
                subtitle = approvalVisibleText(runtime?.hostAlias ?: stringResource(R.string.approval_ux_current_host)),
                navigationIcon = { IconButton(onBack, Modifier.heightIn(min = 48.dp)) {
                    Icon(painterResource(R.drawable.ic_back), stringResource(R.string.approval_ux_back))
                } },
            )
        }, bottomBar = {
            Surface(tonalElevation = 3.dp) {
                Column(
                    Modifier.fillMaxWidth().heightIn(max = actionsHeight).navigationBarsPadding()
                        .verticalScroll(rememberScrollState()).padding(16.dp).testTag("approval-final-actions"),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    if (body != null) Text(stringResource(R.string.approval_ux_progress, reviewed.size, parts.size), style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                    if (original == null) {
                        Button({
                            if (ready && allReviewed && acknowledged && body?.current(System.currentTimeMillis()) == true)
                                handle?.let { onDecide(it, ApprovalChoice.ALLOW_ONCE) }
                        }, enabled = ready && allReviewed && acknowledged, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                            Text(stringResource(R.string.approval_ux_allow))
                        }
                        OutlinedButton({
                            if (ready && body?.current(System.currentTimeMillis()) == true) handle?.let { onDecide(it, ApprovalChoice.REJECT) }
                        }, enabled = ready, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                            Text(stringResource(R.string.approval_ux_reject))
                        }
                    } else {
                        val mayTransfer = original.delivery in setOf(ApprovalDecisionDelivery.PENDING, ApprovalDecisionDelivery.RECONCILE) && original.intent.current(System.currentTimeMillis())
                        OutlinedButton({ retry = true }, enabled = ready && mayTransfer && (original.intent.decision.choice == ApprovalChoice.REJECT || allReviewed && acknowledged),
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.approval_ux_retry)) }
                        OutlinedButton(onQuery, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.approval_ux_query_original)) }
                    }
                }
            }
        }) { insets ->
            Box(Modifier.fillMaxSize().padding(insets), contentAlignment = Alignment.TopCenter) {
                BoxWithConstraints(Modifier.widthIn(max = 800.dp).fillMaxSize()) {
                    val rowPaging = maxWidth - 32.dp >= 400.dp && LocalDensity.current.fontScale <= 1.3f
                    Column(Modifier.fillMaxSize().verticalScroll(scroll).padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text(approvalVisibleText(runtime?.hostAlias ?: stringResource(R.string.approval_ux_current_host)), style = MaterialTheme.typography.titleMedium)
                SelectionContainer {
                    Text(stringResource(R.string.approval_ux_source, runtime?.hostId.orEmpty(), state.selectedRuntimeId.orEmpty(), state.selectedSessionId.orEmpty()), style = MaterialTheme.typography.bodySmall)
                }
                Text(stringResource(R.string.approval_ux_intro))
                if (!authorized) Text(stringResource(R.string.approval_ux_no_authority), color = MaterialTheme.colorScheme.error)
                Text(when (state.approvalStage) {
                    ApprovalUiStage.PREPARING -> stringResource(R.string.approval_ux_preparing)
                    ApprovalUiStage.AUTHENTICATING -> stringResource(R.string.approval_ux_authenticating)
                    ApprovalUiStage.SENDING -> stringResource(R.string.approval_ux_sending)
                    else -> if (retired) stringResource(R.string.approval_ux_retired)
                        else if (current?.context != null) stringResource(R.string.approval_ux_online, (current.remainingMillis + 999) / 1000)
                        else if (original != null) stringResource(R.string.approval_ux_historical) else stringResource(R.string.approval_ux_unavailable)
                }, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                (state.approvalError ?: client?.error ?: client?.view?.error)?.let { code ->
                    Text(approvalErrorText(code), color = MaterialTheme.colorScheme.error)
                    if (code == "approval.assurance_required") OutlinedButton(onReauthenticate, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.approval_ux_reauthenticate)) }
                }
                original?.let {
                    Text(stringResource(R.string.approval_ux_original, stringResource(if (it.intent.decision.choice == ApprovalChoice.ALLOW_ONCE) R.string.approval_ux_allow_choice else R.string.approval_ux_reject_choice)), style = MaterialTheme.typography.titleMedium)
                    Text(approvalRecordLabel(it))
                    SelectionContainer { Text(stringResource(R.string.approval_ux_original_request, it.intent.requestId), style = MaterialTheme.typography.bodySmall) }
                }
                if (body != null && projection == null) {
                    Text(stringResource(R.string.approval_ux_projecting), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                }
                if (body != null && parts.isNotEmpty()) {
                    Text(stringResource(R.string.approval_ux_tool, approvalVisibleText(body.root.string("tool"))), style = MaterialTheme.typography.titleMedium)
                    Text(stringResource(if (rawView) R.string.approval_ux_raw else R.string.approval_ux_structured))
                    OutlinedButton({
                        rawView = !rawView; reviewed = emptySet(); acknowledged = false; retry = false; page = 0
                    }, enabled = !busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                        Text(stringResource(if (rawView) R.string.approval_ux_show_structured else R.string.approval_ux_show_raw))
                    }
                    Text(stringResource(R.string.approval_ux_switch_warning), style = MaterialTheme.typography.bodySmall)
                    Text(stringResource(R.string.approval_ux_page, page + 1, parts.size), style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
                    FlowRow(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        if (!rawView && fields.isNotEmpty()) TextButton({ fieldsOpen = true }, Modifier.heightIn(min = 48.dp)) {
                            Text(stringResource(R.string.approval_ux_field_directory))
                        }
                        TextButton({ if (nextUnreviewed != null) page = nextUnreviewed }, Modifier.heightIn(min = 48.dp),
                            enabled = ready && nextUnreviewed != null) {
                            Text(stringResource(if (nextUnreviewed == null) R.string.approval_ux_all_reviewed else R.string.approval_ux_find_unreviewed))
                        }
                    }
                    Text(stringResource(R.string.approval_ux_escapes), style = MaterialTheme.typography.bodySmall)
                    SelectionContainer {
                        Text(parts[page], fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("approval-reading-page"))
                    }
                    Button({ reviewed = reviewed + page }, enabled = ready, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                        Text(stringResource(if (page in reviewed) R.string.approval_ux_page_reviewed else R.string.approval_ux_acknowledge_page))
                    }
                    // Stack controls: both labels remain readable at 320dp and font scale 2.
                    if (rowPaging) Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton({ page-- }, enabled = page > 0 && !busy, modifier = Modifier.weight(1f).heightIn(min = 48.dp)) { Text(stringResource(R.string.approval_ux_previous)) }
                        OutlinedButton({ page++ }, enabled = page + 1 < parts.size && !busy, modifier = Modifier.weight(1f).heightIn(min = 48.dp)) { Text(stringResource(R.string.approval_ux_next)) }
                    } else {
                        OutlinedButton({ page-- }, enabled = page > 0 && !busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.approval_ux_previous)) }
                        OutlinedButton({ page++ }, enabled = page + 1 < parts.size && !busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.approval_ux_next)) }
                    }
                    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).toggleable(acknowledged, enabled = ready && allReviewed, role = Role.Checkbox) { acknowledged = it },
                        horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(acknowledged, null, enabled = ready && allReviewed)
                        Text(stringResource(R.string.approval_ux_consent), modifier = Modifier.weight(1f).padding(vertical = 8.dp))
                    }
                    if (body.root.array("resources").isEmpty()) Text(stringResource(R.string.approval_ux_empty_resources), style = MaterialTheme.typography.bodySmall)
                }
                original?.let {
                    if (!it.intent.current(System.currentTimeMillis())) Text(stringResource(R.string.approval_ux_original_expired), style = MaterialTheme.typography.bodySmall)
                    if (it.attempts == 0L) TextButton({ discard = true }, enabled = !busy && client?.connected == true, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.approval_ux_discard)) }
                }
                OutlinedButton({
                    reviewed = emptySet(); acknowledged = false; retry = false; retired = true; onDetails(id)
                }, enabled = client?.connected == true && client.contentReady && !busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.approval_ux_details)) }
                TextButton(onRefresh, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.approval_ux_refresh)) }
                OutlinedButton(onBack, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.approval_ux_close)) }
                if (original?.attempts?.let { it > 0 } == true || state.approvalStage == ApprovalUiStage.SENDING) Text(stringResource(R.string.approval_ux_close_warning), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.approval_ux_assurance), style = MaterialTheme.typography.bodySmall)
            }
                }
            }
        }
    }
    if (fieldsOpen) AlertDialog(
        onDismissRequest = { fieldsOpen = false },
        title = { Text(stringResource(R.string.approval_ux_fields_title)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                fields.forEach { field ->
                    val key = field.key ?: return@forEach
                    val label = labels.fields[key]
                    val last = field.pages.last
                    TextButton({ page = field.pages.first; fieldsOpen = false }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                        Column(Modifier.weight(1f), horizontalAlignment = Alignment.Start) {
                            if (label != null) Text(label)
                            Text(key, style = MaterialTheme.typography.bodySmall)
                            Text(stringResource(R.string.approval_ux_field_pages, field.pages.first + 1, last + 1), style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton({ fieldsOpen = false }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.approval_ux_close_field_directory)) } },
    )
    if (retry && ready && handle != null && original != null) AlertDialog(onDismissRequest = { retry = false }, title = { Text(stringResource(R.string.approval_ux_retry_title)) },
        text = { Text(stringResource(R.string.approval_ux_retry_message)) },
        confirmButton = { TextButton({
            retry = false
            if (ready && (original.intent.decision.choice == ApprovalChoice.REJECT || allReviewed && acknowledged)) onSend(handle, original.intent.requestId)
        }) { Text(stringResource(R.string.approval_ux_retry_confirm)) } },
        dismissButton = { TextButton({ retry = false }) { Text(stringResource(R.string.approval_ux_cancel)) } })
    if (discard && original != null) AlertDialog(onDismissRequest = { discard = false }, title = { Text(stringResource(R.string.approval_ux_discard_title)) },
        text = { Text(stringResource(R.string.approval_ux_discard_message)) },
        confirmButton = { TextButton({ discard = false; onDiscard(original.intent.requestId) }) { Text(stringResource(R.string.approval_ux_discard_confirm)) } },
        dismissButton = { TextButton({ discard = false }) { Text(stringResource(R.string.approval_ux_keep)) } })
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
