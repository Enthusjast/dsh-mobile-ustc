package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.*
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.auth.HostBindingDetails
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.Contract
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Composable
fun HostBindingScreen(state: HostBindingState, subject: String, onPreview: (String, String) -> Unit, onQuery: (String) -> Unit,
    onConfirm: () -> Unit, onRefresh: () -> Unit, onEnter: () -> Unit, onBack: () -> Unit, onExit: () -> Unit) {
    Scaffold { insets ->
        Box(Modifier.fillMaxSize().padding(insets).imePadding(), contentAlignment = Alignment.TopCenter) {
            Column(Modifier.widthIn(max = 720.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = 24.dp, vertical = 24.dp),
                verticalArrangement = Arrangement.spacedBy(24.dp)) {
                Column(Modifier.fillMaxWidth()) {
                    TextButton(onBack, Modifier.heightIn(min = 48.dp)) { Text("返回电脑列表") }
                    TextButton(onExit, Modifier.heightIn(min = 48.dp)) { Text("退出本机登录") }
                }
                Text("绑定电脑", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.semantics { heading() })
                Text("当前账号：$subject", color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(stringResource(when (state.phase) {
                    HostBindingPhase.ENTER -> R.string.flow_binding_step_input
                    HostBindingPhase.LOADING, HostBindingPhase.REVIEW -> R.string.flow_binding_step_review
                    HostBindingPhase.CONFIRMING, HostBindingPhase.WAITING_HOST -> R.string.flow_binding_step_wait
                    else -> R.string.flow_binding_step_result
                }), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
                if (state.phase == HostBindingPhase.ENTER) key(state.formRevision) {
                    BindingEntry(state.id, state.error, onPreview, onQuery)
                } else {
                    BindingStatus(state)
                    if (state.phase == HostBindingPhase.REVIEW) state.details?.let { BindingFacts(it) }
                    when (state.phase) {
                        HostBindingPhase.REVIEW -> {
                            val details = state.details!!
                            var checked by remember(details.reviewHash) { mutableStateOf(false) }
                            Text("绑定完成后，当前账号将获得此运行环境的拥有者权限。")
                            Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).toggleable(checked, role = Role.Checkbox, onValueChange = { checked = it }),
                                verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                Checkbox(checked, onCheckedChange = null)
                                Text("我已在电脑上核对以上信息和完整指纹", Modifier.weight(1f))
                            }
                            Button(onConfirm, enabled = checked && details.canConfirm(), modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("确认绑定这台电脑") }
                        }
                        HostBindingPhase.UNKNOWN, HostBindingPhase.WAITING_HOST, HostBindingPhase.WAITING_ACCESS, HostBindingPhase.ERROR -> {
                            if (state.id.isNotEmpty()) OutlinedButton(onRefresh, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("查询绑定状态") }
                            TextButton(onEnter, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("重新输入绑定信息") }
                        }
                        HostBindingPhase.UNAVAILABLE -> OutlinedButton(onEnter, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("输入其他绑定申请") }
                        HostBindingPhase.READY -> Button(onBack, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("查看授权的电脑") }
                        else -> Unit
                    }
                    if (state.phase != HostBindingPhase.REVIEW) state.details?.let { BindingFacts(it) }
                }
            }
        }
    }
}

@Composable
private fun BindingEntry(initialId: String, error: String?, onPreview: (String, String) -> Unit, onQuery: (String) -> Unit) {
    // This capability must never be registered with saved-state or process recovery.
    var id by remember { mutableStateOf(initialId) }
    var code by remember { mutableStateOf("") }
    var visible by remember { mutableStateOf(false) }
    var idTouched by remember { mutableStateOf(false) }
    var codeTouched by remember { mutableStateOf(false) }
    val idValid = runCatching { Contract.uuid(id.trim().lowercase()) }.isSuccess
    val codeValid = runCatching { Contract.nonce(code.trim()) }.isSuccess
    Text(stringResource(R.string.flow_binding_input_help))
    OutlinedTextField(id, { if (it.length <= 64) id = it }, singleLine = true, label = { Text("绑定申请编号") },
        supportingText = { Text(if (idTouched && !idValid) "请填写电脑显示的完整申请编号。" else "填写申请编号，不要输入网址。") }, isError = idTouched && !idValid,
        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Ascii),
        modifier = Modifier.fillMaxWidth().onFocusChanged { if (!it.isFocused && id.isNotEmpty()) idTouched = true })
    OutlinedTextField(code, { if (it.length <= 64) code = it }, singleLine = true, label = { Text("电脑显示的绑定码") },
        supportingText = { Text(if (codeTouched && !codeValid) "请复制完整绑定码，保留字母大小写。" else "绑定码仅用于本次申请，请勿转发给他人。") }, isError = codeTouched && !codeValid,
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Password),
        trailingIcon = { TextButton({ visible = !visible }, Modifier.heightIn(min = 48.dp)) { Text(if (visible) "隐藏" else "显示") } },
        modifier = Modifier.fillMaxWidth().onFocusChanged { if (!it.isFocused && code.isNotEmpty()) codeTouched = true })
    error?.let { Text(bindingError(it), color = MaterialTheme.colorScheme.error, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
    Button({ onPreview(id, code) }, enabled = idValid && codeValid, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("核对电脑信息") }
    Text("已在手机确认过的申请，可以只填写申请编号查询结果。", color = MaterialTheme.colorScheme.onSurfaceVariant)
    OutlinedButton({ onQuery(id) }, enabled = idValid, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("仅查询已确认申请") }
}

@Composable
private fun BindingFacts(details: HostBindingDetails) {
    val clipboard = LocalClipboardManager.current
    var copied by remember(details.reviewHash) { mutableStateOf(false) }
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text("请与电脑上的信息逐项核对", style = MaterialTheme.typography.titleMedium)
            BindingFact("组织", details.organizationName)
            BindingFact("电脑名称", details.hostAlias)
            BindingFact("运行环境", details.profile)
            if (details.dshVersion.isNotEmpty()) BindingFact("DSH 版本", details.dshVersion)
            Text("安装密钥指纹", style = MaterialTheme.typography.labelLarge)
            SelectionContainer {
                Text(details.keyThumbprint.chunked(8).joinToString(" "), style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace, textDirection = TextDirection.Ltr))
            }
            OutlinedButton({
                clipboard.setText(AnnotatedString(details.keyThumbprint))
                copied = true
            }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                Text(stringResource(R.string.flow_binding_copy_fingerprint))
            }
            if (copied) Text(stringResource(R.string.flow_binding_fingerprint_copied), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            Text("请核对全部字符，不能只比较电脑名称。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            BindingFact("工作区", if (details.workspaces.isEmpty()) "尚未配置可用工作区" else details.workspaces.joinToString("\n") { it.reference })
            BindingFact("申请编号", details.id)
            val expiry = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault()).format(Instant.ofEpochMilli(details.expiresAt))
            Text("申请有效至 $expiry", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
@Composable private fun BindingFact(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        SelectionContainer { Text(value, style = MaterialTheme.typography.bodyLarge) }
    }
}
@Composable private fun BindingStatus(state: HostBindingState) {
    val busy = state.phase in setOf(HostBindingPhase.LOADING, HostBindingPhase.CONFIRMING, HostBindingPhase.CHECKING)
    val title = when (state.phase) {
        HostBindingPhase.LOADING -> "正在核对电脑信息"
        HostBindingPhase.REVIEW -> "确认本次绑定申请"
        HostBindingPhase.CONFIRMING -> "正在确认绑定"
        HostBindingPhase.CHECKING -> "正在查询绑定结果"
        HostBindingPhase.UNKNOWN -> "绑定结果待核对"
        HostBindingPhase.WAITING_HOST -> "手机已确认，等待电脑确认"
        HostBindingPhase.WAITING_ACCESS -> "双方已确认，当前未查到可用授权"
        HostBindingPhase.READY -> "绑定已完成"
        HostBindingPhase.UNAVAILABLE -> "此绑定申请当前不可用"
        HostBindingPhase.ERROR -> "暂时无法核对绑定"
        HostBindingPhase.PAUSED, HostBindingPhase.CLOSED -> "已暂停核对绑定"
        HostBindingPhase.ENTER -> "输入绑定信息"
    }
    Surface(color = MaterialTheme.colorScheme.surfaceContainerLow, shape = MaterialTheme.shapes.medium) {
        Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                if (busy) CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
                Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            }
            when (state.phase) {
                HostBindingPhase.UNKNOWN -> Text("确认可能已经送达。请查询原申请的状态，避免重复操作。")
                HostBindingPhase.WAITING_HOST -> Text("请回到发起申请的电脑，核对账号并完成独立确认。")
                HostBindingPhase.WAITING_ACCESS -> Text("请刷新状态，或联系管理员核对当前授权。")
                HostBindingPhase.READY -> Text("此运行环境已出现在当前账号的授权目录中。可返回列表查看可用操作。")
                else -> Unit
            }
            if (state.id.isNotEmpty()) BindingFact(stringResource(R.string.flow_binding_public_id), state.id)
            if (state.phase != HostBindingPhase.REVIEW) {
                if (state.details != null) Text(stringResource(R.string.flow_binding_snapshot), style = MaterialTheme.typography.bodySmall)
                BindingFact(stringResource(R.string.flow_binding_phone), stringResource(when (state.details?.confirmedByMe) {
                    true -> R.string.flow_binding_confirmed
                    false -> R.string.flow_binding_unconfirmed
                    null -> R.string.flow_binding_unverified
                }))
                BindingFact(stringResource(R.string.flow_binding_host), stringResource(when (state.details?.hostConfirmed) {
                    true -> R.string.flow_binding_confirmed
                    false -> R.string.flow_binding_unconfirmed
                    null -> R.string.flow_binding_unverified
                }))
                BindingFact(stringResource(R.string.flow_binding_access), stringResource(when (state.phase) {
                    HostBindingPhase.READY -> R.string.flow_binding_access_ready
                    HostBindingPhase.WAITING_ACCESS -> R.string.flow_binding_access_missing
                    else -> R.string.flow_binding_unverified
                }))
            }
            state.error?.let { Text(bindingError(it), color = MaterialTheme.colorScheme.error) }
        }
    }
}
private fun bindingError(code: String) = when (code) {
    "binding.input_invalid" -> "请填写正确的申请编号和完整绑定码。"
    "binding.review_cleared" -> "核对信息已清除，请重新输入电脑显示的绑定码。"
    "binding.code_required" -> "此申请尚未由当前账号确认，请输入绑定码重新核对。"
    "binding.expired" -> "申请已过期，请在电脑上重新发起绑定。"
    "binding.confirmed_elsewhere" -> "此申请已由另一个账号确认，请在电脑上核对发起信息。"
    "binding.organization_mismatch" -> "此申请不属于当前安装包配置的组织。"
    "binding.details_changed", "binding.identity_mismatch" -> "申请信息已变化，请重新核对后确认。"
    "binding.protocol_unsupported" -> "当前版本暂不支持此运行环境，请更新后重试。"
    "binding.unavailable" -> "此申请已被拒绝或取消，请在电脑上核对后重新发起。"
    "access.denied", "access.revoked" -> "无法访问此申请，请核对申请编号、绑定码和账号权限。"
    "protocol.invalid" -> "申请信息无法验证，请核对来源后重试。"
    else -> "暂时无法核对，请检查网络后查询绑定状态。"
}
