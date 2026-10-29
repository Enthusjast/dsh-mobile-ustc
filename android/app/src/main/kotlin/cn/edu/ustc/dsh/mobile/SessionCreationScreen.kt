package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*

@Composable
fun SessionCreationScreen(state: HomeState, onCreate: (String,String,String)->Unit, onRefresh: ()->Unit, onQuery: ()->Unit,
    onSendPending: (String)->Unit, onOpen: (String)->Unit, onBack: ()->Unit, onExit: ()->Unit) {
    val creation=state.creation ?: SessionCreationState()
    val choices=creation.options
    val runtime=state.runtimes.firstOrNull { it.id==state.selectedRuntimeId }
    var workspace by remember(state.selectedRuntimeId, choices?.epoch) { mutableStateOf<String?>(null) }
    var preset by remember(state.selectedRuntimeId, choices?.epoch) { mutableStateOf<String?>(null) }
    var chooseWorkspace by remember(state.selectedRuntimeId, choices?.epoch) { mutableStateOf(false) }
    var choosePreset by remember(state.selectedRuntimeId, choices?.epoch) { mutableStateOf(false) }
    var workspaceSearch by remember(chooseWorkspace) { mutableStateOf("") }
    var presetSearch by remember(choosePreset) { mutableStateOf("") }
    var another by remember(workspace,preset,choices?.epoch) { mutableStateOf(false) }
    val selected=choices?.workspaces?.firstOrNull { it.id==workspace }
    val valid=creation.phase==SessionCreationPhase.READY && creation.outbox.connected && selected!=null && preset in choices.presets && !state.submitting
    val unresolved=creation.outbox.records.any { it.intent.workspaceId==workspace && it.remote !in setOf(RemoteCommandState.SETTLED,RemoteCommandState.REJECTED) }
    val submit={ val id=workspace; val configuration=preset; val epoch=choices?.epoch; if(valid && id!=null && configuration!=null && epoch!=null) onCreate(id,configuration,epoch) }
    Scaffold { insets ->
        LazyColumn(Modifier.fillMaxSize().padding(insets).imePadding(),contentPadding=PaddingValues(24.dp),verticalArrangement=Arrangement.spacedBy(16.dp)) {
            item("header") {
                Column(Modifier.fillMaxWidth()) {
                    TextButton(onBack,Modifier.heightIn(min=48.dp)) { Text("返回") }
                    TextButton(onExit,Modifier.heightIn(min=48.dp)) { Text("退出本机登录") }
                }
                Text("创建会话",style=MaterialTheme.typography.headlineSmall,modifier=Modifier.semantics { heading() })
                Text(stringResource(R.string.flow_creation_context), style=MaterialTheme.typography.titleSmall)
                Text(runtime?.hostAlias ?: "已授权的电脑",style=MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.flow_creation_intro))
            }
            item("connection") {
                Text(when(creation.phase) {
                    SessionCreationPhase.CONNECTING->"正在连接电脑"
                    SessionCreationPhase.OPTIONS->"正在读取创建选项"
                    SessionCreationPhase.READY->"创建选项已就绪"
                    SessionCreationPhase.OFFLINE->"电脑暂时无法提供创建选项"
                    SessionCreationPhase.BACKOFF->"连接中断，正在重连"
                    SessionCreationPhase.AUTH_REQUIRED->"需要更新登录"
                    SessionCreationPhase.REVOKED->"当前创建权限已失效"
                    SessionCreationPhase.ERROR->"暂时无法创建会话"
                    SessionCreationPhase.CLOSED->"已暂停创建"
                },modifier=Modifier.semantics { liveRegion=LiveRegionMode.Polite })
                if (creation.phase != SessionCreationPhase.READY) Text(stringResource(when (creation.phase) {
                    SessionCreationPhase.OFFLINE, SessionCreationPhase.BACKOFF -> R.string.flow_creation_offline
                    SessionCreationPhase.AUTH_REQUIRED, SessionCreationPhase.REVOKED -> R.string.flow_creation_access_required
                    else -> R.string.flow_creation_options_pending
                }), style=MaterialTheme.typography.bodyMedium)
                if (creation.phase in setOf(SessionCreationPhase.CONNECTING, SessionCreationPhase.OPTIONS, SessionCreationPhase.BACKOFF)) LinearProgressIndicator(Modifier.fillMaxWidth())
                OutlinedButton(onRefresh,enabled=creation.phase !in setOf(SessionCreationPhase.CONNECTING,SessionCreationPhase.OPTIONS,SessionCreationPhase.AUTH_REQUIRED,SessionCreationPhase.REVOKED),modifier=Modifier.fillMaxWidth().heightIn(min=48.dp)) { Text("刷新创建选项") }
            }
            if(choices!=null) item("choices") {
                Column(verticalArrangement=Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(R.string.flow_creation_workspace), style=MaterialTheme.typography.titleMedium, modifier=Modifier.semantics { heading() })
                    Text(stringResource(R.string.flow_creation_workspace_help), style=MaterialTheme.typography.bodySmall)
                    Box {
                        OutlinedButton({chooseWorkspace=true},enabled=creation.phase==SessionCreationPhase.READY && choices.workspaces.isNotEmpty(),modifier=Modifier.fillMaxWidth().heightIn(min=48.dp)) { Text(selected?.let { "${it.label} · ${it.id.take(8)}" } ?: "选择工作区") }
                        DropdownMenu(chooseWorkspace,{chooseWorkspace=false},modifier=Modifier.heightIn(max=360.dp)) {
                            if (choices.workspaces.size > 8) OutlinedTextField(workspaceSearch, {workspaceSearch=it}, label={Text(stringResource(R.string.flow_creation_search_workspace))}, modifier=Modifier.fillMaxWidth().padding(8.dp))
                            val filtered=remember(choices, workspaceSearch) {
                                if (workspaceSearch.isBlank()) choices.workspaces else choices.workspaces.filter { it.label.contains(workspaceSearch,true) || it.id.contains(workspaceSearch,true) }
                            }
                            if (filtered.isEmpty()) Text(stringResource(R.string.flow_creation_search_empty), Modifier.padding(16.dp))
                            filtered.forEach { option -> DropdownMenuItem(text={Text("${option.label} · ${option.id.take(8)}")},onClick={workspace=option.id;chooseWorkspace=false}) }
                        }
                    }
                    Text(stringResource(R.string.flow_creation_preset), style=MaterialTheme.typography.titleMedium, modifier=Modifier.semantics { heading() })
                    Text(stringResource(R.string.flow_creation_preset_help), style=MaterialTheme.typography.bodySmall)
                    Box {
                        OutlinedButton({choosePreset=true},enabled=creation.phase==SessionCreationPhase.READY && choices.presets.isNotEmpty(),modifier=Modifier.fillMaxWidth().heightIn(min=48.dp)) { Text(preset?.takeIf { it in choices.presets } ?: "选择助手配置") }
                        DropdownMenu(choosePreset,{choosePreset=false},modifier=Modifier.heightIn(max=360.dp)) {
                            if (choices.presets.size > 8) OutlinedTextField(presetSearch, {presetSearch=it}, label={Text(stringResource(R.string.flow_creation_search_preset))}, modifier=Modifier.fillMaxWidth().padding(8.dp))
                            val filtered=remember(choices, presetSearch) {
                                if (presetSearch.isBlank()) choices.presets else choices.presets.filter { it.contains(presetSearch,true) }
                            }
                            if (filtered.isEmpty()) Text(stringResource(R.string.flow_creation_search_empty), Modifier.padding(16.dp))
                            filtered.forEach { option -> DropdownMenuItem(text={Text(option)},onClick={preset=option;choosePreset=false}) }
                        }
                    }
                    if(choices.workspaces.isEmpty()) Text(stringResource(R.string.flow_creation_no_workspace))
                    if(choices.presets.isEmpty()) Text(stringResource(R.string.flow_creation_no_preset))
                    if(choices.workspaces.isNotEmpty() && choices.presets.isNotEmpty()) {
                        Text(stringResource(if ((workspace!=null && selected==null) || (preset!=null && preset !in choices.presets)) R.string.flow_creation_selection_stale else R.string.flow_creation_selection_required), style=MaterialTheme.typography.bodySmall)
                        Button({ if(unresolved) another=true else submit() },enabled=valid,modifier=Modifier.fillMaxWidth().heightIn(min=48.dp)) { Text(if(state.submitting) "正在保存创建请求…" else "创建新会话") }
                    }
                    if(another) AlertDialog(onDismissRequest={another=false},title={Text("创建另一个会话？")},
                        text={Text("此工作区还有结果未完成核对的创建请求。新操作会使用新的请求编号，原请求可能已在电脑上创建了会话。")},
                        confirmButton={TextButton({another=false;submit()},enabled=valid,modifier=Modifier.heightIn(min=48.dp)) {Text("确认为另一个新请求")}},
                        dismissButton={TextButton({another=false;onQuery()},modifier=Modifier.heightIn(min=48.dp)) {Text("先核对原请求")}})
                }
            }
            val error=state.commandError ?: creation.error ?: creation.outbox.error
            if(error!=null) item("error") { Text(creationError(error),color=MaterialTheme.colorScheme.error) }
            if(creation.outbox.records.isNotEmpty()) item("records") {
                Text("本机创建记录",style=MaterialTheme.typography.titleMedium,modifier=Modifier.semantics { heading() })
                Text("结果不明时先核对原请求；连接恢复后不会自动重复创建。",style=MaterialTheme.typography.bodySmall)
                OutlinedButton(onQuery,Modifier.fillMaxWidth().heightIn(min=48.dp)) { Text("核对创建结果") }
            }
            items(creation.outbox.records,key={it.intent.requestId}) { record ->
                OutlinedCard(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(12.dp)) {
                        Text(when {
                            record.remote==RemoteCommandState.SETTLED && record.createdSessionId!=null->"会话已创建"
                            record.remote==RemoteCommandState.REJECTED->"电脑拒绝了此创建请求"
                            record.delivery==CommandDelivery.PENDING->"手机待转交"
                            record.remote==RemoteCommandState.HOST_ACCEPTED->"电脑已保存创建请求"
                            record.remote==RemoteCommandState.DISPATCHING->"电脑正在创建会话"
                            record.remote==RemoteCommandState.RECEIVED->"中继已接收，尚未确认电脑创建"
                            else->"创建结果待确认"
                        },style=MaterialTheme.typography.titleSmall)
                        Text(stringResource(R.string.flow_creation_record_workspace, record.intent.workspaceId.orEmpty()))
                        Text(stringResource(R.string.flow_creation_record_preset, record.intent.payload.string("preset")))
                        Text(stringResource(R.string.flow_creation_original_request, record.intent.requestId),style=MaterialTheme.typography.bodySmall)
                        if(record.remote==RemoteCommandState.OUTCOME_UNKNOWN) Text(stringResource(R.string.flow_creation_unknown_result))
                        val eligible=creation.outbox.connected && choices!=null && choices.epoch==record.intent.epoch && choices.workspaces.any { it.id==record.intent.workspaceId } && record.intent.payload.string("preset") in choices.presets
                        if(record.delivery==CommandDelivery.PENDING && record.attempts==0L) OutlinedButton({onSendPending(record.intent.requestId)},enabled=eligible,modifier=Modifier.fillMaxWidth().heightIn(min=48.dp)) {Text("转交这个创建请求")}
                        if(record.remote==RemoteCommandState.RECEIVED && !record.everHostSaved) {
                            var retry by remember { mutableStateOf(false) }
                            OutlinedButton({retry=true},enabled=eligible,modifier=Modifier.fillMaxWidth().heightIn(min=48.dp)) {Text("重新转交同一请求")}
                            if(retry) AlertDialog(onDismissRequest={retry=false},title={Text("重新转交原创建请求？")},text={Text("会先核对原请求状态，保留原编号、工作区和运行代次。已创建或结果不明的请求不会重复转交。")},
                                confirmButton={TextButton({retry=false;onSendPending(record.intent.requestId)},modifier=Modifier.heightIn(min=48.dp)) {Text("核对并重试")}},dismissButton={TextButton({retry=false},modifier=Modifier.heightIn(min=48.dp)) {Text("取消")}})
                        }
                        if(record.remote==RemoteCommandState.SETTLED && record.createdSessionId!=null) {
                            val readable=runtime?.access?.let { val granted=it.scope; it.canList() && granted!=null && "session.read" in granted.actions && record.intent.workspaceId in granted.workspaces }==true
                            OutlinedButton({onOpen(record.intent.requestId)},enabled=readable,modifier=Modifier.fillMaxWidth().heightIn(min=48.dp)) {Text("读取已创建的会话")}
                            if(!readable) Text("当前授权无法读取这个会话。",style=MaterialTheme.typography.bodySmall)
                        }
                        if(choices!=null && record.intent.epoch!=choices.epoch && record.remote !in setOf(RemoteCommandState.SETTLED,RemoteCommandState.REJECTED)) Text("电脑运行环境已更新，原请求不会用于新的运行代次。",style=MaterialTheme.typography.bodySmall)
                        record.error?.let { Text(creationError(it),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.error) }
                    }
                }
            }
        }
    }
}
private fun creationError(code: String)=when(code) {
    "protocol.unsupported"->"电脑尚不支持当前创建流程，请在电脑核对插件与配置。"
    "runtime.changed"->"电脑运行环境或创建选项已更新，请先核对原请求并刷新选项。"
    "data.locked","data.lock_required"->"请解锁设备并设置安全锁屏后再使用本机创建记录。"
    "data.key_missing","data.corrupt","data.unavailable","data.outbox_limit"->"本机创建记录暂不可用，已停止提交新的创建请求。"
    "access.denied","access.revoked"->"当前授权不允许此创建操作。"
    else->"暂时无法核对创建结果，请查询原请求状态后再继续。"
}
