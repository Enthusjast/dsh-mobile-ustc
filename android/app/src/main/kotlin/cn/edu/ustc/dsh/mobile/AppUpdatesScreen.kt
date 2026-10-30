package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp
import java.util.Locale

@Composable
internal fun AppUpdatesScreen(state: AppUpdateUiState, check: () -> Unit, download: () -> Unit, install: () -> Unit,
    permission: () -> Unit, cleanup: (String) -> Unit, cancelDownload: () -> Unit, back: () -> Unit) {
    var confirmCleanup by remember(state.viewId) { mutableStateOf<String?>(null) }
    LaunchedEffect(state.cleanupToken, state.canCleanup) { if (!state.canCleanup || confirmCleanup != state.cleanupToken) confirmCleanup = null }
    val enabled = !state.busy && !state.launchPending
    Scaffold(topBar = {
        cn.edu.ustc.dsh.ui.DshTopBar(
            title = stringResource(R.string.settings_updates),
            subtitle = if (state.installedVersion == null) stringResource(R.string.flow_update_version_unknown, BuildConfig.VERSION_NAME) else stringResource(R.string.flow_update_current_version, BuildConfig.VERSION_NAME, state.installedVersion.toString()),
            contentMaxWidth = 720.dp,
            navigationIcon = { IconButton(back, Modifier.heightIn(min = 48.dp)) {
                Icon(painterResource(R.drawable.ic_back), stringResource(R.string.flow_update_back))
            } },
        )
    }) { insets ->
        Box(Modifier.fillMaxSize().padding(insets), contentAlignment = Alignment.TopCenter) {
            LazyColumn(Modifier.widthIn(max = 720.dp).fillMaxWidth(), contentPadding = PaddingValues(cn.edu.ustc.dsh.ui.DshSpacing.page), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                item("stage") {
                    Text(stringResource(when (state.phase) {
                        AppUpdatePhase.AVAILABLE, AppUpdatePhase.DOWNLOADING, AppUpdatePhase.VERIFYING, AppUpdatePhase.REPREPARE -> R.string.flow_update_step_prepare
                        AppUpdatePhase.PREPARED, AppUpdatePhase.WAITING_USER -> R.string.flow_update_step_install
                        AppUpdatePhase.UNKNOWN, AppUpdatePhase.INSTALLED, AppUpdatePhase.FAILED, AppUpdatePhase.BLOCKED -> R.string.flow_update_step_reconcile
                        else -> R.string.flow_update_step_check
                    }), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
                }
                item("status") {
                    OutlinedCard(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                            Text(updatePhaseTitle(state.phase), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                            Text(updatePhaseDescription(state.phase), style = MaterialTheme.typography.bodyMedium)
                            if (state.currentSupported == false) Text("当前版本已超出服务公布的支持范围。请安装适用更新，或联系管理员。", color = MaterialTheme.colorScheme.error)
                            if (state.phase in setOf(AppUpdatePhase.DOWNLOADING, AppUpdatePhase.VERIFYING, AppUpdatePhase.PREPARED, AppUpdatePhase.WAITING_USER, AppUpdatePhase.UNKNOWN)) Text(stringResource(R.string.flow_update_not_installed), style = MaterialTheme.typography.bodySmall)
                            if (state.phase == AppUpdatePhase.DOWNLOADING && state.release != null) {
                                val total = state.release.sizeBytes
                                LinearProgressIndicator(progress = { (state.downloadedBytes.toFloat() / total).coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
                                Text("已下载 ${updateSize(state.downloadedBytes)} / ${updateSize(total)}", style = MaterialTheme.typography.bodySmall)
                            } else if (state.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                            when (state.phase) {
                                AppUpdatePhase.AVAILABLE -> Button(if (state.canInstall) download else permission, enabled = enabled, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                                    Text(if (state.canInstall) "下载并校验" else "允许本应用安装")
                                }
                                AppUpdatePhase.PREPARED, AppUpdatePhase.WAITING_USER -> Button(if (state.canInstall) install else permission, enabled = enabled, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                                    Text(if (!state.canInstall) "允许本应用安装" else if (state.phase == AppUpdatePhase.PREPARED) "打开系统安装确认" else "继续系统安装")
                                }
                                AppUpdatePhase.IDLE, AppUpdatePhase.CURRENT, AppUpdatePhase.INSTALLED, AppUpdatePhase.FAILED, AppUpdatePhase.ERROR, AppUpdatePhase.REPREPARE, AppUpdatePhase.UNKNOWN -> Button(check, enabled = enabled, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                                    Text(if (state.phase == AppUpdatePhase.UNKNOWN) "核对安装结果" else if (state.phase in setOf(AppUpdatePhase.ERROR, AppUpdatePhase.FAILED, AppUpdatePhase.REPREPARE)) "重新检查更新" else "检查适用更新")
                                }
                                else -> Unit
                            }
                            if (state.phase in setOf(AppUpdatePhase.DOWNLOADING, AppUpdatePhase.VERIFYING)) OutlinedButton(cancelDownload, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("取消本次下载") }
                            if (state.phase in setOf(AppUpdatePhase.AVAILABLE, AppUpdatePhase.PREPARED, AppUpdatePhase.WAITING_USER)) TextButton(check, enabled = enabled, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                                Text(if (state.phase == AppUpdatePhase.AVAILABLE) "重新检查更新" else "核对安装结果")
                            }
                            if (state.canCleanup && state.cleanupToken != null) TextButton({ confirmCleanup = state.cleanupToken }, enabled = enabled, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("放弃待处理更新") }
                            state.error?.let { Text(appUpdateErrorText(it), color = MaterialTheme.colorScheme.error, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
                        }
                    }
                }
                state.release?.let { release -> item("release") {
                    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
                        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("${release.versionName}（${release.versionCode}）", style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
                            Text("下载大小 ${updateSize(release.sizeBytes)}", color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text("更新说明", style = MaterialTheme.typography.labelLarge)
                            SelectionContainer { Text(release.releaseNotes.ifBlank { stringResource(R.string.flow_update_no_notes) }) }
                        }
                    }
                } }
            }
        }
    }
    val confirmedContext = confirmCleanup
    if (confirmedContext != null && confirmedContext == state.cleanupToken && state.canCleanup) AlertDialog(onDismissRequest = { confirmCleanup = null }, title = { Text("放弃待处理更新？") },
        text = { Text("将放弃当前更新并清除本机更新记录。系统已开始的安装仍可能完成，返回后请重新核对当前版本。") },
        confirmButton = { TextButton({ confirmCleanup = null; cleanup(confirmedContext) }, enabled = enabled, modifier = Modifier.heightIn(min = 48.dp)) { Text("确认放弃") } },
        dismissButton = { TextButton({ confirmCleanup = null }, Modifier.heightIn(min = 48.dp)) { Text("保留更新") } })
}

private fun updateSize(bytes: Long) = String.format(Locale.ROOT, "%.1f MB", bytes / (1024.0 * 1024.0))
private fun updatePhaseTitle(phase: AppUpdatePhase) = when (phase) {
    AppUpdatePhase.LOADING -> "正在核对本机更新"
    AppUpdatePhase.UNCONFIGURED -> "此安装包尚未配置更新来源"
    AppUpdatePhase.IDLE -> "检查应用更新"
    AppUpdatePhase.CHECKING -> "正在检查适用更新"
    AppUpdatePhase.CURRENT -> "暂无适用更新"
    AppUpdatePhase.AVAILABLE -> "有适用于本机的更新"
    AppUpdatePhase.DOWNLOADING -> "正在下载更新"
    AppUpdatePhase.VERIFYING -> "正在校验安装包"
    AppUpdatePhase.PREPARED -> "安装包已校验"
    AppUpdatePhase.REPREPARE -> "需要重新准备更新"
    AppUpdatePhase.WAITING_USER -> "等待系统安装确认"
    AppUpdatePhase.UNKNOWN -> "安装结果尚未核对"
    AppUpdatePhase.INSTALLED -> "已核对当前安装版本"
    AppUpdatePhase.FAILED -> "上次安装未完成"
    AppUpdatePhase.BLOCKED -> "本机有待处理的更新记录"
    AppUpdatePhase.ERROR -> "更新暂未完成"
}
private fun updatePhaseDescription(phase: AppUpdatePhase) = when (phase) {
    AppUpdatePhase.UNCONFIGURED -> "请联系管理员获取包含更新配置的安装包。"
    AppUpdatePhase.AVAILABLE -> "下载并校验后，还需要在系统页面确认安装。"
    AppUpdatePhase.PREPARED, AppUpdatePhase.WAITING_USER -> "点击继续后，将重新核对发行状态并打开系统安装页面。"
    AppUpdatePhase.REPREPARE -> "临时下载已结束，请重新检查并下载。"
    AppUpdatePhase.UNKNOWN -> "先核对当前安装版本，再决定是否放弃待处理更新。"
    AppUpdatePhase.INSTALLED -> "当前安装包与目标更新的版本、签名和完整内容一致。"
    AppUpdatePhase.BLOCKED -> "请核对当前账号。需要重新开始时，可放弃本机待处理更新。"
    AppUpdatePhase.DOWNLOADING, AppUpdatePhase.VERIFYING -> "离开此页面后，需要重新下载并校验。"
    AppUpdatePhase.FAILED -> "可以重新检查适用于本机的更新。"
    AppUpdatePhase.ERROR -> "请查看原因，核对后再继续。"
    else -> "使用当前账号检查适用于本机的更新。"
}
internal fun appUpdateErrorText(code: String) = when (code) {
    "update.configuration", "update.not_configured" -> "安装包中的更新配置未就绪，请联系管理员。"
    "update.publication_changed" -> "发行已变更或不再适用，请重新检查更新。"
    "update.install_permission_required" -> "系统尚未允许本应用安装更新，请前往设置后返回。"
    "update.installed_changed" -> "当前安装版本已变化，请重新检查。"
    "update.installation_changed" -> "待处理更新已变化，请重新核对后操作。"
    "update.prepare_again", "update.state_changed" -> "临时更新已结束，请重新下载并校验。"
    "update.apk_invalid", "update.integrity_mismatch", "update.identity_mismatch", "update.incompatible" -> "安装包未通过内容、签名或兼容性校验，请重新检查发行。"
    "update.other_context" -> "待处理记录属于另一账号或部署，请先放弃旧更新。"
    "update.storage_unavailable", "update.installation_unknown", "update.pending_installation" -> "无法确认待处理更新，请核对安装结果，必要时放弃后重新开始。"
    "update.system_ui_unavailable" -> "暂时无法打开系统页面，请再次操作，或联系管理员。"
    "auth.expired", "auth.proof_invalid", "auth.reauthentication_required", "access.denied", "access.revoked", "device.invalid" -> "当前账号或设备需要重新验证，请返回核对登录。"
    else -> "暂时无法完成更新，请检查连接后重新核对。"
}
