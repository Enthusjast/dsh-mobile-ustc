package cn.edu.ustc.dsh.mobile

import android.os.Build
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.activity.compose.BackHandler

@Composable
fun HomeRoute(model: HomeViewModel, onSecuritySettings: () -> Unit, onCancel: () -> Unit) {
    val state by model.state.collectAsStateWithLifecycle()
    val bindingState = state.binding
    if (state.phase == HomePhase.READY && state.appUpdateSettings) {
        BackHandler { model.closeAppUpdates() }
        val update = state.appUpdates ?: AppUpdateUiState()
        AppUpdatesScreen(update, { model.checkAppUpdates(update.viewId) },
            { model.downloadAppUpdate(update.viewId, update.release?.document?.sha256()) },
            { model.installAppUpdate(update.viewId, update.attemptId, update.release?.document?.sha256()) },
            { model.requestAppInstallPermission(update.viewId) }, { token -> model.cleanupAppUpdate(update.viewId, token) },
            { model.cancelAppUpdateDownload(update.viewId) }, model::closeAppUpdates)
    } else if (state.phase == HomePhase.READY && state.notificationSettings) {
        BackHandler { model.closeNotificationSettings() }
        val notifications = state.notifications ?: NotificationUiState()
        NotificationsScreen(notifications.copy(note = state.notificationNote ?: notifications.note), model::refreshNotifications, model::enableNotifications, model::disableNotifications, model::renewNotifications,
            { model.notificationInbox(false) }, { model.notificationInbox(true) }, model::openNotification, model::closeNotificationSettings)
    } else if (state.phase == HomePhase.READY && state.reviewingApprovalId != null) {
        BackHandler { model.closeApprovalReview() }
        ApprovalReviewScreen(state, model::closeApprovalReview, model::reviewApproval, model::decideApproval, model::sendOriginalApproval,
            model::queryApprovals, model::discardUnsentApproval, model::refreshApprovals, model::reauthenticateApproval)
    } else if (state.phase == HomePhase.READY && bindingState != null) {
        BackHandler { model.closeBinding() }
        HostBindingScreen(bindingState, state.subject, model::previewBinding, model::queryBinding, model::confirmBinding, model::refreshBinding, model::enterAnotherBinding, model::closeBinding, onCancel)
    } else if(state.phase==HomePhase.READY && state.creation!=null) {
        BackHandler { model.back() }
        SessionCreationScreen(state,model::createSession,model::refreshCreationOptions,model::queryCreation,model::sendPendingCreation,model::openCreatedSession,model::back,onCancel)
    } else if (state.phase == HomePhase.READY && state.selectedRuntimeId != null) {
        BackHandler { model.back() }
        SessionsScreen(state, model::openSession, model::back, model::refreshSessions, model::loadOlder, model::retryRead, onCancel,
            model::submitMessage, model::sendPending, model::queryCommands, model::cancelSession, {state.selectedRuntimeId?.let(model::openCreation)},model::answerQuestion,model::claimQuestion,model::releaseQuestion,model::refreshQuestions,
            model::reviewApproval, model::queryApprovals, model::archiveSession,
            model::pickDocument, model::documentPicked, model::toggleUpload, model::queryUpload, model::removeUpload, model::cancelUpload,
            model::browseExports, model::requestExport, model::queryExports, model::cancelExport, model::removeExport,
            model::chooseExportDestination, model::exportDestinationPicked, model::cancelExportSave)
    } else HomeScreen(state, model::login, model::register, model::refresh, onSecuritySettings, onCancel, model::openRuntime, model::openBinding,model::openCreation,model::openNotificationSettings,model::openAppUpdates)
}

@Composable
fun HomeScreen(state: HomeState, onLogin: () -> Unit, onRegister: (String) -> Unit, onRefresh: () -> Unit, onSecuritySettings: () -> Unit, onCancel: () -> Unit, onRuntime: (String) -> Unit = {}, onBinding: () -> Unit = {}, onCreate: (String)->Unit={}, onNotifications: () -> Unit = {}, onAppUpdates: () -> Unit = {}) {
    var name by rememberSaveable { mutableStateOf("${Build.MANUFACTURER} ${Build.MODEL}".trim()) }
    val displayName = state.deviceName ?: name
    val nameValid = displayName.trim().isNotEmpty() && displayName.trim().toByteArray(Charsets.UTF_8).size <= 160 && displayName.none { it < ' ' || it == '\u007f' }
    Scaffold { insets ->
        Box(Modifier.fillMaxSize().padding(insets).imePadding(), contentAlignment = Alignment.TopCenter) {
            Column(Modifier.widthIn(max = 600.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = 24.dp, vertical = 32.dp), verticalArrangement = Arrangement.spacedBy(24.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    Image(painterResource(R.drawable.ic_dsh), null, Modifier.size(48.dp))
                    Column {
                        Text("DSH 远控", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.semantics { heading() })
                        Text("让电脑上的会话，随你继续", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
                    Column(Modifier.fillMaxWidth().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                        val title = when (state.phase) {
                            HomePhase.UNCONFIGURED, HomePhase.INVALID_CONFIGURATION -> "学校登录尚未配置"
                            HomePhase.ENROLL, HomePhase.PREPARING, HomePhase.AUTHENTICATING, HomePhase.REGISTERING, HomePhase.RECONCILING, HomePhase.REGISTRATION_UNKNOWN -> "登记这部手机"
                            HomePhase.READY -> "本机已登记"
                            else -> "连接学校账号"
                        }
                        Text(title, style = MaterialTheme.typography.titleLarge, modifier = Modifier.semantics { heading() })
                        when (state.phase) {
                            HomePhase.UNCONFIGURED, HomePhase.INVALID_CONFIGURATION -> {
                                Text("请联系管理员获取配置了学校登录的安装包。", style = MaterialTheme.typography.bodyLarge)
                                Button({}, enabled = false, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("等待学校配置") }
                            }
                            HomePhase.SIGNED_OUT -> {
                                Text("使用学校统一身份认证，在浏览器中完成登录。", style = MaterialTheme.typography.bodyLarge)
                                Text(state.issuer, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Button(onLogin, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("使用学校账号登录") }
                            }
                            HomePhase.REAUTHENTICATE -> {
                                Text("重新验证学校账号后，继续使用此设备的原有登记。", style = MaterialTheme.typography.bodyLarge)
                                SelectionContainer { Text(state.subject, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                                Button(onLogin, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("重新登录此账号") }
                            }
                            HomePhase.RECOVERY_ERROR -> {
                                Text(if (state.error == "account.cleanup_failed") "本机登录尚未清理完成，请重试退出。" else "暂时无法恢复本机登录。请解锁设备并检查网络后重试。", style = MaterialTheme.typography.bodyLarge)
                                Button(onLogin, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(if (state.error == "account.cleanup_failed") "重试退出" else "重试恢复") }
                            }
                            HomePhase.ENROLL -> {
                                Text("账号已验证。为这部手机登记独立密钥后，即可查看获授权的电脑。", style = MaterialTheme.typography.bodyLarge)
                                SelectionContainer { Text(state.subject, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                                OutlinedTextField(value = displayName, onValueChange = { name = it }, label = { Text("设备名称") },
                                    supportingText = { Text(if (state.deviceName != null) "继续核对原设备登记" else if (nameValid) "便于在账号中识别这部设备" else "请输入名称，或将名称缩短后重试") },
                                    enabled = state.deviceName == null, isError = !nameValid, singleLine = true, modifier = Modifier.fillMaxWidth())
                                Button({ onRegister(displayName) }, enabled = nameValid, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("确认并登记设备") }
                                if (state.securitySetupRequired) OutlinedButton(onSecuritySettings, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("前往安全设置") }
                            }
                            HomePhase.READY -> {
                                Text("可以查看当前账号获授权的运行实例。", style = MaterialTheme.typography.bodyLarge)
                                Text(state.subject, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                OutlinedButton(onRefresh, enabled = !state.refreshing, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(if (state.refreshing) "正在刷新…" else "刷新运行实例") }
                                OutlinedButton(onNotifications, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("通知与待核对提醒") }
                                OutlinedButton(onAppUpdates, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("应用更新") }
                                Button(onBinding, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(if (state.pendingBindingId == null) "绑定电脑" else "核对待确认的电脑绑定") }
                            }
                            HomePhase.REGISTRATION_UNKNOWN -> {
                                Text("尚未核对设备登记结果。请保持本机登录并检查网络，再查询登记状态。", style = MaterialTheme.typography.bodyLarge)
                                Button({ onRegister(displayName) }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("核对设备登记") }
                            }
                            else -> {
                                Row(Modifier.semantics { liveRegion = LiveRegionMode.Polite }, verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                    CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
                                    Text(when (state.phase) {
                                        HomePhase.LOADING -> "正在准备登录"
                                        HomePhase.RECOVERING -> "正在恢复本机登录"
                                        HomePhase.RENEWING -> "正在更新登录信息"
                                        HomePhase.CLEARING -> "正在清理本机登录"
                                        HomePhase.STARTING -> "正在连接学校认证"
                                        HomePhase.BROWSER -> "等待浏览器完成登录"
                                        HomePhase.EXCHANGING -> "正在验证登录信息"
                                        HomePhase.PREPARING -> "正在准备设备登记"
                                        HomePhase.AUTHENTICATING -> "等待本机身份确认"
                                        HomePhase.REGISTERING -> "正在登记设备"
                                        HomePhase.RECONCILING -> "正在核对设备登记"
                                    }, style = MaterialTheme.typography.bodyLarge)
                                }
                            }
                        }
                        state.error?.let { error ->
                            Text(errorText(error), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                            if (error == "vault.lock_required" && state.phase != HomePhase.ENROLL) {
                                OutlinedButton(onSecuritySettings, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("前往安全设置") }
                            }
                        }
                        if (state.phase !in setOf(HomePhase.LOADING, HomePhase.CLEARING, HomePhase.UNCONFIGURED, HomePhase.INVALID_CONFIGURATION, HomePhase.SIGNED_OUT)) {
                            TextButton(onCancel, Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                                Text(if (state.phase in setOf(HomePhase.READY, HomePhase.REAUTHENTICATE)) "退出本机登录" else if (state.phase == HomePhase.RECOVERY_ERROR) "清除本机登录" else "取消并退出登录")
                            }
                        }
                    }
                }
                if (state.phase == HomePhase.READY) {
                    Text("授权的运行实例", style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
                    if (state.runtimes.isEmpty() && !state.refreshing) Text("还没有可访问的电脑。需要先完成主机绑定和授权。", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    state.runtimes.forEach { runtime ->
                        OutlinedCard(Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text(runtime.hostAlias, style = MaterialTheme.typography.titleMedium)
                                Text("运行环境 ${runtime.id.take(8)}", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                if (runtime.version.isNotEmpty()) Text("DSH ${runtime.version}", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                OutlinedButton({ onRuntime(runtime.id) }, enabled = runtime.access?.organizationId != null && runtime.access.canList(), modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("查看会话") }
                                if(runtime.access?.creationScope()!=null) OutlinedButton({onCreate(runtime.id)},modifier=Modifier.fillMaxWidth().heightIn(min=48.dp)) { Text("创建新会话") }
                            }
                        }
                    }
                }
                Text("DSH Mobile · ${BuildConfig.VERSION_NAME}", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelMedium)
            }
        }
    }
}

private fun errorText(code: String): String = when (code) {
    "login.browser_unavailable" -> "没有找到可用的浏览器，请安装浏览器后重试。"
    "login.invalid_callback" -> "没有接受此登录返回，请继续原来的登录或重新开始。"
    "login.expired", "auth.expired", "login.identity" -> "登录信息已失效或未通过验证，请重新登录。"
    "login.cancelled", "login.authentication_cancelled" -> "本次确认已取消，可以重新操作。"
    "login.reauthentication", "auth.reauthentication_required" -> "需要重新验证学校账号，原设备密钥会保留。"
    "login.account_mismatch" -> "请选择原学校账号，或先退出本机登录后切换账号。"
    "auth.identity_mismatch" -> "账号身份信息已变化，请重新登录并登记。"
    "login.configuration" -> "安装包配置已变化，无法复用原登录。请核对配置或清除本机登录。"
    "vault.lock_required" -> "请先设置安全锁屏，再继续保存本机登录。"
    "vault.locked" -> "请解锁设备后重试恢复。"
    "vault.key_missing", "vault.corrupt", "vault.unavailable", "vault.conflict" -> "本机登录暂时无法读取或保存，请重试恢复。"
    "device.lock_required", "device.biometric_required" -> "请先设置安全锁屏和受支持的生物识别，再继续登记。"
    "device.key_invalidated", "device.key_missing" -> "设备密钥已失效，请退出本机登录后重新登记。"
    "access.denied", "access.revoked", "device.invalid" -> "当前设备没有访问权限，请检查设备登记和授权。"
    "access.organization_missing" -> "当前账号不属于此安装包配置的组织，请联系管理员。"
    "auth.proof_invalid" -> "设备证明未通过验证，请重新确认后重试。"
    "device.registration_not_found" -> "尚未查到本机登记，可以再次确认后登记。"
    "device.registration_unknown" -> "暂时无法核对登记结果，请恢复网络后再次查询。"
    "device.registration_conflict" -> "登记信息与已有设备不一致，请先核对登记状态。"
    else -> "暂时无法完成操作，请检查网络后重试。"
}
