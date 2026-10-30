package cn.edu.ustc.dsh.mobile

import android.Manifest
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Alignment
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.protocol.NotificationReference
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Composable
internal fun NotificationsScreen(state: NotificationUiState, refresh: () -> Unit, enable: () -> Unit, disable: () -> Unit, renew: () -> Unit,
    inbox: () -> Unit, more: () -> Unit, open: (String, String?) -> Unit, back: () -> Unit) {
    val context = LocalContext.current
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { refresh() }
    Scaffold(topBar = {
        cn.edu.ustc.dsh.ui.DshTopBar(
            title = stringResource(R.string.settings_notifications),
            contentMaxWidth = 720.dp,
            navigationIcon = { IconButton(back, Modifier.heightIn(min = 48.dp)) {
                Icon(painterResource(R.drawable.ic_back), stringResource(R.string.flow_notifications_back))
            } },
        )
    }) { insets ->
    Box(Modifier.fillMaxSize().padding(insets), contentAlignment = Alignment.TopCenter) {
    LazyColumn(Modifier.widthIn(max = 720.dp).fillMaxWidth().padding(horizontal = cn.edu.ustc.dsh.ui.DshSpacing.page), contentPadding = PaddingValues(vertical = cn.edu.ustc.dsh.ui.DshSpacing.page), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        item("heading") {
            Text("默认隐藏正文、参数和主机别名。打开提醒后重新核对当前状态。")
            Text(stringResource(R.string.flow_notifications_foreground), color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        item("channel") {
            OutlinedCard(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.flow_notifications_permission, stringResource(if (state.allowed) R.string.flow_notifications_allowed else R.string.flow_notifications_not_allowed)), style = MaterialTheme.typography.titleSmall)
                Text(stringResource(R.string.flow_notifications_registration), style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
                Text(when (state.phase) {
                    NotificationPhase.LOADING -> "正在核对通知通道"
                    NotificationPhase.UNCONFIGURED -> "此安装包尚未配置推送通道"
                    NotificationPhase.UNAVAILABLE -> "当前设备暂不支持已配置通道"
                    NotificationPhase.DISABLED -> "此账号尚未启用通知"
                    NotificationPhase.WAITING -> "正在核对通知通道归属"
                    NotificationPhase.ACTIVE -> "此账号的通知通道已登记"
                    NotificationPhase.ERROR -> "通知通道需要重新核对"
                }, style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                Text("送达和显示受设备、系统与网络限制。通道登记不代表每条提醒已被看到。", style = MaterialTheme.typography.bodySmall)
                state.expiresAt?.let { expires ->
                    val expiry = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault()).format(Instant.ofEpochMilli(expires))
                    Text(stringResource(R.string.flow_notifications_expiry, expiry), style = MaterialTheme.typography.bodySmall)
                }
                if (!state.allowed) OutlinedButton({
                    if (Build.VERSION.SDK_INT >= 33) permission.launch(Manifest.permission.POST_NOTIFICATIONS)
                    else context.startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName))
                }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("允许系统通知") }
                if (!state.allowed && Build.VERSION.SDK_INT >= 33) TextButton({
                    context.startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName))
                }, Modifier.heightIn(min = 48.dp)) { Text("打开系统通知设置") }
                OutlinedButton(refresh, enabled = !state.busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("核对通道状态") }
                if (state.phase != NotificationPhase.ACTIVE && state.canEnable) Button(enable, enabled = !state.busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(if (state.phase == NotificationPhase.WAITING) "继续登记原通道" else "启用此账号通知") }
                if (state.phase == NotificationPhase.ACTIVE) OutlinedButton(renew, enabled = !state.busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("续期此通知通道") }
                if (state.phase in setOf(NotificationPhase.WAITING, NotificationPhase.ACTIVE, NotificationPhase.ERROR)) TextButton(disable, Modifier.heightIn(min = 48.dp)) { Text("停用此账号通知") }
                state.error?.let { Text(notificationErrorText(it), color = MaterialTheme.colorScheme.error) }
                if (state.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            } }
        }
        if (state.phase == NotificationPhase.ACTIVE) item("inbox") {
            OutlinedButton(inbox, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("核对待处理提醒") }
            Text("这里是提醒引用；完整交互以在线会话为准。", style = MaterialTheme.typography.bodySmall)
        }
        item("reference-scope") {
            Text(stringResource(R.string.flow_notifications_references), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
            Text(stringResource(if (state.items.isEmpty()) R.string.flow_notifications_no_references else R.string.flow_notifications_reference_scope), style = MaterialTheme.typography.bodyMedium)
        }
        state.note?.let { note -> item("note") { Text(note) } }
        items(state.items, key = { it.id }) { reference ->
            OutlinedCard(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(notificationReferenceText(reference))
                OutlinedButton({ open(reference.bindingId, reference.id) }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("在线重新核对") }
            } }
        }
        if (state.cursor != null) item("more") { OutlinedButton(more, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("更多提醒") } }
    }
    }
    }
}
internal fun notificationErrorText(code: String) = when (code) {
    "push.not_configured" -> "此安装包未包含已核验的推送配置。"
    "push.services_unavailable" -> "此设备的 FCM 服务不可用，需要匹配的设备推送通道。"
    "push.permission_required" -> "系统通知权限或通知通道已关闭。"
    "push.conflict" -> "通道与原登记冲突，请先停用旧通道再重新核对。"
    "push.expired" -> "登记或提醒已过期，请重新核对。"
    "push.cleanup_failed", "push.cleanup_required" -> "旧通道注销待联网重试，本机已经停止接收旧账号提醒。"
    "push.storage_unavailable" -> "本机通知记录无法读取。请核对设备登记状态，必要时联系管理员清理旧通道。"
    "push.stale", "access.denied", "auth.identity_mismatch" -> "当前账号或设备无法核对此提醒。"
    else -> "暂时无法核对通知，请检查连接后重试。"
}
