package cn.edu.ustc.dsh.mobile

import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.network.SessionDirectoryEntry
import cn.edu.ustc.dsh.ui.DshSpacing
import cn.edu.ustc.dsh.ui.DshStatusNotice
import cn.edu.ustc.dsh.ui.DshTopBar
import java.text.DateFormat
import java.util.Date

internal enum class HomeDestination(@get:StringRes val label: Int, @get:DrawableRes val icon: Int) {
    SESSIONS(R.string.nav_sessions, R.drawable.ic_sessions),
    COMPUTERS(R.string.nav_computers, R.drawable.ic_computers),
    SETTINGS(R.string.nav_settings, R.drawable.ic_settings),
}

/** Presentation state only. No credentials, drafts, approval handles or restored authority. */
@Stable
internal class HomeNavigation {
    var destination by mutableStateOf(HomeDestination.SESSIONS)
    var directoryRuntimeId by mutableStateOf<String?>(null)
    var directoryFromComputer by mutableStateOf(false)
    var directoryPosition = LazyListState()
        private set

    fun selectRuntime(id: String) {
        if (directoryRuntimeId != id) directoryPosition = LazyListState()
        directoryRuntimeId = id
    }
}

private fun runtimeLabel(id: String, runtimes: List<RuntimeRow>): String {
    val collides = runtimes.any { it.id != id && it.id.regionMatches(0, id, 0, 8) && it.id.regionMatches(32, id, 32, 4) }
    return if (collides) id else "${id.take(8)}…${id.takeLast(4)}"
}

@Composable
internal fun DshAppShell(
    state: HomeState,
    navigation: HomeNavigation,
    onDestination: (HomeDestination) -> Unit,
    onRuntime: (String) -> Unit,
    onSession: (String) -> Unit,
    onRefresh: () -> Unit,
    onRefreshSessions: () -> Unit,
    onCreate: (String) -> Unit,
    onBinding: () -> Unit,
    onNotifications: () -> Unit,
    onAppUpdates: () -> Unit,
    onExit: () -> Unit,
    onBackToComputers: () -> Unit,
) {
    val destination = navigation.destination
    val runtime = state.runtimes.firstOrNull { it.id == state.selectedRuntimeId && it.id == navigation.directoryRuntimeId }
        ?.takeIf { it.access?.organizationId != null && it.access.canList() }
    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal),
        topBar = {
            DshTopBar(
                title = stringResource(destination.label),
                navigationIcon = {
                    if (destination == HomeDestination.SESSIONS && navigation.directoryFromComputer) {
                        IconButton(onBackToComputers) { ShellIcon(R.drawable.ic_back, R.string.action_back_computers) }
                    }
                },
                actions = {
                    if (destination != HomeDestination.SETTINGS) {
                        IconButton(
                            onClick = if (destination == HomeDestination.SESSIONS && runtime != null) onRefreshSessions else onRefresh,
                            enabled = !state.refreshing && !state.loadingSessions,
                        ) { ShellIcon(R.drawable.ic_refresh, R.string.action_refresh) }
                    }
                    if (destination == HomeDestination.SESSIONS && runtime?.access?.creationScope() != null) {
                        IconButton({ if (runtime.access.creationScope() != null) onCreate(runtime.id) }) { ShellIcon(R.drawable.ic_add, R.string.action_create_session) }
                    }
                },
            )
        },
        bottomBar = {
            NavigationBar {
                HomeDestination.entries.forEach { item ->
                    NavigationBarItem(
                        selected = destination == item,
                        onClick = { onDestination(item) },
                        icon = { ShellIcon(item.icon) },
                        label = { Text(stringResource(item.label)) },
                    )
                }
            }
        },
    ) { insets ->
        Box(Modifier.fillMaxSize().padding(insets), contentAlignment = Alignment.TopCenter) {
            when (destination) {
                HomeDestination.SESSIONS -> SessionDirectoryScreen(state, navigation, onRuntime, onSession, onBinding)
                HomeDestination.COMPUTERS -> ComputersScreen(state, onRuntime, onCreate, onBinding)
                HomeDestination.SETTINGS -> SettingsScreen(state, onNotifications, onAppUpdates, onExit)
            }
        }
    }
}

@Composable
private fun ShellIcon(@DrawableRes icon: Int, @StringRes description: Int? = null) {
    Icon(painterResource(icon), description?.let { stringResource(it) }, Modifier.size(24.dp))
}

@Composable
private fun SessionDirectoryScreen(state: HomeState, navigation: HomeNavigation, onRuntime: (String) -> Unit, onSession: (String) -> Unit, onBinding: () -> Unit) {
    val listable = state.runtimes.filter { it.access?.organizationId != null && it.access.canList() }
    val selected = state.runtimes.firstOrNull { it.id == state.selectedRuntimeId && it.id == navigation.directoryRuntimeId }
    val runtime = selected?.takeIf { it in listable }
    val staleSelection = navigation.directoryRuntimeId != null && runtime == null
    var choosingComputer by remember { mutableStateOf(false) }
    LazyColumn(
        modifier = Modifier.widthIn(max = 800.dp).fillMaxSize().testTag("session-directory"),
        state = navigation.directoryPosition,
        contentPadding = PaddingValues(DshSpacing.page),
        verticalArrangement = Arrangement.spacedBy(DshSpacing.small),
    ) {
        item("scope") {
            Column(verticalArrangement = Arrangement.spacedBy(DshSpacing.small)) {
                OutlinedButton({ choosingComputer = true }, enabled = listable.isNotEmpty(), modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("runtime-filter")) {
                    Column(Modifier.weight(1f), horizontalAlignment = Alignment.Start) {
                        Text(runtime?.hostAlias ?: stringResource(R.string.session_select_computer))
                        runtime?.let { Text(stringResource(R.string.computer_runtime, runtimeLabel(it.id, listable)), style = MaterialTheme.typography.bodyMedium) }
                    }
                    ShellIcon(R.drawable.ic_chevron)
                }
                Text(stringResource(R.string.session_scope), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        if (state.refreshing && runtime == null) item("loading-computers") { DirectoryProgress(R.string.directory_loading) }
        if (state.loadingSessions && runtime != null) item("loading-sessions") { DirectoryProgress(R.string.session_loading) }
        state.error?.let { item("account-error") { DshStatusNotice(errorText(it), isError = true) } }
        if (staleSelection && !state.refreshing && state.sessionError == null) item("stale-scope") {
            DshStatusNotice(stringResource(R.string.session_scope_changed), isError = true)
        }
        if (runtime == null && listable.isNotEmpty() && !staleSelection && !state.refreshing) item("choose-scope") {
            DshStatusNotice(stringResource(R.string.session_choose_scope))
        }
        state.sessionError?.let { error -> item("directory-error") {
            DshStatusNotice(stringResource(if (error == "access.denied") R.string.session_directory_denied else R.string.session_directory_error), isError = true)
        } }
        if (!state.refreshing && state.error == null && listable.isEmpty()) item("no-computers") {
            EmptyDirectory(R.string.session_no_computer, R.string.session_no_computer_detail)
            TextButton(onBinding, Modifier.heightIn(min = 48.dp)) { Text(stringResource(if (state.pendingBindingId == null) R.string.action_bind_computer else R.string.action_review_binding)) }
        }
        if (runtime != null && !state.loadingSessions && state.sessionError == null && state.sessions.isEmpty()) item("empty") {
            DshStatusNotice(stringResource(R.string.session_empty))
        }
        if (runtime != null && !state.loadingSessions && state.sessionError == null) items(state.sessions, key = { it.id }) { session ->
            SessionListItem(session, runtime.access?.let(session::viewScope) != null) {
                if (runtime.access?.canList() == true && runtime.access.let(session::viewScope) != null) onSession(session.id)
            }
        }
    }
    if (choosingComputer) AlertDialog(
        onDismissRequest = { choosingComputer = false },
        title = { Text(stringResource(R.string.session_select_computer)) },
        text = {
            LazyColumn {
                items(listable, key = { it.id }) { row ->
                    ListItem(
                        headlineContent = { Text(row.hostAlias) },
                        supportingContent = { Text(stringResource(R.string.computer_runtime, row.id)) },
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("runtime-filter-${row.id}").clickable(role = Role.Button) {
                            choosingComputer = false
                            if (row.access?.canList() == true) onRuntime(row.id)
                        },
                    )
                }
            }
        },
        confirmButton = { TextButton({ choosingComputer = false }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.action_close)) } },
    )
}

@Composable
private fun SessionListItem(session: SessionDirectoryEntry, canRead: Boolean, onClick: () -> Unit) {
    val updated = remember(session.updatedAt) { DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(session.updatedAt)) }
    ListItem(
        headlineContent = { Text(stringResource(R.string.session_short_title, session.id.take(8))) },
        supportingContent = {
            Column(verticalArrangement = Arrangement.spacedBy(DshSpacing.extraSmall)) {
                Text(stringResource(when (session.state) {
                    "running" -> R.string.session_running
                    "archived" -> R.string.session_archived
                    "unavailable" -> R.string.session_unavailable
                    else -> R.string.session_available
                }))
                session.workspaceId?.let { Text(stringResource(R.string.session_workspace, "${it.take(8)}…${it.takeLast(4)}")) }
                Text(stringResource(R.string.session_updated, updated), style = MaterialTheme.typography.bodyMedium)
                if (!canRead) Text(stringResource(R.string.session_directory_only))
            }
        },
        trailingContent = { if (canRead) ShellIcon(R.drawable.ic_chevron) },
        modifier = Modifier.fillMaxWidth().heightIn(min = 64.dp).testTag("session-${session.id}")
            .then(if (canRead) Modifier.clickable(role = Role.Button, onClick = onClick) else Modifier),
        colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surface),
    )
}

@Composable
private fun ComputersScreen(state: HomeState, onRuntime: (String) -> Unit, onCreate: (String) -> Unit, onBinding: () -> Unit) {
    var detailId by remember { mutableStateOf<String?>(null) }
    LazyColumn(Modifier.widthIn(max = 800.dp).fillMaxSize().testTag("computers-directory"), contentPadding = PaddingValues(DshSpacing.page), verticalArrangement = Arrangement.spacedBy(DshSpacing.medium)) {
        item("bind") {
            OutlinedButton(onBinding, Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                Text(stringResource(if (state.pendingBindingId == null) R.string.action_bind_computer else R.string.action_review_binding))
            }
            Text(stringResource(R.string.computer_scope), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (state.refreshing) item("loading") { DirectoryProgress(R.string.directory_loading) }
        state.error?.let { item("error") { DshStatusNotice(errorText(it), isError = true) } }
        if (!state.refreshing && state.runtimes.isEmpty()) item("empty") { EmptyDirectory(R.string.computer_empty, R.string.computer_empty_detail) }
        items(state.runtimes, key = { it.id }) { runtime ->
            OutlinedCard {
                Column(Modifier.fillMaxWidth().padding(DshSpacing.page), verticalArrangement = Arrangement.spacedBy(DshSpacing.small)) {
                    Text(runtime.hostAlias, style = MaterialTheme.typography.titleMedium)
                    Text(stringResource(R.string.computer_runtime, runtimeLabel(runtime.id, state.runtimes)), style = MaterialTheme.typography.bodyMedium)
                    Text(stringResource(R.string.computer_presence_unknown), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    val canList = runtime.access?.organizationId != null && runtime.access.canList()
                    if (canList) FilledTonalButton({ if (runtime.access.canList()) onRuntime(runtime.id) }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.action_open_sessions)) }
                    else Text(stringResource(R.string.computer_no_directory), color = MaterialTheme.colorScheme.onSurfaceVariant)
                    if (runtime.access?.creationScope() != null) TextButton({ if (runtime.access.creationScope() != null) onCreate(runtime.id) }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.action_create_session)) }
                    TextButton({ detailId = runtime.id }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.action_computer_details)) }
                }
            }
        }
    }
    state.runtimes.firstOrNull { it.id == detailId }?.let { runtime ->
        AlertDialog(
            onDismissRequest = { detailId = null },
            title = { Text(stringResource(R.string.action_computer_details)) },
            text = {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(DshSpacing.medium)) {
                    item { DetailField(R.string.computer_name, runtime.hostAlias) }
                    item { DetailField(R.string.computer_host_id, runtime.hostId) }
                    item { DetailField(R.string.computer_runtime_id, runtime.id) }
                    item { DetailField(R.string.computer_organization, runtime.access?.organizationId ?: stringResource(R.string.value_unknown)) }
                    item { DetailField(R.string.computer_version, runtime.version.ifEmpty { stringResource(R.string.value_unknown) }) }
                    item { DetailField(R.string.computer_role, stringResource(when (runtime.access?.role) { "owner" -> R.string.role_owner; "operator" -> R.string.role_operator; "viewer" -> R.string.role_viewer; else -> R.string.value_unknown })) }
                }
            },
            confirmButton = { TextButton({ detailId = null }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.action_close)) } },
        )
    }
}

@Composable
private fun SettingsScreen(state: HomeState, onNotifications: () -> Unit, onAppUpdates: () -> Unit, onExit: () -> Unit) {
    var confirmExit by remember { mutableStateOf(false) }
    LazyColumn(Modifier.widthIn(max = 800.dp).fillMaxSize().testTag("settings-list"), contentPadding = PaddingValues(DshSpacing.page), verticalArrangement = Arrangement.spacedBy(DshSpacing.page)) {
        item("account") {
            Text(stringResource(R.string.settings_account), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
            DetailField(R.string.settings_subject, state.subject)
            DetailField(R.string.settings_account_source, state.issuer)
            DetailField(R.string.settings_device, state.deviceName ?: stringResource(R.string.settings_device_registered))
            DetailField(R.string.settings_device_id, state.deviceId)
        }
        item("notifications") { SettingsItem(R.string.settings_notifications, R.string.settings_notifications_detail, onNotifications) }
        item("updates") { SettingsItem(R.string.settings_updates, R.string.settings_updates_detail, onAppUpdates) }
        item("about") {
            Text(stringResource(R.string.settings_about), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
            Text(stringResource(R.string.settings_version, BuildConfig.VERSION_NAME), style = MaterialTheme.typography.bodyMedium)
            Text(stringResource(R.string.settings_appearance_system), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        item("exit") {
            HorizontalDivider()
            TextButton({ confirmExit = true }, Modifier.fillMaxWidth().heightIn(min = 48.dp), colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)) { Text(stringResource(R.string.action_exit_account)) }
        }
    }
    if (confirmExit) AlertDialog(
        onDismissRequest = { confirmExit = false },
        title = { Text(stringResource(R.string.settings_exit_title)) },
        text = { Text(stringResource(R.string.settings_exit_detail), Modifier.verticalScroll(rememberScrollState())) },
        confirmButton = { TextButton({ confirmExit = false; onExit() }, Modifier.heightIn(min = 48.dp), colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)) { Text(stringResource(R.string.action_exit_account)) } },
        dismissButton = { TextButton({ confirmExit = false }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.action_cancel)) } },
    )
}

@Composable
private fun SettingsItem(@StringRes title: Int, @StringRes description: Int, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(stringResource(title)) },
        supportingContent = { Text(stringResource(description)) },
        trailingContent = { ShellIcon(R.drawable.ic_chevron) },
        modifier = Modifier.clickable(role = Role.Button, onClick = onClick).heightIn(min = 64.dp),
        colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    )
}

@Composable
private fun DetailField(@StringRes label: Int, value: String) {
    Column(Modifier.padding(vertical = DshSpacing.extraSmall), verticalArrangement = Arrangement.spacedBy(DshSpacing.extraSmall)) {
        Text(stringResource(label), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        SelectionContainer { Text(value, style = MaterialTheme.typography.bodyMedium) }
    }
}

@Composable
private fun DirectoryProgress(@StringRes text: Int) {
    Row(Modifier.fillMaxWidth().padding(vertical = DshSpacing.small), horizontalArrangement = Arrangement.spacedBy(DshSpacing.medium), verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
        DshStatusNotice(stringResource(text), Modifier.weight(1f))
    }
}

@Composable
private fun EmptyDirectory(@StringRes title: Int, @StringRes detail: Int) {
    Column(Modifier.padding(vertical = DshSpacing.page), verticalArrangement = Arrangement.spacedBy(DshSpacing.small)) {
        Text(stringResource(title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
        Text(stringResource(detail), color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
