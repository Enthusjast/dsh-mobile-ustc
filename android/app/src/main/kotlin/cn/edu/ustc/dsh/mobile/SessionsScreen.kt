package cn.edu.ustc.dsh.mobile

import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.session.*
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.launch

/** Detail groups are presentation only; each is rendered at most once. */
private enum class ChatDetailSection { DEFAULT, COMMANDS, UPLOADS }
private enum class ChatDetailGroup { ARCHIVE, APPROVALS, UPLOADS, EXPORTS, EXPORT_STATUS, COMMANDS, CANCEL }

@Composable
fun SessionsScreen(state: HomeState, onBack: () -> Unit, onRefresh: () -> Unit, onOlder: () -> Unit, onRetry: () -> Unit,
    onSubmit: (String, String, Boolean) -> Unit = { _, _, _ -> }, onSendPending: (String) -> Unit = {}, onQueryCommands: () -> Unit = {}, onCancelSession: (String) -> Unit = {},
    onAnswer: (QuestionHandle,QuestionAnswers)->Unit={_,_->},onClaim: (QuestionHandle)->Unit={},onRelease: (QuestionHandle)->Unit={},onRefreshQuestions: ()->Unit={},
    onApproval: (String) -> Unit = {}, onApprovalQuery: () -> Unit = {}, onArchive: (String, Boolean, Boolean) -> Unit = { _, _, _ -> },
    onPickFile: (String?, String, String) -> Unit = { _, _, _ -> }, onPickedFile: (String, Uri?) -> Unit = { _, _ -> }, onToggleFile: (String) -> Unit = {},
    onQueryFile: (String) -> Unit = {}, onRemoveFile: (String) -> Unit = {}, onCancelFile: () -> Unit = {},
    onBrowseExports: (ExportSource?, Boolean) -> Unit = { _, _ -> }, onExport: (ExportSource) -> Unit = {}, onQueryExports: () -> Unit = {},
    onCancelExport: (String) -> Unit = {}, onRemoveExport: (String) -> Unit = {}, onSaveExport: (String) -> Unit = {}, onExportDestination: (String, Uri?) -> Unit = { _, _ -> }, onCancelExportSave: () -> Unit = {},
    readingPosition: ChatReadingPosition? = null) {
    val runtime = state.runtimeRow(state.selectedRuntimeId)
    val opened = state.selectedSessionId ?: return
    val archived = state.sessions.firstOrNull { it.id == opened }?.state == "archived"
    val canCompose = !archived && state.outbox != null && runtime?.access?.role in setOf("operator", "owner") && runtime?.access?.scope?.actions?.containsAll(setOf("message.submit", "command.status")) == true
    var showDetails by remember(opened) { mutableStateOf(false) }
    var detailSection by remember(opened) { mutableStateOf(ChatDetailSection.DEFAULT) }
    var detailRequestId by remember(opened) { mutableStateOf<String?>(null) }
    var cancelConfirmEpoch by remember(opened) { mutableStateOf<String?>(null) }
    val keyboard = LocalSoftwareKeyboardController.current
    val imeVisible = WindowInsets.ime.getBottom(LocalDensity.current) > 0
    val leaveDetails = { showDetails = false; detailSection = ChatDetailSection.DEFAULT; detailRequestId = null }
    val returnFromChat: () -> Unit = { if (imeVisible) keyboard?.hide() else if (showDetails) leaveDetails() else onBack() }
    BackHandler(enabled = showDetails) { returnFromChat() }
    val chatListState = rememberLazyListState()
    val detailsListState = rememberLazyListState()
    val listState = if (showDetails) detailsListState else chatListState
    val read = state.reader ?: SessionReadState(SessionReadPhase.CONNECTING)
    val transcript = read.window
    var initialized by remember(opened) { mutableStateOf(false) }
    var followLatest by remember(opened) { mutableStateOf(readingPosition?.following ?: true) }
    var newMessages by remember(opened) { mutableStateOf(false) }
    var lastMessageKey by remember(opened) { mutableStateOf<String?>(null) }
    var lastMessageLength by remember { mutableIntStateOf(-1) }
    var requestedBoundary by remember(opened) { mutableStateOf<Long?>(null) }
    val scope = rememberCoroutineScope()
    val cancelEpoch = read.runtimeEpoch
    val canCancel = !archived && read.phase == SessionReadPhase.READY && transcript?.taskRunning == true && cancelEpoch != null &&
        runtime?.access?.let { grant ->
            grant.canRead() && grant.role in setOf("operator", "owner") &&
                grant.scope?.actions?.containsAll(setOf("session.cancel", "command.status")) == true
        } == true && state.outbox?.connected == true && !state.submitting
    val pendingCancel = cancelEpoch?.let { epoch ->
        state.outbox?.records?.firstOrNull {
            it.intent.runtimeId == state.selectedRuntimeId && it.intent.sessionId == opened && it.intent.isCurrentCancel(epoch) &&
                it.remote !in setOf(RemoteCommandState.SETTLED, RemoteCommandState.REJECTED)
        }
    }
    val summary = state.outbox?.let { selectChatDeliveryRecord(it.records, state.selectedRuntimeId.orEmpty(), opened) }
    val footerError = state.commandError ?: state.outbox?.error
    val hasOperationFooter = summary != null || footerError != null || canCancel || pendingCancel != null
    val openDetails: (ChatDetailSection, String?) -> Unit = { section, request ->
        detailSection = section
        detailRequestId = request
        showDetails = true
        scope.launch { detailsListState.scrollToItem(0) }
    }
    LaunchedEffect(canCancel) { if (!canCancel) cancelConfirmEpoch = null }
    val currentTranscript by rememberUpdatedState(transcript)
    val currentRead by rememberUpdatedState(read)
    val currentOnOlder by rememberUpdatedState(onOlder)
    LaunchedEffect(listState, opened, showDetails) {
        if (!showDetails) snapshotFlow { Triple(listState.isScrollInProgress, listState.layoutInfo.visibleItemsInfo.lastOrNull()?.key, listState.layoutInfo.visibleItemsInfo.any { it.key == "older" }) }
            .collect { (scrolling, lastKey, atHistoryBoundary) ->
                if (scrolling) {
                    followLatest = lastKey == "conversation-end"
                    if (followLatest) newMessages = false
                    listState.layoutInfo.visibleItemsInfo.firstOrNull { visible ->
                        currentTranscript?.items?.any { message -> message.id == visible.key } == true
                    }?.let { visible ->
                        readingPosition?.key = visible.key as String
                        readingPosition?.offset = (-visible.offset).coerceAtLeast(0)
                    }
                    val snapshot = currentTranscript
                    val boundary = snapshot?.records?.firstOrNull()?.seq
                    if (initialized && atHistoryBoundary && boundary != null && boundary != requestedBoundary &&
                        snapshot.hasMore && currentRead.phase == SessionReadPhase.READY && !currentRead.loadingOlder && currentRead.pageError == null) {
                        requestedBoundary = boundary
                        currentOnOlder()
                    }
                    readingPosition?.following = followLatest
                }
            }
    }
    LaunchedEffect(transcript, showDetails) {
        if (!showDetails && transcript != null) {
            val restoreIndex = if (!initialized && readingPosition?.following == false) transcript.items.indexOfFirst { it.id == readingPosition.key } else -1
            if (restoreIndex >= 0) {
                withFrameNanos { }
                // Trailing decoration must include the optional operation footer.
                val trailing = 1 + (if (transcript.taskRunning && read.phase == SessionReadPhase.READY) 1 else 0) + (if (hasOperationFooter) 1 else 0)
                val index = listState.layoutInfo.totalItemsCount - trailing - transcript.items.size + restoreIndex
                if (index >= 0) listState.scrollToItem(index, readingPosition!!.offset)
                initialized = true
            } else if (!initialized || followLatest) {
                withFrameNanos { }
                val end = listState.layoutInfo.totalItemsCount - 1
                followLatest = true
                readingPosition?.following = true
                if (end >= 0) listState.scrollToItem(end)
                initialized = true
                newMessages = false
            } else if (lastMessageKey != null && (transcript.items.lastOrNull()?.id != lastMessageKey ||
                    (transcript.items.lastOrNull()?.live == true && transcript.items.lastOrNull()?.blocks?.sumOf { it.text.length } != lastMessageLength))) {
                newMessages = true
            }
            lastMessageKey = transcript.items.lastOrNull()?.id
            lastMessageLength = transcript.items.lastOrNull()?.blocks?.sumOf { it.text.length } ?: -1
        }
    }
    var text by remember(opened, state.composerRevision) { mutableStateOf(state.composerRestore?.text ?: "") }
    var mode by remember(opened) { mutableStateOf(state.composerRestore?.mode ?: "queue") }
    LaunchedEffect(state.composerRevision) { state.composerRestore?.let { mode = it.mode } }
    state.documentPicker?.let { pending -> key(pending.id) {
        var launched by rememberSaveable { mutableStateOf(false) }
        // Each consent has its own registry key and immutable token. A result
        // from an older account/view cannot be relabeled as a later selection.
        val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> onPickedFile(pending.id, uri) }
        LaunchedEffect(pending.id) { if (!launched) { launched = true; picker.launch(arrayOf("*/*")) } }
    } }
    state.exportSavePicker?.let { pending -> key(pending.id) {
        var launched by rememberSaveable { mutableStateOf(false) }
        val picker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri -> onExportDestination(pending.id, uri) }
        LaunchedEffect(pending.id) { if (!launched) { launched = true; picker.launch(exportSuggestedName(pending.name)) } }
    } }
    Scaffold(
        topBar = {
            cn.edu.ustc.dsh.ui.DshTopBar(
                title = stringResource(R.string.chat_title, opened.take(8)),
                subtitle = if (read.phase == SessionReadPhase.READY) stringResource(R.string.chat_live_subtitle, runtime?.hostAlias ?: stringResource(R.string.chat_authorized_computer))
                    else runtime?.hostAlias ?: stringResource(R.string.chat_authorized_computer),
                navigationIcon = {
                    IconButton(returnFromChat) {
                        Icon(painterResource(R.drawable.ic_back), contentDescription = stringResource(if (showDetails) R.string.chat_messages else if (state.knownTarget != null) R.string.chat_back_reminders else R.string.chat_back))
                    }
                },
                actions = { if (!showDetails) TextButton({ openDetails(ChatDetailSection.DEFAULT, null) }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_details)) } },
            )
        },
        bottomBar = {
            if (!showDetails) Column {
                val approvalsPending = runtime?.access?.role == "owner" && runtime.access.scope?.actions?.containsAll(setOf("session.read", "approval.decide")) == true &&
                    state.approvals?.view?.items?.any { it.canReview || it.handle != null || it.remainingMillis > 0 && it.status.state in setOf(ApprovalRemoteState.PENDING, ApprovalRemoteState.DECISION_RECEIVED) } == true
                if (!archived && read.phase == SessionReadPhase.READY && (read.questions.items.isNotEmpty() || approvalsPending)) {
                    TextButton({ followLatest = false; scope.launch { listState.animateScrollToItem(0) } }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                        Text(stringResource(R.string.chat_pending))
                    }
                }
                if (canCompose) SessionComposer(state, onSubmit, text, mode, { text = it }, { mode = it },
                    onAttach = { onPickFile(null, text, mode) }, onRemove = onToggleFile,
                    onViewAttachments = { openDetails(ChatDetailSection.UPLOADS, null) })
            }
        },
    ) { insets ->
        Box(Modifier.fillMaxSize().padding(insets), contentAlignment = Alignment.TopCenter) {
            LazyColumn(Modifier.widthIn(max = 800.dp).fillMaxSize().testTag("chat-list"), state = listState, contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    if (read.phase != SessionReadPhase.READY || read.cacheError != null) item("connection") {
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
                                if (read.window != null && read.phase != SessionReadPhase.READY) Text("显示本机已确认保存的历史缓存。当前任务状态需重新连接确认。", style = MaterialTheme.typography.bodySmall)
                                if (read.cacheError != null) Text("本机历史缓存暂时无法读取或更新，在线阅读仍可继续。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                                if (read.phase == SessionReadPhase.OFFLINE && read.window == null) Text("需要电脑上线后才能读取内容。")
                                if (read.error in setOf("protocol.snapshot_too_large", "client.history_limit")) Text("内容超过本机阅读窗口，请在电脑查看完整内容。")
                                if (read.phase in setOf(SessionReadPhase.ERROR, SessionReadPhase.OFFLINE, SessionReadPhase.BACKOFF)) {
                                    OutlinedButton(onRetry, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("重新读取") }
                                }
                            }
                        }
                    }
                    state.notificationNote?.let { note -> item("notification-note") { Text(note, color = MaterialTheme.colorScheme.onSurfaceVariant) } }
                    val focusedQuestion = read.questions.items.firstOrNull { it.handle == state.notificationQuestion }
                    if (!showDetails && read.phase == SessionReadPhase.READY && !archived && focusedQuestion != null) item("question:${focusedQuestion.handle.kind}:${focusedQuestion.batch.id}") {
                        QuestionCard(focusedQuestion, read.questions.canAnswer, state.submitting, state.outbox?.records ?: emptyList(), onAnswer, onClaim, onRelease, onRefreshQuestions, onQueryCommands)
                    }

                    fun LazyListScope.archiveGroup() {
                        if (!showDetails || !(archived || runtime?.access?.scope?.actions?.contains("session.archive") == true)) return
                        item("archive-session") {
                            key(opened) {
                                SessionArchiveActions(archived, read.runtimeEpoch, read.phase == SessionReadPhase.READY && state.outbox?.canArchive == true && !state.submitting,
                                    runtime?.access?.role in setOf("operator", "owner") && runtime?.access?.scope?.actions?.containsAll(setOf("session.archive", "command.status")) == true,
                                    onArchive, onRefresh)
                            }
                        }
                    }
                    fun LazyListScope.approvalGroup() {
                        val approvals = state.approvals?.takeIf { !archived && runtime?.access?.role == "owner" && runtime.access.scope?.actions?.containsAll(setOf("session.read", "approval.decide")) == true } ?: return
                        approvals.error?.let { code -> item("approval-error") { Text(approvalErrorText(code), color = MaterialTheme.colorScheme.error) } }
                        val pending = approvals.view.items.filter { it.canReview || it.handle != null || it.remainingMillis > 0 && it.status.state in setOf(ApprovalRemoteState.PENDING, ApprovalRemoteState.DECISION_RECEIVED) }
                        if (!showDetails) items(pending, key = { "approval:${it.status.id}" }) { view ->
                            OutlinedCard(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                Text("待处理工具审批", style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
                                Text("先在线核对完整动作与参数，再为本次调用作出决定。")
                                OutlinedButton({ onApproval(view.status.id) }, enabled = approvals.connected && approvals.contentReady, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("核对工具审批") }
                            } }
                        }
                        if (showDetails && approvals.records.isNotEmpty()) item("approval-records-heading") {
                            Text("本机审批记录", style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
                            TextButton(onApprovalQuery, Modifier.heightIn(min = 48.dp)) { Text("核对审批结果") }
                        }
                        if (showDetails) items(approvals.records, key = { "approval-original:${it.intent.requestId}" }) { row ->
                            OutlinedCard(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                Text(if (row.intent.decision.choice == ApprovalChoice.ALLOW_ONCE) "原决定：仅本次允许" else "原决定：拒绝", style = MaterialTheme.typography.titleSmall)
                                Text(approvalRecordLabel(row))
                                OutlinedButton({ onApproval(row.intent.approvalId) }, enabled = approvals.connected, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("查看原决定与当前详情") }
                            } }
                        }
                    }
                    fun LazyListScope.uploadsGroup() {
                        if (!showDetails) return
                        val files = state.uploads?.takeIf { !archived && canCompose }
                        if (files == null) {
                            if (detailSection == ChatDetailSection.UPLOADS) item("uploads-unavailable") {
                                Text(stringResource(R.string.chat_attachments_unavailable), color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            return
                        }
                        item("uploads") {
                            UploadsPanel(files, state.outbox?.canAttachFiles == true && read.phase == SessionReadPhase.READY,
                                { id -> onPickFile(id, text, mode) }, onToggleFile, onQueryFile, onRemoveFile, onCancelFile)
                        }
                    }
                    fun LazyListScope.exportsGroup() {
                        if (!showDetails) return
                        state.exports?.let { exports -> item("exports") { ExportsPanel(exports, onBrowseExports, onExport, onQueryExports, onCancelExport, onRemoveExport, onSaveExport, state.exportSaving || state.exportSavePicker != null) } }
                    }
                    fun LazyListScope.exportStatusGroup() {
                        if (!showDetails || !(state.exportSaving || state.exportSaved || state.exportSaveError != null)) return
                        item("export-save-status") {
                            if (state.exportSaving) {
                                Text("正在下载并核对文件 · ${state.exportBytes} 字节", modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                                TextButton(onCancelExportSave, Modifier.heightIn(min = 48.dp)) { Text("取消保存") }
                            }
                            if (state.exportSaved) Text("文件已保存，回读校验通过。", modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                            state.exportSaveError?.let { Text(exportErrorText(it), color = MaterialTheme.colorScheme.error) }
                        }
                    }
                    fun LazyListScope.commandGroup() {
                        state.commandError?.let { error -> item("command-error") { Text(commandErrorText(error), color = MaterialTheme.colorScheme.error) } }
                        val outbox = state.outbox ?: return
                        outbox.error?.let { error -> item("outbox-error") { Text(commandErrorText(error), color = MaterialTheme.colorScheme.error, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) } }
                        if (!showDetails) return
                        val target = detailRequestId.takeIf { detailSection == ChatDetailSection.COMMANDS }
                        val ordered = outbox.records.sortedWith(
                            compareBy<PendingCommand> { if (target != null && it.intent.requestId == target) 0 else 1 }
                                .thenByDescending { it.createdAt }.thenByDescending { it.intent.requestId })
                        if (ordered.isEmpty()) item("outbox-empty") { Text(stringResource(R.string.chat_no_delivery_records), style = MaterialTheme.typography.bodySmall) }
                        else item("outbox-heading") {
                            Text("本机发送记录", style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
                            Text("入队确认不代表任务完成。连接恢复后会先核对原请求状态。", style = MaterialTheme.typography.bodySmall)
                            OutlinedButton(onQueryCommands, Modifier.heightIn(min = 48.dp)) { Text("核对发送状态") }
                        }
                        items(ordered, key = { "command:${it.intent.requestId}" }) { record ->
                            OutlinedCard(Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                    Text(stringResource(commandLabel(record)), style = MaterialTheme.typography.titleSmall)
                                    if (record.intent.kind == CommandKind.MESSAGE && record.remote == RemoteCommandState.SETTLED) {
                                        Text(stringResource(R.string.chat_delivery_settled_note), style = MaterialTheme.typography.bodySmall)
                                    }
                                    SelectionContainer { Text(stringResource(R.string.chat_original_request, record.intent.requestId), style = MaterialTheme.typography.bodySmall) }
                                    Text(stringResource(when {
                                        record.attempts == 0L -> R.string.chat_local_only
                                        record.remote == RemoteCommandState.RECEIVED -> R.string.chat_relay_only
                                        record.remote == RemoteCommandState.HOST_ACCEPTED -> R.string.chat_host_saved
                                        record.everAgentQueued -> R.string.chat_queued_not_finished
                                        else -> R.string.chat_original_reconcile
                                    }), style = MaterialTheme.typography.bodySmall)
                                    if (needsDeliveryReconciliation(record) && record.remote != RemoteCommandState.OUTCOME_UNKNOWN) {
                                        Text(stringResource(R.string.chat_original_reconcile), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                                    }
                                    if (record.intent.kind == CommandKind.ARCHIVE) {
                                        val archiveIntent = (record.intent.payload["archived"] as JsonBoolean).value
                                        Text(if (archiveIntent) "归档会话" else "恢复会话")
                                        if ((record.intent.payload["stop_activity"] as JsonBoolean).value) Text("已选择同时请求停止活动；实际结束状态以会话内容为准。", style = MaterialTheme.typography.bodySmall)
                                    }
                                    if (!record.everAgentQueued) record.intent.text()?.let { ReadingText(it, 512) }
                                    if (record.intent.fileIds().isNotEmpty()) Text("附件 ${record.intent.fileIds().size} 个；状态以原请求为准。", style = MaterialTheme.typography.bodySmall)
                                    if(record.intent.kind.question) SubmittedQuestionAnswer(record.intent)
                                    val questionCurrent=!record.intent.kind.question || read.questions.items.any {it.batch.id==record.intent.payload.string("question_id") && it.batch.definition==record.intent.questionDefinition && it.handle.epoch==record.intent.epoch && it.answerable}
                                    val actionAllowed = (!archived || record.intent.kind == CommandKind.ARCHIVE) && (record.intent.epoch == null || record.intent.epoch == read.runtimeEpoch)
                                    if (record.delivery == CommandDelivery.PENDING && record.attempts == 0L && questionCurrent) {
                                        OutlinedButton({ onSendPending(record.intent.requestId) }, enabled = outbox.connected && actionAllowed, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(if (record.intent.kind == CommandKind.MESSAGE) "发送这条待发消息" else "发送这条待发命令") }
                                    }
                                    if ((record.remote == RemoteCommandState.RECEIVED || record.remote == null && record.intent.fileIds().isNotEmpty()) && !record.everHostSaved && record.attempts > 0 && questionCurrent) {
                                        var retry by remember { mutableStateOf(false) }
                                        OutlinedButton({ retry = true }, enabled = outbox.connected && actionAllowed && (record.intent.fileIds().isEmpty() || outbox.canAttachFiles), modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("重新转交同一请求") }
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
                    fun LazyListScope.cancelGroup() {
                        if (!showDetails || !(canCancel || pendingCancel != null)) return
                        item("cancel-task") {
                            if (pendingCancel != null) {
                                Text(stringResource(R.string.chat_cancel_pending), style = MaterialTheme.typography.titleSmall)
                                SelectionContainer { Text(stringResource(R.string.chat_original_request, pendingCancel.intent.requestId), style = MaterialTheme.typography.bodySmall) }
                            }
                            if (canCancel && cancelEpoch != null) {
                                OutlinedButton({ cancelConfirmEpoch = cancelEpoch }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("中断当前任务") }
                            }
                        }
                    }

                    if (showDetails) {
                        val order = when (detailSection) {
                            ChatDetailSection.DEFAULT -> listOf(ChatDetailGroup.ARCHIVE, ChatDetailGroup.APPROVALS, ChatDetailGroup.UPLOADS, ChatDetailGroup.EXPORTS, ChatDetailGroup.EXPORT_STATUS, ChatDetailGroup.COMMANDS, ChatDetailGroup.CANCEL)
                            ChatDetailSection.COMMANDS -> listOf(ChatDetailGroup.COMMANDS, ChatDetailGroup.ARCHIVE, ChatDetailGroup.APPROVALS, ChatDetailGroup.UPLOADS, ChatDetailGroup.EXPORTS, ChatDetailGroup.EXPORT_STATUS, ChatDetailGroup.CANCEL)
                            ChatDetailSection.UPLOADS -> listOf(ChatDetailGroup.UPLOADS, ChatDetailGroup.ARCHIVE, ChatDetailGroup.APPROVALS, ChatDetailGroup.EXPORTS, ChatDetailGroup.EXPORT_STATUS, ChatDetailGroup.COMMANDS, ChatDetailGroup.CANCEL)
                        }
                        for (group in order) when (group) {
                            ChatDetailGroup.ARCHIVE -> archiveGroup()
                            ChatDetailGroup.APPROVALS -> approvalGroup()
                            ChatDetailGroup.UPLOADS -> uploadsGroup()
                            ChatDetailGroup.EXPORTS -> exportsGroup()
                            ChatDetailGroup.EXPORT_STATUS -> exportStatusGroup()
                            ChatDetailGroup.COMMANDS -> commandGroup()
                            ChatDetailGroup.CANCEL -> cancelGroup()
                        }
                    } else {
                        approvalGroup()
                        if (read.phase == SessionReadPhase.READY && !archived) {
                            items(read.questions.items.filter { it.batch.id != focusedQuestion?.batch?.id },key={"question:${it.handle.kind}:${it.batch.id}"}) {question->
                                QuestionCard(question,read.questions.canAnswer,state.submitting,state.outbox?.records ?: emptyList(),onAnswer,onClaim,onRelease,onRefreshQuestions,onQueryCommands)
                            }
                            read.questions.error?.let {code->item("question-error") {Text(commandErrorText(code),color=MaterialTheme.colorScheme.error)}}
                        }
                    }
                    if (!showDetails && transcript != null) {
                        if (transcript.hasMore && read.phase == SessionReadPhase.READY) item("older") {
                            OutlinedButton(onOlder, enabled = !read.loadingOlder && read.pageError != "client.history_limit", modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(if (read.loadingOlder) "正在读取更早消息…" else "读取更早消息") }
                            read.pageError?.let { Text(if (it == "client.history_limit") "已达到本机阅读窗口上限，请在电脑查看更早内容。" else "更早消息暂时无法读取，可以重试。", color = MaterialTheme.colorScheme.error) }
                        }
                        if (transcript.checkpoint != "persisted") item("persistence") { Text("保存状态暂不可用，部分内容尚未确认保存。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                        if (transcript.items.isEmpty() && read.phase == SessionReadPhase.READY) item("empty-session") { Text("会话还没有消息。") }
                        items(transcript.items, key = { it.id }) { entry -> ConversationBubble(entry) }
                        if (transcript.taskRunning && read.phase == SessionReadPhase.READY) item("running") { Text("电脑上的任务仍在进行。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    }
                    if (!showDetails && hasOperationFooter) item("chat-operation-footer") {
                        ChatOperationFooter(summary, footerError, canCancel, pendingCancel,
                            onViewDelivery = { openDetails(ChatDetailSection.COMMANDS, summary?.intent?.requestId) },
                            onViewCancel = { openDetails(ChatDetailSection.COMMANDS, pendingCancel?.intent?.requestId) },
                            onCancel = { if (canCancel && cancelEpoch != null) cancelConfirmEpoch = cancelEpoch })
                    }
                    if (!showDetails) item("conversation-end") { Spacer(Modifier.height(1.dp)) }
            }
            if (!showDetails && initialized && (!followLatest || newMessages)) {
                FilledTonalButton(
                    onClick = {
                        followLatest = true
                        readingPosition?.following = true
                        newMessages = false
                        scope.launch { listState.animateScrollToItem((listState.layoutInfo.totalItemsCount - 1).coerceAtLeast(0)) }
                    },
                    modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp).heightIn(min = 48.dp),
                ) { Text(stringResource(if (newMessages) R.string.chat_new_messages else R.string.chat_latest)) }
            }
        }
    }
    val confirmEpoch = cancelConfirmEpoch
    if (confirmEpoch != null && canCancel && confirmEpoch == cancelEpoch) AlertDialog(
        onDismissRequest = { cancelConfirmEpoch = null }, title = { Text("中断电脑上的当前任务？") },
        text = { Text("这不会清空已排队的消息。后续任务是否继续，以电脑端状态为准。") },
        confirmButton = { TextButton({
            val epoch = cancelEpoch
            cancelConfirmEpoch = null
            if (epoch != null && epoch == confirmEpoch && canCancel) onCancelSession(epoch)
        }) { Text("确认中断") } },
        dismissButton = { TextButton({ cancelConfirmEpoch = null }) { Text("继续运行") } })
}

@Composable
private fun ChatOperationFooter(summary: PendingCommand?, error: String?, canCancel: Boolean, pendingCancel: PendingCommand?,
    onViewDelivery: () -> Unit, onViewCancel: () -> Unit, onCancel: () -> Unit) {
    Surface(color = MaterialTheme.colorScheme.surfaceContainerLow, shape = MaterialTheme.shapes.medium) {
        Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (summary != null) {
                Text(stringResource(R.string.chat_footer_title), style = MaterialTheme.typography.labelLarge, modifier = Modifier.semantics { heading() })
                Text(stringResource(commandLabel(summary)), style = MaterialTheme.typography.bodyMedium)
                SelectionContainer { Text(stringResource(R.string.chat_original_request, summary.intent.requestId), style = MaterialTheme.typography.bodySmall) }
                if (summary.intent.kind == CommandKind.MESSAGE && summary.remote == RemoteCommandState.SETTLED) {
                    Text(stringResource(R.string.chat_delivery_settled_note), style = MaterialTheme.typography.bodySmall)
                }
                TextButton(onViewDelivery, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_view_delivery)) }
            }
            if (error != null) Text(commandErrorText(error), color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            if (pendingCancel != null) {
                Text(stringResource(R.string.chat_cancel_pending), style = MaterialTheme.typography.bodyMedium)
                TextButton(onViewCancel, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_view_cancel_original)) }
            }
            if (canCancel) OutlinedButton(onCancel, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("中断当前任务") }
        }
    }
}

@Composable
private fun ConversationBubble(item: ConversationItem) {
    val user = item.role == ConversationRole.USER
    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (user) Arrangement.End else Arrangement.Start) {
        Surface(Modifier.widthIn(max = 640.dp).fillMaxWidth(if (user) 0.94f else 1f), color = if (user) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surfaceContainerLow, shape = MaterialTheme.shapes.medium) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(when (item.role) { ConversationRole.USER -> "你"; ConversationRole.ASSISTANT -> "助手"; ConversationRole.TOOL -> "工具"; ConversationRole.NOTICE -> "状态" }, style = MaterialTheme.typography.labelLarge)
                for ((index, block) in item.blocks.withIndex()) key(index) {
                    when (block.kind) {
                        BlockKind.TEXT -> RichMessageText(block.text)
                        BlockKind.REASONING -> {
                            var expanded by remember { mutableStateOf(false) }
                            TextButton({ expanded = !expanded }, Modifier.heightIn(min = 48.dp)) { Text(if (expanded) "收起思考过程" else "查看思考过程") }
                            if (expanded) RichMessageText(block.text)
                        }
                        BlockKind.TOOL -> ToolCallRecord(item.id, index, block, item.live)
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

/** Only fields already present in the validated display record; never a completion claim. */
@Composable
private fun ToolCallRecord(itemId: String, index: Int, block: DisplayBlock, live: Boolean) {
    var expanded by remember(itemId, index) { mutableStateOf(false) }
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(if (block.name.isEmpty()) R.string.chat_tool_info else R.string.chat_tool_record), style = MaterialTheme.typography.labelLarge)
            if (block.name.isNotEmpty()) Text(block.name, style = MaterialTheme.typography.titleSmall)
            if (live && !block.complete) Text(stringResource(R.string.chat_tool_receiving), style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            TextButton({ expanded = !expanded }, Modifier.heightIn(min = 48.dp)) {
                Text(stringResource(if (expanded) R.string.chat_hide_call else R.string.chat_show_call))
            }
            if (expanded) {
                SelectionContainer {
                    Text(stringResource(if (block.callId.isEmpty()) R.string.chat_no_call_id else R.string.chat_call_id, block.callId),
                        style = MaterialTheme.typography.bodySmall)
                }
                if (block.text.isNotEmpty()) RichMessageText(block.text, 4 * 1024)
                else Text(stringResource(R.string.chat_no_tool_detail), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
private fun SessionComposer(
    state: HomeState, onSubmit: (String, String, Boolean) -> Unit, text: String, mode: String,
    onText: (String) -> Unit, onMode: (String) -> Unit, onAttach: () -> Unit, onRemove: (String) -> Unit,
    onViewAttachments: () -> Unit,
) {
    val placeholder = "11111111-1111-4111-8111-111111111111"
    val selected = state.uploads?.let { uploads -> uploads.selected.mapNotNull { id -> uploads.rows.firstOrNull { it.stored.intent.requestId == id } } } ?: emptyList()
    val attachments = selected.mapNotNull { it.stored.fileId }
    val attachmentsReady = selected.size == (state.uploads?.selected?.size ?: 0) && selected.all { it.ready() }
    val textValid = runCatching { CommandIntent.message(placeholder, placeholder, placeholder, mode, text, attachments) }.isSuccess
    val valid = (text.isNotBlank() || attachments.isNotEmpty()) && attachmentsReady && textValid
    val online = state.outbox?.connected == true && state.reader?.phase == SessionReadPhase.READY
    var menu by remember { mutableStateOf(false) }
    var explainAttachments by remember { mutableStateOf(false) }
    var attachmentDetail by remember { mutableStateOf<Pair<String, Long?>?>(null) }
    val attachmentAvailable = online && state.outbox?.canAttachFiles == true && state.uploads != null
    Surface(tonalElevation = 3.dp, modifier = Modifier.testTag("message-composer")) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().imePadding().padding(horizontal = 8.dp, vertical = 4.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Box {
                    TextButton({ menu = true }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(if (mode == "queue") R.string.chat_queue else R.string.chat_steer)) }
                    DropdownMenu(menu, { menu = false }) {
                        DropdownMenuItem(text = { Column { Text(stringResource(R.string.chat_queue)); Text(stringResource(R.string.chat_queue_desc), style = MaterialTheme.typography.bodySmall) } }, onClick = { menu = false; onMode("queue") })
                        DropdownMenuItem(text = { Column { Text(stringResource(R.string.chat_steer)); Text(stringResource(R.string.chat_steer_desc), style = MaterialTheme.typography.bodySmall) } }, onClick = { menu = false; onMode("steer") })
                    }
                }
                Spacer(Modifier.weight(1f))
                TextButton({ if (attachmentAvailable) onAttach() else explainAttachments = true }, enabled = state.uploads?.busy != true, modifier = Modifier.heightIn(min = 48.dp)) {
                    Text(stringResource(if (attachmentAvailable) R.string.chat_attach else R.string.chat_attach_unavailable))
                }
            }
            if (selected.isNotEmpty()) {
                Text(stringResource(R.string.chat_attachment_count, attachments.size), style = MaterialTheme.typography.bodySmall)
                Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    selected.forEach { upload ->
                        val name = upload.stored.intent.manifest.name
                        val size = upload.stored.intent.manifest.sizeBytes
                        Column(Modifier.widthIn(max = 240.dp)) {
                            Text(name, style = MaterialTheme.typography.bodyMedium, maxLines = 2, overflow = TextOverflow.Ellipsis)
                            Text(fileSizeText(size), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Row {
                                TextButton({ onRemove(upload.stored.intent.requestId) }, Modifier.heightIn(min = 48.dp),
                                    contentPadding = PaddingValues(horizontal = 8.dp)) {
                                    Text(stringResource(R.string.chat_remove_attachment), modifier = Modifier.semantics {
                                        contentDescription = upload.stored.intent.manifest.name
                                    })
                                }
                                TextButton({ attachmentDetail = name to size }, Modifier.heightIn(min = 48.dp),
                                    contentPadding = PaddingValues(horizontal = 8.dp)) {
                                    Text(stringResource(R.string.chat_attachment_detail), modifier = Modifier.semantics {
                                        contentDescription = upload.stored.intent.manifest.name
                                    })
                                }
                            }
                        }
                    }
                }
                TextButton(onViewAttachments, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_view_attachments)) }
            }
            val inputLabel = stringResource(R.string.chat_input)
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Bottom, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                OutlinedTextField(text, { if (it.length <= 65_536) onText(it) }, label = { Text(inputLabel) },
                    minLines = 1, maxLines = 5, isError = text.isNotBlank() && !textValid,
                    modifier = Modifier.weight(1f))
                FilledIconButton({ onSubmit(mode, text, online) }, enabled = valid && !state.submitting, modifier = Modifier.size(48.dp)) {
                    Icon(painterResource(R.drawable.ic_send), contentDescription = stringResource(if (state.submitting) R.string.chat_saving else if (online) R.string.chat_send else R.string.chat_save_pending))
                }
            }
            if (state.submitting) Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                Text(stringResource(R.string.chat_saving_request), style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            }
            if (!attachmentsReady) Text(stringResource(R.string.chat_attachment_not_ready), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            if (text.isNotBlank() && !textValid) Text(stringResource(R.string.chat_invalid), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            if (!online) Text(stringResource(R.string.chat_offline), style = MaterialTheme.typography.bodySmall)
        }
    }
    attachmentDetail?.let { (name, size) ->
        AlertDialog(onDismissRequest = { attachmentDetail = null }, title = { Text(stringResource(R.string.chat_attachment_detail)) },
            text = { Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SelectionContainer { Text(name) }
                Text(fileSizeText(size), style = MaterialTheme.typography.bodySmall)
            } },
            confirmButton = { TextButton({ attachmentDetail = null }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.action_close)) } })
    }
    if (explainAttachments) AlertDialog(onDismissRequest = { explainAttachments = false },
        title = { Text(stringResource(R.string.chat_attach_unavailable)) },
        text = { Text(stringResource(R.string.chat_attach_unavailable_reason)) },
        confirmButton = { TextButton({ explainAttachments = false }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_link_cancel)) } })
}
private fun commandErrorText(code: String) = when (code) {
    "data.locked", "data.lock_required" -> "请解锁设备并设置安全锁屏后，再使用本机发送记录。"
    "data.key_missing", "data.key_corrupt", "data.owner_mismatch", "data.corrupt", "data.unavailable" -> "本机发送记录无法读取，已停用发送。请先核对本机数据。"
    "data.outbox_limit" -> "本机发送记录已达到容量上限，请核对已有记录后再继续。"
    "command.busy" -> "待处理的发送操作较多，请稍后核对发送状态。"
    "command.too_large", "command.invalid" -> "消息过长或格式不支持，请调整后重试。"
    "command.reconcile_required", "command.delivery_unconfirmed", "command.status_unavailable" -> "尚未核对发送结果，请查询原请求状态；不会自动重复发送。"
    "runtime.changed" -> "电脑运行环境已重新启动，原操作请求不会用于新的任务。"
    "session.active" -> "会话仍有活动。请等待结束，或重新确认归档并请求停止。"
    "session.archived" -> "会话已归档，请刷新会话状态并恢复后继续。"
    "access.denied" -> "当前连接不支持或未获授权执行此操作，请刷新会话状态。"
    "question.stale","question.resync_required","question.ended","interaction.stale" -> "提问状态已更新，请刷新并核对电脑上的当前问题。原答复不会自动重发。"
    "question.invalid_answer" -> "请按当前问题的选项和要求填写完整答复。"
    "question.reconcile_required" -> "这个问题已有答复请求，请先核对原请求的结果。"
    "question.claim_limit","rate.limited" -> "当前等待请求较多，请结束已有答复或刷新提问状态后重试。"
    "command.cancel_unconfirmed" -> "尚未核对中断请求结果，请查询原请求状态；不会自动重复中断。"
    else -> if (code.startsWith("file.")) fileErrorText(code) else "暂时无法处理此发送操作，请先核对发送状态。"
}
