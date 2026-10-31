package cn.edu.ustc.dsh.mobile

import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.session.*
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.launch

/** Separate tasks share the already-open reader and never create another receiver. */
private enum class ChatDetailSection { INFO, COMMANDS, FILES, IMAGES }

private fun questionAnchor(handle: QuestionHandle) = "question:${handle.kind}:${handle.questionId}:${handle.epoch}:${handle.subscriptionId}:${handle.syncId}:${handle.definition}"
private fun approvalAnchor(approval: PresentedApproval) = "approval:${approval.status.id}:${approval.handle?.reviewId.orEmpty()}"

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SessionsScreen(state: HomeState, onBack: () -> Unit, onRefresh: () -> Unit, onOlder: () -> Unit, onRetry: () -> Unit,
    onSubmit: (MessageSubmission) -> Unit = {}, onSendPending: (String) -> Unit = {}, onQueryCommands: () -> Unit = {}, onCancelSession: (String) -> Unit = {},
    onAnswer: (QuestionHandle,QuestionAnswers)->Unit={_,_->},onClaim: (QuestionHandle)->Unit={},onRelease: (QuestionHandle)->Unit={},onRefreshQuestions: ()->Unit={},
    onApproval: (String) -> Unit = {}, onApprovalQuery: () -> Unit = {}, onArchive: (String, Boolean, Boolean) -> Unit = { _, _, _ -> },
    onPickFile: (String?) -> Unit = {}, onPickedFile: (String, Uri?) -> Unit = { _, _ -> }, onToggleFile: (String) -> Unit = {},
    onQueryFile: (String) -> Unit = {}, onRemoveFile: (String) -> Unit = {}, onCancelFile: () -> Unit = {},
    onBrowseExports: (ExportSource?, Boolean) -> Unit = { _, _ -> }, onExport: (ExportSource) -> Unit = {}, onQueryExports: () -> Unit = {},
    onCancelExport: (String) -> Unit = {}, onRemoveExport: (String) -> Unit = {}, onSaveExport: (String) -> Unit = {}, onExportDestination: (String, Uri?) -> Unit = { _, _ -> }, onCancelExportSave: () -> Unit = {},
    readingPosition: ChatReadingPosition? = null, onComposerChange: (MessageComposerState) -> Unit = {}, onModels: (() -> Unit)? = null,
    onChanges: (() -> Unit)? = null, onMessageAction: ((String) -> Unit)? = null,
    onPickImage: () -> Unit = {}, onPickCamera: () -> Unit = {}, onPreviewMedia: ((VisibleMediaReference) -> Unit)? = null,
    onDismissImagePreview: () -> Unit = {}, onCancelImage: () -> Unit = {}, onReselectImage: (String) -> Unit = {},
    onResolveFailedInput: (MessageComposerState, Boolean) -> Unit = { _, _ -> }) {
    val runtime = state.runtimeRow(state.selectedRuntimeId)
    val opened = state.selectedSessionId ?: return
    val archived = state.sessions.firstOrNull { it.id == opened }?.state == "archived"
    val canCompose = !archived && state.outbox != null && runtime?.access?.role in setOf("operator", "owner") && runtime?.access?.scope?.actions?.containsAll(setOf("message.submit", "command.status")) == true
    var showDetails by remember(opened) { mutableStateOf(false) }
    var detailSection by remember(opened) { mutableStateOf(ChatDetailSection.INFO) }
    var detailRequestId by remember(opened) { mutableStateOf<String?>(null) }
    var cancelConfirmEpoch by remember(opened) { mutableStateOf<String?>(null) }
    var taskMenu by remember(opened) { mutableStateOf(false) }
    var fullEditor by remember(state.composer?.resource) { mutableStateOf(false) }
    var quoteTooLarge by remember(state.composer?.resource) { mutableStateOf(false) }
    var pendingMenu by remember(opened) { mutableStateOf(false) }
    var requestedAnchor by remember(opened) { mutableStateOf<String?>(null) }
    var targetGone by remember(opened) { mutableStateOf(false) }
    val keyboard = LocalSoftwareKeyboardController.current
    val imeVisible = WindowInsets.isImeVisible
    val leaveDetails = { showDetails = false; detailSection = ChatDetailSection.INFO; detailRequestId = null }
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
    val focusedQuestion = read.questions.items.firstOrNull { it.handle == state.notificationQuestion }
    val visibleQuestions = read.questions.items.takeIf { read.phase == SessionReadPhase.READY && !archived }.orEmpty()
    val pendingQuestions = visibleQuestions.filter { it.answerable }
    val approvalView = state.approvals?.takeIf {
        !archived && runtime?.access?.role == "owner" && runtime.access.scope?.actions?.containsAll(setOf("session.read", "approval.decide")) == true
    }
    val pendingApprovals = approvalView?.view?.items.orEmpty().filter { it.canReview || it.handle != null || it.remainingMillis > 0 && it.status.state in setOf(ApprovalRemoteState.PENDING, ApprovalRemoteState.DECISION_RECEIVED) }
    val pendingOriginals = state.outbox?.records.orEmpty().filter { it.remote !in setOf(RemoteCommandState.SETTLED, RemoteCommandState.REJECTED, RemoteCommandState.AGENT_QUEUED) }
    val chatKeys = if (requestedAnchor == null) emptyList() else buildList {
        if (read.phase != SessionReadPhase.READY || read.cacheError != null) add("connection")
        if (state.notificationNote != null) add("notification-note")
        if (focusedQuestion != null && visibleQuestions.any { it.handle == focusedQuestion.handle }) add(questionAnchor(focusedQuestion.handle))
        if (approvalView?.error != null) add("approval-error")
        pendingApprovals.forEach { add(approvalAnchor(it)) }
        visibleQuestions.filter { it.handle != focusedQuestion?.handle }.forEach { add(questionAnchor(it.handle)) }
        if (read.questions.error != null && read.phase == SessionReadPhase.READY && !archived) add("question-error")
    }
    LaunchedEffect(requestedAnchor, chatKeys, showDetails) {
        val anchor = requestedAnchor ?: return@LaunchedEffect
        val index = chatKeys.indexOf(anchor)
        if (showDetails || index < 0) targetGone = true else chatListState.scrollToItem(index)
        requestedAnchor = null
    }
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
    LaunchedEffect(canCancel, cancelEpoch) { if (!canCancel || cancelConfirmEpoch != null && cancelConfirmEpoch != cancelEpoch) cancelConfirmEpoch = null }
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
    MediaPickerEffect(state.documentPicker, onPickedFile)
    state.images?.let { MessageMediaPreview(it, onDismissImagePreview) }
    state.exportSavePicker?.let { pending -> key(pending.id) {
        var launched by rememberSaveable { mutableStateOf(false) }
        val picker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri -> onExportDestination(pending.id, uri) }
        LaunchedEffect(pending.id) { if (!launched) { launched = true; picker.launch(exportSuggestedName(pending.name)) } }
    } }
    Scaffold(
        topBar = {
            cn.edu.ustc.dsh.ui.DshTopBar(
                title = if (!showDetails) stringResource(R.string.chat_title, opened.take(8)) else when (detailSection) {
                    ChatDetailSection.INFO -> stringResource(R.string.chat_details)
                    ChatDetailSection.FILES -> stringResource(R.string.chat_files)
                    ChatDetailSection.IMAGES -> stringResource(R.string.session_actions_images)
                    ChatDetailSection.COMMANDS -> stringResource(R.string.chat_original_records)
                },
                subtitle = if (read.phase == SessionReadPhase.READY) stringResource(R.string.chat_live_subtitle, runtime?.hostAlias ?: stringResource(R.string.chat_authorized_computer))
                    else runtime?.hostAlias ?: stringResource(R.string.chat_authorized_computer),
                navigationIcon = {
                    IconButton(returnFromChat) {
                        Icon(painterResource(R.drawable.ic_back), contentDescription = stringResource(if (showDetails) R.string.chat_messages else if (state.knownTarget != null) R.string.chat_back_reminders else R.string.chat_back))
                    }
                },
                actions = {
                    if (!showDetails) {
                        IconButton({ openDetails(ChatDetailSection.INFO, null) }, Modifier.size(48.dp)) {
                            Icon(painterResource(R.drawable.ic_info), contentDescription = stringResource(R.string.chat_details))
                        }
                        Box {
                            IconButton({ taskMenu = true }, Modifier.size(48.dp)) {
                                Icon(painterResource(R.drawable.ic_more), contentDescription = stringResource(R.string.chat_task_more))
                            }
                            DropdownMenu(taskMenu, { taskMenu = false }) {
                                DropdownMenuItem(text = { Text(stringResource(R.string.chat_files)) }, onClick = { taskMenu = false; openDetails(ChatDetailSection.FILES, null) })
                                DropdownMenuItem(text = { Text(stringResource(R.string.chat_original_records)) }, onClick = { taskMenu = false; openDetails(ChatDetailSection.COMMANDS, null) })
                                if (onModels != null) DropdownMenuItem(text = { Text(stringResource(R.string.models_open)) },
                                    enabled = state.modelCatalog != null, onClick = { taskMenu = false; onModels() })
                                if (onChanges != null && state.changes != null) DropdownMenuItem(text = { Text(stringResource(R.string.session_actions_changes)) },
                                    onClick = { taskMenu = false; onChanges() })
                                if (state.images != null) DropdownMenuItem(text = { Text(stringResource(R.string.session_actions_images)) },
                                    onClick = { taskMenu = false; openDetails(ChatDetailSection.IMAGES, null) })
                            }
                        }
                    }
                },
            )
        },
    ) { insets ->
        Column(Modifier.fillMaxSize().padding(insets).consumeWindowInsets(insets).imePadding(), horizontalAlignment = Alignment.CenterHorizontally) {
            LazyColumn(Modifier.widthIn(max = 800.dp).fillMaxWidth().weight(1f).testTag("chat-list"), state = listState, contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
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
                    if (!showDetails && read.phase == SessionReadPhase.READY && !archived && focusedQuestion != null) item(questionAnchor(focusedQuestion.handle)) {
                        QuestionCard(focusedQuestion, read.questions.canAnswer, state.submitting, state.outbox?.records ?: emptyList(), onAnswer, onClaim, onRelease, onRefreshQuestions, onQueryCommands)
                    }

                    fun LazyListScope.archiveGroup() {
                        if (!showDetails || detailSection != ChatDetailSection.INFO || !(archived || runtime?.access?.scope?.actions?.contains("session.archive") == true)) return
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
                        if (!showDetails) items(pending, key = { approvalAnchor(it) }) { view ->
                            OutlinedCard(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                Text("待处理工具审批", style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
                                Text("先在线核对完整动作与参数，再为本次调用作出决定。")
                                view.context?.let { context ->
                                    Text("工具：${approvalVisibleText(context.root.string("tool"))}", style = MaterialTheme.typography.bodyMedium)
                                    Text("工作区：${context.root.obj("workspace").string("workspace_id")}", style = MaterialTheme.typography.bodySmall)
                                    Text("资源 ${context.root.array("resources").size} 项 · 摘要不替代完整核对", style = MaterialTheme.typography.bodySmall)
                                }
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
                        if (!showDetails || detailSection != ChatDetailSection.FILES) return
                        val files = state.uploads?.takeIf { !archived && canCompose }
                        if (files == null) {
                            if (detailSection == ChatDetailSection.FILES) item("uploads-unavailable") {
                                Text(stringResource(R.string.chat_attachments_unavailable), color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            return
                        }
                        item("uploads") {
                            UploadsPanel(files.copy(rows = files.rows.filter { it.stored.intent.image == null }), state.outbox?.canAttachFiles == true && read.phase == SessionReadPhase.READY,
                                onPickFile, onToggleFile, onQueryFile, onRemoveFile, onCancelFile)
                        }
                    }
                    fun LazyListScope.imagesGroup() {
                        if (!showDetails || detailSection != ChatDetailSection.IMAGES) return
                        state.images?.let { imageState -> item("images") {
                            SessionImagesPanel(imageState, state.uploads,
                                canCompose && state.outbox?.canAttachImages == true && read.phase == SessionReadPhase.READY,
                                onPickImage, onPickCamera, onToggleFile, onQueryFile, onRemoveFile, onCancelImage, onDismissImagePreview, onReselectImage)
                        } }
                    }
                    fun LazyListScope.exportsGroup() {
                        if (!showDetails || detailSection != ChatDetailSection.FILES) return
                        state.exports?.let { exports -> item("exports") { ExportsPanel(exports, onBrowseExports, onExport, onQueryExports, onCancelExport, onRemoveExport, onSaveExport, state.exportSaving || state.exportSavePicker != null) } }
                    }
                    fun LazyListScope.exportStatusGroup() {
                        if (!showDetails || detailSection != ChatDetailSection.FILES || !(state.exportSaving || state.exportSaved || state.exportSaveError != null)) return
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
                        if (!showDetails || detailSection != ChatDetailSection.COMMANDS) return
                        val target = detailRequestId.takeIf { detailSection == ChatDetailSection.COMMANDS }
                        val ordered = outbox.records.sortedWith(
                            compareBy<PendingCommand> { if (target != null && it.intent.requestId == target) 0 else 1 }
                                .thenByDescending { it.createdAt }.thenByDescending { it.intent.requestId })
                        if (target != null && ordered.none { it.intent.requestId == target }) item("original-unavailable") { Text(stringResource(R.string.chat_target_gone), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
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
                                    if (!record.everAgentQueued) record.intent.text()?.let { RichMessageText(it, 512) }
                                    if (record.intent.fileIds().isNotEmpty()) Text("附件 ${record.intent.fileIds().size} 个；状态以原请求为准。", style = MaterialTheme.typography.bodySmall)
                                    if(record.intent.kind.question) SubmittedQuestionAnswer(record.intent)
                                    record.intent.modelSelection()?.let { selection ->
                                        SelectionContainer { Text("${selection.providerId}\n${selection.modelId}" +
                                            (selection.reasoningEffortId?.let { "\n$it" } ?: "")) }
                                        Text(stringResource(R.string.models_checkpoint_scope), style = MaterialTheme.typography.bodySmall)
                                    }
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
                        if (!showDetails || detailSection != ChatDetailSection.INFO || !(canCancel || pendingCancel != null)) return
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
                        when (detailSection) {
                            ChatDetailSection.INFO -> {
                                item("session-info") {
                                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                        Text(stringResource(R.string.chat_details), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
                                        SelectionContainer { Text("会话：$opened\n电脑：${runtime?.hostId.orEmpty()}\n运行环境：${state.selectedRuntimeId.orEmpty()}") }
                                        state.sessions.firstOrNull { it.id == opened }?.let { session ->
                                            Text("目录状态：${session.state}")
                                            SelectionContainer { Text("工作区：${session.workspaceId ?: "目录未提供"}") }
                                            Text("目录已保存序号：${session.lastPersisted}", style = MaterialTheme.typography.bodySmall)
                                            Text("目录更新时间：${java.time.Instant.ofEpochMilli(session.updatedAt)}", style = MaterialTheme.typography.bodySmall)
                                        } ?: Text("尚未取得当前会话的目录信息。", style = MaterialTheme.typography.bodySmall)
                                        TextButton(onRefresh, Modifier.heightIn(min = 48.dp)) { Text("刷新会话信息") }
                                        TextButton({ openDetails(ChatDetailSection.FILES, null) }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_files)) }
                                        TextButton({ openDetails(ChatDetailSection.COMMANDS, null) }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_original_records)) }
                                    }
                                }
                                archiveGroup()
                                cancelGroup()
                            }
                            ChatDetailSection.FILES -> { uploadsGroup(); exportsGroup(); exportStatusGroup() }
                            ChatDetailSection.IMAGES -> imagesGroup()
                            ChatDetailSection.COMMANDS -> { commandGroup(); approvalGroup() }
                        }
                    } else {
                        approvalGroup()
                        if (read.phase == SessionReadPhase.READY && !archived) {
                            items(visibleQuestions.filter { it.handle != focusedQuestion?.handle },key={questionAnchor(it.handle)}) {question->
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
                        items(transcript.items, key = { it.id }) { entry -> ConversationMessage(entry, state.composer?.takeIf { canCompose }?.let { draft -> { quote ->
                            val quoted = draft.withLocalQuote(quote)
                            if (quoted.value.text.length <= 65_536) onComposerChange(quoted) else quoteTooLarge = true
                        } },
                            onMessageAction = onMessageAction.takeIf { state.messageActions?.canPreview == true },
                            onPreviewMedia = onPreviewMedia.takeIf { read.phase == SessionReadPhase.READY && runtime?.access?.scope?.actions?.contains("file.download") == true }) }
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
            if (!showDetails) Column {
                if (initialized && (!followLatest || newMessages)) {
                    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
                        Box(Modifier.widthIn(max = 800.dp).fillMaxWidth().padding(horizontal = 16.dp)) {
                            FilledTonalButton(
                                onClick = {
                                    followLatest = true
                                    readingPosition?.following = true
                                    newMessages = false
                                    scope.launch { chatListState.animateScrollToItem((chatListState.layoutInfo.totalItemsCount - 1).coerceAtLeast(0)) }
                                },
                                modifier = Modifier.align(Alignment.CenterEnd).heightIn(min = 48.dp),
                            ) { Text(stringResource(if (newMessages) R.string.chat_new_messages else R.string.chat_latest)) }
                        }
                    }
                }
                if (pendingQuestions.isNotEmpty() || pendingApprovals.isNotEmpty() || pendingOriginals.isNotEmpty()) Box {
                    val blocking = pendingQuestions.count { it.handle.kind == QuestionKind.BLOCKING }
                    val timed = pendingQuestions.size - blocking
                    TextButton({ pendingMenu = true }, Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                        Text(stringResource(R.string.chat_pending_counts, blocking, timed, pendingApprovals.size, pendingOriginals.size))
                    }
                    DropdownMenu(pendingMenu, { pendingMenu = false }) {
                        pendingQuestions.forEach { question ->
                            DropdownMenuItem(text = { Text("${if (question.handle.kind == QuestionKind.BLOCKING) "待答提问" else "限时提问"} · ${question.batch.prompts.first().question}", maxLines = 2, overflow = TextOverflow.Ellipsis) }, onClick = {
                                pendingMenu = false; followLatest = false; targetGone = false; requestedAnchor = questionAnchor(question.handle)
                            })
                        }
                        pendingApprovals.forEach { approval ->
                            DropdownMenuItem(text = { Text("工具审批 · ${approval.status.id}") }, onClick = {
                                pendingMenu = false; followLatest = false; targetGone = false; requestedAnchor = approvalAnchor(approval)
                            })
                        }
                        pendingOriginals.forEach { original ->
                            DropdownMenuItem(text = { Text("原请求 · ${original.intent.requestId}") }, onClick = { pendingMenu = false; openDetails(ChatDetailSection.COMMANDS, original.intent.requestId) })
                        }
                    }
                }
                if (targetGone) Text(stringResource(R.string.chat_target_gone), modifier = Modifier.padding(horizontal = 16.dp).semantics { liveRegion = LiveRegionMode.Polite })
                if (canCompose && !fullEditor) state.composer?.let { draft -> SessionComposer(state, onSubmit, draft, onComposerChange,
                    onAttach = { onPickFile(null) }, onRemove = onToggleFile,
                    onViewAttachments = { openDetails(ChatDetailSection.FILES, null) }, onExpand = { fullEditor = true }, onResolveFailure = onResolveFailedInput) }
            }
        }
    }
    if (fullEditor && canCompose) state.composer?.let { draft ->
        Dialog(onDismissRequest = { if (imeVisible) keyboard?.hide() else fullEditor = false }, properties = DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false)) {
            Surface(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing).imePadding()) {
                SessionComposer(state, onSubmit, draft, onComposerChange, { onPickFile(null) }, onToggleFile,
                    { fullEditor = false; openDetails(ChatDetailSection.FILES, null) }, expanded = true, onExpand = { fullEditor = false }, onResolveFailure = onResolveFailedInput)
            }
        }
    }
    if (quoteTooLarge) AlertDialog(onDismissRequest = { quoteTooLarge = false }, title = { Text(stringResource(R.string.chat_quote_too_large)) },
        confirmButton = { TextButton({ quoteTooLarge = false }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.action_close)) } })
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

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ChatOperationFooter(summary: PendingCommand?, error: String?, canCancel: Boolean, pendingCancel: PendingCommand?,
    onViewDelivery: () -> Unit, onViewCancel: () -> Unit, onCancel: () -> Unit) {
    Surface(color = MaterialTheme.colorScheme.surfaceContainerLow, shape = MaterialTheme.shapes.medium) {
        Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            val sameCancel = summary != null && summary.intent.requestId == pendingCancel?.intent?.requestId
            if (summary != null) {
                FlowRow(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(R.string.chat_footer_title), style = MaterialTheme.typography.labelLarge,
                        modifier = Modifier.align(Alignment.CenterVertically).semantics { heading() })
                    TextButton(if (sameCancel) onViewCancel else onViewDelivery, Modifier.heightIn(min = 48.dp)) {
                        Text(stringResource(if (sameCancel) R.string.chat_view_cancel_original else R.string.chat_view_delivery))
                    }
                }
                Text(stringResource(commandLabel(summary)), style = MaterialTheme.typography.bodyMedium)
                if (needsDeliveryReconciliation(summary) && summary.remote != null && summary.remote != RemoteCommandState.OUTCOME_UNKNOWN) {
                    Text(stringResource(R.string.chat_original_reconcile), style = MaterialTheme.typography.bodySmall)
                }
                if (summary.intent.kind == CommandKind.MESSAGE && summary.remote == RemoteCommandState.SETTLED) {
                    Text(stringResource(R.string.chat_delivery_settled_note), style = MaterialTheme.typography.bodySmall)
                }
                if (sameCancel) Text(stringResource(R.string.chat_cancel_pending), style = MaterialTheme.typography.bodySmall)
            }
            if (error != null) Text(commandErrorText(error), color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            if (pendingCancel != null && !sameCancel) {
                Text(stringResource(R.string.chat_cancel_pending), style = MaterialTheme.typography.bodyMedium)
                TextButton(onViewCancel, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_view_cancel_original)) }
            }
            if (canCancel) OutlinedButton(onCancel, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("中断当前任务") }
        }
    }
}


@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SessionComposer(
    state: HomeState, onSubmit: (MessageSubmission) -> Unit, draft: MessageComposerState,
    onEdit: (MessageComposerState) -> Unit, onAttach: () -> Unit, onRemove: (String) -> Unit,
    onViewAttachments: () -> Unit, expanded: Boolean = false, onExpand: () -> Unit,
    onResolveFailure: (MessageComposerState, Boolean) -> Unit,
) {
    val text = draft.value.text
    val mode = draft.mode
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
    var rejectedInput by remember(draft.resource) { mutableStateOf(false) }
    val attachmentAvailable = online && state.outbox?.canAttachFiles == true && state.uploads != null
    Surface(tonalElevation = 3.dp, modifier = Modifier.testTag("message-composer").then(if (expanded) Modifier.fillMaxSize() else Modifier)) {
        Column(Modifier.fillMaxWidth().then(if (expanded) Modifier.fillMaxHeight() else Modifier).padding(horizontal = 8.dp, vertical = 4.dp)) {
            Column(Modifier.weight(1f, fill = false).verticalScroll(rememberScrollState())) {
                state.failedInput?.takeIf { it.resource == draft.resource }?.let { original ->
                    FailedMessageInput(original, !state.submitting, onResolveFailure)
                }
                FlowRow(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    Box {
                        TextButton({ menu = true }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(if (mode == "queue") R.string.chat_queue else R.string.chat_steer)) }
                        DropdownMenu(menu, { menu = false }) {
                            DropdownMenuItem(text = { Column { Text(stringResource(R.string.chat_queue)); Text(stringResource(R.string.chat_queue_desc), style = MaterialTheme.typography.bodySmall) } }, onClick = { menu = false; onEdit(draft.copy(mode = "queue")) })
                            DropdownMenuItem(text = { Column { Text(stringResource(R.string.chat_steer)); Text(stringResource(R.string.chat_steer_desc), style = MaterialTheme.typography.bodySmall) } }, onClick = { menu = false; onEdit(draft.copy(mode = "steer")) })
                        }
                    }
                    TextButton({ if (attachmentAvailable) onAttach() else explainAttachments = true }, enabled = state.uploads?.busy != true, modifier = Modifier.heightIn(min = 48.dp)) {
                        Text(stringResource(if (attachmentAvailable) R.string.chat_attach else R.string.chat_attach_unavailable))
                    }
                    TextButton(onExpand, Modifier.heightIn(min = 48.dp)) { Text(stringResource(if (expanded) R.string.chat_editor_compact else R.string.chat_editor_expand)) }
                }
                if (selected.isNotEmpty()) {
                    Text(stringResource(R.string.chat_attachment_count, attachments.size), style = MaterialTheme.typography.bodySmall)
                    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        selected.forEach { upload ->
                            val name = upload.stored.intent.manifest.name
                            val size = upload.stored.intent.manifest.sizeBytes
                            val removeName = stringResource(R.string.chat_remove_selection, name)
                            val detailName = stringResource(R.string.chat_attachment_detail_action, name)
                            Column(Modifier.widthIn(max = 240.dp)) {
                                Text(name, style = MaterialTheme.typography.bodyMedium, maxLines = 2, overflow = TextOverflow.Ellipsis)
                                Text(fileSizeText(size), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Row {
                                    TextButton({ onRemove(upload.stored.intent.requestId) }, Modifier.heightIn(min = 48.dp).semantics {
                                        contentDescription = removeName
                                    }, contentPadding = PaddingValues(horizontal = 8.dp)) {
                                        Text(stringResource(R.string.chat_remove_attachment))
                                    }
                                    TextButton({ attachmentDetail = name to size }, Modifier.heightIn(min = 48.dp).semantics {
                                        contentDescription = detailName
                                    }, contentPadding = PaddingValues(horizontal = 8.dp)) {
                                        Text(stringResource(R.string.chat_attachment_detail))
                                    }
                                }
                            }
                        }
                    }
                    TextButton(onViewAttachments, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_view_attachments)) }
                }
            }
            val inputLabel = stringResource(R.string.chat_input)
            Row(Modifier.fillMaxWidth().then(if (expanded) Modifier.weight(1f) else Modifier), verticalAlignment = Alignment.Bottom, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                OutlinedTextField(draft.value, { value ->
                    if (value.text.length > 65_536) rejectedInput = true
                    else { rejectedInput = false; onEdit(draft.copy(value = value)) }
                }, label = { Text(inputLabel) },
                    minLines = 1, maxLines = if (expanded) Int.MAX_VALUE else 5, isError = rejectedInput || text.isNotBlank() && !textValid,
                    modifier = Modifier.weight(1f).then(if (expanded) Modifier.fillMaxHeight() else Modifier))
                val action = stringResource(if (state.submitting) R.string.chat_saving else if (!online) R.string.chat_save_pending else if (mode == "queue") R.string.chat_send_queue else R.string.chat_send_steer)
                Button({ onSubmit(MessageSubmission(draft, online)) }, enabled = valid && !rejectedInput && !state.submitting,
                    modifier = Modifier.heightIn(min = 48.dp).semantics { contentDescription = action }, contentPadding = PaddingValues(horizontal = 12.dp)) {
                    Text(action)
                }
            }
            if (state.submitting) Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                Text(stringResource(R.string.chat_saving_request), style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            }
            if (!attachmentsReady) Text(stringResource(R.string.chat_attachment_not_ready), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            if (rejectedInput) {
                val rejection = stringResource(R.string.chat_input_rejected)
                Text(rejection, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.semantics { error(rejection); liveRegion = LiveRegionMode.Polite })
            } else if (text.isNotBlank() && !textValid) Text(stringResource(R.string.chat_invalid), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            if (!online) Text(stringResource(R.string.chat_offline), style = MaterialTheme.typography.bodySmall)
        }
    }
    attachmentDetail?.let { (name, size) ->
        AlertDialog(onDismissRequest = { attachmentDetail = null }, title = { Text(stringResource(R.string.chat_attachment_detail)) },
            text = { Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
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
