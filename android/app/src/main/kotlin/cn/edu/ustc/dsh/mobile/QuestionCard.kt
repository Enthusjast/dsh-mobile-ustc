package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*

private class AnswerDraft(val selected: Set<String> = emptySet(), val custom: String = "") {
    override fun toString() = "AnswerDraft"
}

/** Opening is explicit, including notification-focused entries. Summary composition never claims time. */
@Composable
fun QuestionCard(view: PresentedQuestion, canAnswer: Boolean, submitting: Boolean, records: List<PendingCommand>,
    onAnswer: (QuestionHandle, QuestionAnswers) -> Unit, onClaim: (QuestionHandle) -> Unit, onRelease: (QuestionHandle) -> Unit, onRefresh: () -> Unit, onQuery: () -> Unit) {
    val batch = view.batch
    val handle = view.handle
    var expanded by remember(handle) { mutableStateOf(false) }
    val pending = records.lastOrNull {
        it.intent.kind.question && it.intent.payload.string("question_id") == batch.id &&
            it.intent.questionDefinition == batch.definition && it.remote != RemoteCommandState.REJECTED
    }
    val enabled = canAnswer && view.answerable && !submitting && pending == null
    val plan = batch.prompts.any { it.planApproval != null }
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.question_needs_reply), style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.semantics { heading() })
            QuestionKindLabel(batch)
            Text(batch.prompts.first().question, maxLines = 2, overflow = TextOverflow.Ellipsis,
                style = MaterialTheme.typography.bodyMedium)
            QuestionStatus(view)
            OutlinedButton(onClick = {
                expanded = true
                if (enabled && batch.kind == QuestionKind.TIMED && batch.phase == QuestionPhase.OPEN) onClaim(handle)
            }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                Text(stringResource(if (canAnswer) R.string.question_open_answer else R.string.question_open_readonly))
            }
        }
    }
    if (expanded) {
        // The form owns volatile drafts and one release. Closing, removal and handle retirement all dispose it.
        val release by rememberUpdatedState(onRelease)
        DisposableEffect(handle) { onDispose { release(handle) } }
        key(handle) {
            QuestionForm(view, canAnswer, submitting, pending, enabled, plan, onAnswer,
                onClose = { expanded = false }, onRefresh = onRefresh, onQuery = onQuery)
        }
    }
}

@Composable
private fun QuestionKindLabel(batch: QuestionBatch) {
    Text(stringResource(when {
        batch.prompts.any { it.planApproval != null } -> R.string.question_kind_plan
        batch.kind == QuestionKind.TIMED -> R.string.question_kind_timed
        else -> R.string.question_kind_ordinary
    }), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.semantics { heading() })
    if (batch.kind == QuestionKind.TIMED && batch.prompts.any { it.planApproval != null }) {
        Text(stringResource(R.string.question_kind_timed), style = MaterialTheme.typography.labelMedium)
    }
}

@Composable
private fun QuestionStatus(view: PresentedQuestion) {
    val remaining = view.remainingMillis
    Text(when {
        view.batch.phase == QuestionPhase.REPLY_QUEUED -> stringResource(R.string.question_status_queued)
        view.batch.phase == QuestionPhase.CONTINUED -> stringResource(R.string.question_status_continued)
        !view.answerable -> stringResource(R.string.question_status_unavailable)
        view.batch.kind == QuestionKind.BLOCKING -> stringResource(R.string.question_status_blocking)
        view.claim?.phase == ClaimPhase.PENDING -> stringResource(R.string.question_status_claiming)
        remaining != null -> stringResource(R.string.question_status_remaining, (remaining + 999) / 1000)
        else -> stringResource(R.string.question_status_unknown_time)
    }, style = MaterialTheme.typography.bodySmall,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
}

/** One full-height scroll surface keeps long and multi-prompt forms usable at large font sizes. */
@Composable
private fun QuestionForm(view: PresentedQuestion, canAnswer: Boolean, submitting: Boolean, pending: PendingCommand?,
    enabled: Boolean, plan: Boolean, onAnswer: (QuestionHandle, QuestionAnswers) -> Unit,
    onClose: () -> Unit, onRefresh: () -> Unit, onQuery: () -> Unit) {
    val batch = view.batch
    var drafts by remember { mutableStateOf(batch.prompts.associate { it.id to AnswerDraft() }) }
    var reviewed by remember { mutableStateOf(emptySet<String>()) }
    val answers = runCatching {
        QuestionAnswers(batch.id, batch.prompts.map { prompt ->
            val draft = drafts.getValue(prompt.id)
            QuestionAnswer(prompt.id, draft.selected.toList(), draft.custom.takeIf { it.isNotEmpty() })
        })
    }.getOrNull()
    val valid = answers != null && runCatching { batch.validate(answers) }.isSuccess
    val reviewing = batch.prompts.any { prompt ->
        val draft = drafts.getValue(prompt.id)
        prompt.planApproval != null && (prompt.planApproval in draft.selected || draft.custom.trim() == prompt.planApproval) && prompt.id !in reviewed
    }
    Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false, dismissOnClickOutside = false)) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.surface) {
            Column(Modifier.fillMaxSize()) {
                cn.edu.ustc.dsh.ui.DshTopBar(
                    title = stringResource(when {
                        plan -> R.string.question_kind_plan
                        batch.kind == QuestionKind.TIMED -> R.string.question_kind_timed
                        else -> R.string.question_kind_ordinary
                    }),
                    subtitle = if (batch.kind == QuestionKind.TIMED && plan) stringResource(R.string.question_kind_timed) else null,
                    navigationIcon = { IconButton(onClose, Modifier.heightIn(min = 48.dp)) {
                        Icon(androidx.compose.ui.res.painterResource(R.drawable.ic_back), stringResource(R.string.question_close))
                    } },
                )
                HorizontalDivider()
                Column(Modifier.weight(1f).fillMaxWidth()
                    .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal + WindowInsetsSides.Bottom))
                    .imePadding().verticalScroll(rememberScrollState()).padding(cn.edu.ustc.dsh.ui.DshSpacing.page),
                    verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    if (plan) Text(stringResource(R.string.question_plan_not_approval), style = MaterialTheme.typography.bodyMedium)
                    QuestionStatus(view)
                    batch.prompts.forEachIndexed { index, prompt -> key(prompt.id) {
                        if (index > 0) HorizontalDivider()
                        Text(stringResource(R.string.question_prompt_position, index + 1, batch.prompts.size),
                            style = MaterialTheme.typography.labelLarge, modifier = Modifier.semantics { heading() })
                        prompt.header?.takeIf { it.isNotBlank() }?.let { Text(it, style = MaterialTheme.typography.titleSmall) }
                        val questionComplete = QuestionText(prompt.question)
                        val detailComplete = prompt.detail?.let { detail ->
                            Text(stringResource(if (prompt.planApproval != null) R.string.question_plan_detail else R.string.question_detail),
                                style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
                            QuestionText(detail)
                        } ?: true
                        if (prompt.planApproval != null) {
                            val complete = questionComplete && detailComplete
                            Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).toggleable(
                                value = prompt.id in reviewed, enabled = enabled && complete, role = Role.Checkbox,
                                onValueChange = { checked -> reviewed = if (checked) reviewed + prompt.id else reviewed - prompt.id }
                            ), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Checkbox(prompt.id in reviewed, onCheckedChange = null, enabled = enabled && complete)
                                Text(stringResource(R.string.question_plan_reviewed), Modifier.weight(1f))
                            }
                            if (!complete) Text(stringResource(R.string.question_plan_expand_first), style = MaterialTheme.typography.bodySmall)
                        }
                        Text(stringResource(when {
                            prompt.options.isEmpty() -> R.string.question_mode_text
                            prompt.multiSelect -> R.string.question_mode_multiple
                            else -> R.string.question_mode_single
                        }), style = MaterialTheme.typography.labelMedium)
                        val draft = drafts.getValue(prompt.id)
                        fun toggle(label: String) {
                            val selected = if (prompt.multiSelect) {
                                if (label in draft.selected) draft.selected - label else draft.selected + label
                            } else if (label in draft.selected) emptySet() else setOf(label)
                            drafts = drafts + (prompt.id to AnswerDraft(selected, draft.custom))
                        }
                        Column(if (prompt.multiSelect) Modifier else Modifier.selectableGroup()) {
                            for (option in prompt.options) key(option.label) {
                                val optionEnabled = enabled && (option.label != prompt.planApproval || prompt.id in reviewed)
                                val selected = option.label in draft.selected
                                val selection = if (prompt.multiSelect) Modifier.toggleable(selected, enabled = optionEnabled,
                                    role = Role.Checkbox, onValueChange = { toggle(option.label) })
                                else Modifier.selectable(selected, enabled = optionEnabled, role = Role.RadioButton,
                                    onClick = { toggle(option.label) })
                                Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).then(selection).padding(vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    if (prompt.multiSelect) Checkbox(selected, onCheckedChange = null, enabled = optionEnabled)
                                    else RadioButton(selected, onClick = null, enabled = optionEnabled)
                                    Column(Modifier.weight(1f)) {
                                        Text(option.label)
                                        option.description?.let { QuestionText(it) }
                                    }
                                }
                            }
                        }
                        OutlinedTextField(draft.custom, { value ->
                            if (value.length <= 16_384) drafts = drafts + (prompt.id to AnswerDraft(draft.selected, value))
                        }, enabled = enabled, label = {
                            Text(stringResource(if (prompt.options.isEmpty()) R.string.question_answer_label else R.string.question_custom_label, prompt.id))
                        }, minLines = 1, maxLines = 6, modifier = Modifier.fillMaxWidth())
                        if (batch.kind == QuestionKind.TIMED) Text(stringResource(R.string.question_optional), style = MaterialTheme.typography.bodySmall)
                    } }
                    if (!canAnswer) Text(stringResource(R.string.question_readonly), style = MaterialTheme.typography.bodySmall)
                    if (batch.kind == QuestionKind.TIMED && batch.phase == QuestionPhase.OPEN) {
                        Text(stringResource(R.string.question_timed_late), style = MaterialTheme.typography.bodySmall)
                    }
                    if (pending != null) {
                        Text(stringResource(when {
                            pending.remote == RemoteCommandState.SETTLED -> R.string.question_original_confirmed
                            pending.everAgentQueued -> R.string.question_original_queued
                            else -> R.string.question_original_unknown
                        }), style = MaterialTheme.typography.bodySmall)
                        OutlinedButton(onQuery, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.question_query_original)) }
                    }
                    if (reviewing) Text(stringResource(R.string.question_plan_review_first), style = MaterialTheme.typography.bodySmall)
                    Button(onClick = { if (enabled && valid && !reviewing && answers != null) onAnswer(view.handle, answers) },
                        enabled = enabled && valid && !reviewing, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                        Text(stringResource(when {
                            submitting -> R.string.question_saving
                            batch.phase == QuestionPhase.CONTINUED -> R.string.question_send_continued
                            plan -> R.string.question_send_plan
                            else -> R.string.question_send
                        }))
                    }
                    OutlinedButton(onClose, Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.question_not_now)) }
                    Text(stringResource(R.string.question_close_explanation), style = MaterialTheme.typography.bodySmall)
                    TextButton(onRefresh, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.question_refresh)) }
                }
            }
        }
    }
}

/** Large plans stay readable without silently authorizing hidden details. */
@Composable
private fun QuestionText(text: String): Boolean {
    var limit by remember(text) { mutableIntStateOf(8192) }
    val end = minOf(limit, text.length).let {
        if (it in 1 until text.length && text[it - 1].isHighSurrogate() && text[it].isLowSurrogate()) it - 1 else it
    }
    Text(text.substring(0, end), style = MaterialTheme.typography.bodyLarge)
    if (end < text.length) TextButton({ limit = (limit + 8192).coerceAtMost(text.length) }, Modifier.heightIn(min = 48.dp)) {
        Text(stringResource(R.string.question_show_more))
    }
    return end == text.length
}

@Composable
fun SubmittedQuestionAnswer(intent: CommandIntent) {
    val payload = QuestionAnswers.parse(intent.payload)
    Text(stringResource(R.string.question_submitted_id, payload.questionId.take(8)), style = MaterialTheme.typography.bodySmall)
    payload.values.forEach { answer ->
        Text(answer.id, style = MaterialTheme.typography.labelMedium)
        answer.selected.forEach { QuestionText(it) }
        answer.custom?.let { QuestionText(it) }
        if (answer.selected.isEmpty() && answer.custom.isNullOrEmpty()) Text(stringResource(R.string.question_answer_empty), style = MaterialTheme.typography.bodySmall)
    }
}
