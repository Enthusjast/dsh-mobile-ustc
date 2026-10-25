package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*

private class AnswerDraft(val selected: Set<String> = emptySet(),val custom: String="") {override fun toString()="AnswerDraft"}

@Composable
fun QuestionCard(view: PresentedQuestion,canAnswer: Boolean,submitting: Boolean,records: List<PendingCommand>,
    onAnswer: (QuestionHandle,QuestionAnswers)->Unit,onClaim: (QuestionHandle)->Unit,onRelease: (QuestionHandle)->Unit,onRefresh: ()->Unit,onQuery: ()->Unit) {
    val batch=view.batch;val handle=view.handle
    var expanded by remember(handle) {mutableStateOf(false)}
    var drafts by remember(handle) {mutableStateOf(batch.prompts.associate {it.id to AnswerDraft()})}
    var reviewed by remember(handle) {mutableStateOf(emptySet<String>())}
    val matching=records.filter {it.intent.kind.question && it.intent.payload.string("question_id")==batch.id && it.intent.questionDefinition==batch.definition}
    val pending=matching.lastOrNull {it.remote!=RemoteCommandState.REJECTED}
    val answers=runCatching {QuestionAnswers(batch.id,batch.prompts.map {prompt->val draft=drafts.getValue(prompt.id);QuestionAnswer(prompt.id,draft.selected.toList(),draft.custom.takeIf {it.isNotEmpty()})})}.getOrNull()
    val valid=answers!=null && runCatching {batch.validate(answers)}.isSuccess
    val reviewing=batch.prompts.any {prompt->val draft=drafts.getValue(prompt.id);prompt.planApproval!=null && (prompt.planApproval in draft.selected || draft.custom.trim()==prompt.planApproval) && prompt.detail!=null && prompt.id !in reviewed}
    val enabled=canAnswer && view.answerable && !submitting && pending==null
    val remaining=view.remainingMillis
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(12.dp)) {
            Text(if(batch.prompts.any {it.planApproval!=null}) "计划确认" else "电脑提问",style=MaterialTheme.typography.titleMedium,modifier=Modifier.semantics {heading()})
            if(batch.prompts.any {it.planApproval!=null}) Text("这是对助手的计划答复，不是工具执行批准。",style=MaterialTheme.typography.bodySmall)
            Text(when {
                batch.phase==QuestionPhase.REPLY_QUEUED->"后续答复已入队，等待电脑更新"
                batch.phase==QuestionPhase.CONTINUED->"任务已继续；新的答复会作为后续消息发送"
                !view.answerable->"当前问题暂不可应答，请核对电脑上的最新状态"
                batch.kind==QuestionKind.BLOCKING->"正在等待完整答复"
                view.claim?.phase==ClaimPhase.PENDING->"正在向电脑申请答复时间"
                remaining!=null->"剩余约 ${(remaining+999)/1000} 秒；以电脑状态为准"
                else->"电脑尚未提供等待倒计时"
            },style=MaterialTheme.typography.bodySmall,modifier=Modifier.semantics {liveRegion=LiveRegionMode.Polite})
            if(!expanded) {
                Text(batch.prompts.first().question.take(240))
                OutlinedButton({expanded=true;if(canAnswer && batch.kind==QuestionKind.TIMED && batch.phase==QuestionPhase.OPEN && view.answerable) onClaim(handle)},modifier=Modifier.fillMaxWidth().heightIn(min=48.dp)) {Text(if(canAnswer) "查看并答复" else "查看问题")}
            } else {
                DisposableEffect(handle) {onDispose {onRelease(handle)}}
                for(prompt in batch.prompts) key(prompt.id) {
                    prompt.header?.takeIf {it.isNotBlank()}?.let {Text(it,style=MaterialTheme.typography.titleSmall)}
                    QuestionText(prompt.question)
                    prompt.detail?.let {detail->
                        val complete=QuestionText(detail)
                        if(complete && prompt.id !in reviewed) SideEffect {reviewed=reviewed+prompt.id}
                    }
                    val draft=drafts.getValue(prompt.id)
                    fun toggle(label: String) {
                        val selected=if(prompt.multiSelect) {if(label in draft.selected) draft.selected-label else draft.selected+label}
                            else if(label in draft.selected) emptySet() else setOf(label)
                        drafts=drafts+(prompt.id to AnswerDraft(selected,draft.custom))
                    }
                    for(option in prompt.options) key(option.label) {
                        Row(Modifier.fillMaxWidth().heightIn(min=48.dp).clickable(enabled=enabled) {toggle(option.label)},verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                            if(prompt.multiSelect) Checkbox(option.label in draft.selected,{toggle(option.label)},enabled=enabled)
                            else RadioButton(option.label in draft.selected,{toggle(option.label)},enabled=enabled)
                            Column(Modifier.weight(1f)) {Text(option.label);option.description?.let {QuestionText(it)}}
                        }
                    }
                    OutlinedTextField(draft.custom,{value->if(value.length<=16_384) drafts=drafts+(prompt.id to AnswerDraft(draft.selected,value))},
                        enabled=enabled,label={Text(if(prompt.options.isEmpty()) "答复：${prompt.id}" else "补充或自定义答复：${prompt.id}")},minLines=1,maxLines=6,modifier=Modifier.fillMaxWidth())
                    if(batch.kind==QuestionKind.TIMED) Text("此项可留空跳过；不会替你选择任何选项。",style=MaterialTheme.typography.bodySmall)
                }
                if(!canAnswer) Text("当前无法在手机答复，请在电脑处理或恢复本机答复权限。",style=MaterialTheme.typography.bodySmall)
                if(batch.kind==QuestionKind.TIMED && batch.phase==QuestionPhase.OPEN) Text("若电脑已继续运行，答复将作为后续消息；不会再次完成旧问题。",style=MaterialTheme.typography.bodySmall)
                if(pending!=null) {
                    Text(when {
                        pending.remote==RemoteCommandState.SETTLED->"答复已确认，等待电脑更新问题列表"
                        pending.everAgentQueued->"后续答复已入队"
                        else->"原答复结果待确认，请先核对原请求"
                    },style=MaterialTheme.typography.bodySmall)
                    OutlinedButton(onQuery,modifier=Modifier.fillMaxWidth().heightIn(min=48.dp)) {Text("核对原答复")}
                }
                if(reviewing) Text("请先展开并核对完整计划详情，再选择继续该计划。",style=MaterialTheme.typography.bodySmall)
                Button({if(answers!=null) onAnswer(handle,answers)},enabled=enabled && valid && !reviewing,modifier=Modifier.fillMaxWidth().heightIn(min=48.dp)) {
                    Text(if(submitting) "正在保存答复…" else if(batch.phase==QuestionPhase.CONTINUED) "作为后续答复发送" else "发送完整答复")
                }
                OutlinedButton({expanded=false;onRelease(handle)},modifier=Modifier.fillMaxWidth().heightIn(min=48.dp)) {Text("暂不回答")}
            }
            TextButton(onRefresh,Modifier.heightIn(min=48.dp)) {Text("刷新提问状态")}
        }
    }
}

/** Large plans stay readable without silently authorizing hidden details. */
@Composable
private fun QuestionText(text: String): Boolean {
    var limit by remember(text) {mutableIntStateOf(8192)}
    val end=minOf(limit,text.length).let {if(it in 1 until text.length && text[it-1].isHighSurrogate() && text[it].isLowSurrogate()) it-1 else it}
    Text(text.substring(0,end),style=MaterialTheme.typography.bodyLarge)
    if(end<text.length) TextButton({limit=(limit+8192).coerceAtMost(text.length)},Modifier.heightIn(min=48.dp)) {Text("继续显示问题详情")}
    return end==text.length
}

@Composable
fun SubmittedQuestionAnswer(intent: CommandIntent) {
    val payload=QuestionAnswers.parse(intent.payload)
    Text("问题 ${payload.questionId.take(8)}",style=MaterialTheme.typography.bodySmall)
    payload.values.forEach {answer->
        Text(answer.id,style=MaterialTheme.typography.labelMedium)
        answer.selected.forEach {QuestionText(it)}
        answer.custom?.let {QuestionText(it)}
        if(answer.selected.isEmpty() && answer.custom.isNullOrEmpty()) Text("此项留空",style=MaterialTheme.typography.bodySmall)
    }
}
