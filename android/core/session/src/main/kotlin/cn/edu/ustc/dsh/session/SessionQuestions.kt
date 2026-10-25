package cn.edu.ustc.dsh.session

import cn.edu.ustc.dsh.protocol.*
import java.security.MessageDigest
import java.util.Collections

enum class QuestionKind { BLOCKING, TIMED }
enum class QuestionPhase { OPEN, CONTINUED, REPLY_QUEUED }
class QuestionStateException(val code: String) : IllegalStateException(code)
class QuestionOption(val label: String,val description: String?) { override fun toString()="QuestionOption" }
class QuestionPrompt(val id: String,val question: String,val detail: String?,val header: String?,val options: List<QuestionOption>,val multiSelect: Boolean,val planApproval: String?) {
    override fun toString()="QuestionPrompt"
}
class QuestionBatch private constructor(val id: String,val kind: QuestionKind,val phase: QuestionPhase,val expiresAt: Long?,val prompts: List<QuestionPrompt>,val definition: String,val weight: Long) {
    fun validate(answers: QuestionAnswers) {
        if(answers.questionId!=id || answers.values.size!=prompts.size || answers.values.map {it.id}.toSet()!=prompts.map {it.id}.toSet()) throw QuestionStateException("question.invalid_answer")
        for(prompt in prompts) {
            val value=answers.values.single {it.id==prompt.id}
            if(!prompt.multiSelect && value.selected.size>1 || value.selected.any {label->prompt.options.none {it.label==label}} ||
                kind==QuestionKind.BLOCKING && value.selected.isEmpty() && value.custom.isNullOrBlank()) throw QuestionStateException("question.invalid_answer")
        }
    }
    override fun toString()="QuestionBatch($kind, $phase)"
    companion object {
        fun parse(root: JsonObject,kind: QuestionKind): QuestionBatch {
            root.exactKeys(*(setOf("question_id","expires_at","questions")+if(kind==QuestionKind.TIMED) setOf("state") else emptySet()).toTypedArray())
            val phase=if(kind==QuestionKind.BLOCKING) QuestionPhase.OPEN else when(root.string("state")) {"open"->QuestionPhase.OPEN;"continued"->QuestionPhase.CONTINUED;"reply_queued"->QuestionPhase.REPLY_QUEUED;else->throw SessionDataException()}
            val expiry=when(val value=root["expires_at"]) {JsonNull->null;is JsonString->relayTime(value.value);else->throw SessionDataException()}
            if(kind==QuestionKind.BLOCKING && expiry==null || phase!=QuestionPhase.OPEN && expiry!=null) throw SessionDataException()
            val raw=root.array("questions"); if(raw.size !in 1..32) throw SessionDataException()
            val prompts=raw.map {value->
                val item=value as? JsonObject ?: throw SessionDataException()
                SessionJson.fields(item,setOf("id","question"),setOf("detail","header","options","multi_select","intent"))
                fun text(name: String,max: Int,optional: Boolean=false): String? = if(optional && name !in item.fields) null else questionText(item.string(name),max)
                val options=if("options" !in item.fields) emptyList() else item.array("options").also {if(it.size>32) throw SessionDataException()}.map {entry->
                    val option=entry as? JsonObject ?: throw SessionDataException()
                    SessionJson.fields(option,setOf("label"),setOf("description"))
                    val label=questionText(option.string("label"),4096); if(label.isEmpty()) throw SessionDataException()
                    QuestionOption(label,option.fields["description"]?.let {questionText(option.string("description"),16_384)})
                }
                if(options.map {it.label}.toSet().size!=options.size) throw SessionDataException()
                val approval=if("intent" !in item.fields) null else item.obj("intent").let {
                    it.exactKeys("kind","approve"); if(it.string("kind")!="plan-review") throw SessionDataException()
                    questionText(it.string("approve"),4096).also {value->if(value.isEmpty()) throw SessionDataException()}
                }
                val id=text("id",128)!!;val question=text("question",16_384)!!
                if(id.isEmpty() || question.isEmpty()) throw SessionDataException()
                QuestionPrompt(id,question,text("detail",65_536,true),text("header",128,true),Collections.unmodifiableList(options),if("multi_select" in item.fields) SessionJson.boolean(item,"multi_select") else false,approval)
            }
            if(prompts.map {it.id}.toSet().size!=prompts.size || SessionJson.encode(root).size>128*1024) throw SessionDataException("question.too_large")
            val bytes=SessionJson.encode(jsonObject("questions" to JsonArray(raw)))
            val digest=MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {"%02x".format(it.toInt() and 255)}
            return QuestionBatch(Contract.uuid(root.string("question_id")),kind,phase,expiry,Collections.unmodifiableList(prompts),digest,SessionJson.weight(root))
        }
    }
}
data class QuestionHandle(val runtimeId: String,val sessionId: String,val epoch: String,val subscriptionId: String,val syncId: String,val questionId: String,val kind: QuestionKind,val definition: String)
enum class ClaimPhase { PENDING, ACTIVE }
class QuestionClaimView(val requestId: String,val phase: ClaimPhase,val remainingMillis: Long?)
class PresentedQuestion(val batch: QuestionBatch,val handle: QuestionHandle,val remainingMillis: Long?,val claim: QuestionClaimView?,val foregroundEnded: Boolean) {
    val answerable get()=batch.phase!=QuestionPhase.REPLY_QUEUED && (batch.phase==QuestionPhase.CONTINUED || (remainingMillis==null || remainingMillis>0) && !foregroundEnded)
}
data class SessionQuestionState(val items: List<PresentedQuestion> = emptyList(),val canAnswer: Boolean=false,val blockingLoaded: Boolean=false,val timedLoaded: Boolean=false,val error: String?=null)

/** Only current routed snapshots and claim lifetimes live here; nothing is a transcript checkpoint. */
class SessionQuestions(private val route: SessionRoute,private val request: String) {
    private class Entry(val batch: QuestionBatch,val deadline: Long?)
    private class Claim(val id: String,val question: String,val sentAt: Long,var remaining: Long?=null,var deadline: Long?=null)
    private var sync: String?=null
    private val entries=linkedMapOf<String,Entry>()
    private val revisions=mutableMapOf<QuestionKind,Long>()
    private val last=mutableMapOf<QuestionKind,JsonObject>()
    private val claims=linkedMapOf<String,Claim>()
    private val releases=linkedMapOf<String,Pair<String,Long>>()
    private val used=linkedSetOf<String>()
    private val retired=linkedSetOf<String>()
    private val ended=mutableSetOf<String>()
    private var error: String?=null
    val hasClaims get()=claims.isNotEmpty() || releases.isNotEmpty()
    fun attach(syncId: String) {
        Contract.uuid(syncId)
        if(sync==syncId) return
        if(hasClaims) throw QuestionStateException("question.resync_required")
        sync=syncId;entries.clear();revisions.clear();last.clear();ended.clear();error=null
    }
    fun accept(content: SessionContent,nowMillis: Long=System.currentTimeMillis(),nowNanos: Long=System.nanoTime()): Boolean {
        if(content.requestId!=request || content.syncId!=sync) throw SessionDataException()
        val kind=when(content.type) {"question.snapshot"->QuestionKind.BLOCKING;"question.timed.snapshot"->QuestionKind.TIMED;else->throw SessionDataException()}
        val payload=content.payload;payload.exactKeys("revision","items")
        val revision=payload.integer("revision",0)
        val previous=revisions[kind]
        if(previous!=null && revision<previous) return false
        if(previous==revision) {if(!SessionJson.same(last[kind]!!,payload)) throw SessionDataException();return false}
        val raw=payload.array("items");if(raw.size>64 || SessionJson.weight(payload)>SessionWindow.MAX_RETAINED_WEIGHT) throw SessionDataException("question.too_large")
        val batches=raw.map {QuestionBatch.parse(it as? JsonObject ?: throw SessionDataException(),kind)}
        if(batches.sumOf {it.weight}+entries.values.filter {it.batch.kind!=kind}.sumOf {it.batch.weight}>SessionWindow.MAX_RETAINED_WEIGHT) throw SessionDataException("question.too_large")
        if(batches.map {it.id}.toSet().size!=batches.size) throw SessionDataException()
        for(batch in batches) {
            val old=entries[batch.id]?.batch
            if(old!=null && (old.kind!=kind || old.definition!=batch.definition)) throw SessionDataException()
        }
        val replacements=batches.associate {batch->
            val old=entries[batch.id]
            val proposed=batch.expiresAt?.let {nowNanos+(it-nowMillis).coerceIn(0,Int.MAX_VALUE.toLong())*1_000_000}
            val deadline=if(batch.phase!=QuestionPhase.OPEN) null else listOfNotNull(old?.deadline,proposed).minOrNull()
            batch.id to Entry(batch,deadline)
        }
        entries.entries.removeAll {it.value.batch.kind==kind && it.key !in replacements}
        entries.putAll(replacements)
        val gone=claims.values.filter {entry->entries[entry.question]?.batch?.phase!=QuestionPhase.OPEN}.map {it.id}
        for(id in gone) retire(id)
        ended.retainAll(entries.keys)
        for(batch in batches) if(batch.phase!=QuestionPhase.OPEN) ended.remove(batch.id)
        revisions[kind]=revision;last[kind]=payload;return true
    }
    fun state(canAnswer: Boolean,nowNanos: Long=System.nanoTime()): SessionQuestionState {
        val current=sync ?: return SessionQuestionState(canAnswer=canAnswer)
        val views=entries.values.map {entry->
            val claim=claims.values.firstOrNull {it.question==entry.batch.id}
            val remaining=listOfNotNull(entry.deadline,claim?.deadline).minOrNull()?.let {((it-nowNanos)/1_000_000).coerceAtLeast(0)}
            PresentedQuestion(entry.batch,QuestionHandle(route.runtimeId,route.sessionId,route.epoch,route.subscriptionId,current,entry.batch.id,entry.batch.kind,entry.batch.definition),remaining,
                claim?.let {QuestionClaimView(it.id,if(it.deadline==null) ClaimPhase.PENDING else ClaimPhase.ACTIVE,it.deadline?.let {deadline->((deadline-nowNanos)/1_000_000).coerceAtLeast(0)})},entry.batch.id in ended)
        }
        return SessionQuestionState(Collections.unmodifiableList(views),canAnswer,QuestionKind.BLOCKING in revisions,QuestionKind.TIMED in revisions,error)
    }
    fun require(handle: QuestionHandle,nowNanos: Long=System.nanoTime()): PresentedQuestion = state(true,nowNanos).items.firstOrNull {it.handle==handle && it.answerable} ?: throw QuestionStateException("question.stale")
    fun validate(handle: QuestionHandle,answers: QuestionAnswers,nowNanos: Long=System.nanoTime()) {require(handle,nowNanos).batch.validate(answers)}
    fun validateStored(question: String,kind: QuestionKind,definition: String,answers: QuestionAnswers,nowNanos: Long=System.nanoTime()) {
        val current=state(true,nowNanos).items.firstOrNull {it.batch.id==question && it.batch.kind==kind && it.batch.definition==definition && it.answerable} ?: throw QuestionStateException("question.stale")
        current.batch.validate(answers)
    }
    fun beginClaim(handle: QuestionHandle,id: String,nowNanos: Long=System.nanoTime()): String? {
        val current=require(handle,nowNanos)
        if(current.batch.kind!=QuestionKind.TIMED || current.batch.phase!=QuestionPhase.OPEN) throw QuestionStateException("question.stale")
        if(claims.values.any {it.question==handle.questionId}) return null
        if(claims.size>=4 || used.size>=256) throw QuestionStateException("question.claim_limit")
        Contract.uuid(id);if(id in used) throw QuestionStateException("question.claim_limit")
        claims[id]=Claim(id,handle.questionId,nowNanos);used+=id;error=null;return id
    }
    fun beginRelease(handle: QuestionHandle,id: String,nowNanos: Long=System.nanoTime()): String? {
        if(handle.runtimeId!=route.runtimeId || handle.sessionId!=route.sessionId || handle.kind!=QuestionKind.TIMED || handle.epoch!=route.epoch || handle.subscriptionId!=route.subscriptionId || handle.syncId!=sync) return null
        val claim=claims.values.firstOrNull {it.question==handle.questionId} ?: return null
        Contract.uuid(id);retire(claim.id);releases[id]=claim.id to nowNanos;return claim.id
    }
    fun claimFrame(frame: JsonObject,nowMillis: Long=System.currentTimeMillis(),nowNanos: Long=System.nanoTime()) {
        val type=frame.string("type")
        relayEnvelope(frame,type,"v","type","request_id","runtime_id","runtime_epoch","session_id","subscription_id","sync_id","payload")
        if(!route.matches(frame) || frame.string("sync_id")!=sync) throw SessionDataException()
        val id=Contract.uuid(frame.string("request_id"));val payload=frame.obj("payload")
        if(type=="question.released") {
            payload.exactKeys("claim_id");val released=releases.remove(id) ?: return
            if(Contract.uuid(payload.string("claim_id"))!=released.first) throw SessionDataException();return
        }
        val claim=claims[id] ?: if(id in retired) return else throw SessionDataException()
        if(payload.string("question_id")!=claim.question) throw SessionDataException()
        when(type) {
            "question.claimed"->{
                payload.exactKeys("question_id","remaining_ms","expires_at")
                val remaining=payload.integer("remaining_ms",0,Int.MAX_VALUE.toLong());val expires=relayTime(payload.string("expires_at"))
                if(claim.remaining!=null) {if(claim.remaining!=remaining) throw SessionDataException();return}
                claim.remaining=remaining
                claim.deadline=minOf(claim.sentAt+remaining*1_000_000,nowNanos+(expires-nowMillis).coerceIn(0,Int.MAX_VALUE.toLong())*1_000_000)
                entries[claim.question]?.let {entry->entries[claim.question]=Entry(entry.batch,listOfNotNull(entry.deadline,claim.deadline).minOrNull())}
            }
            "question.claim.closed"->{
                payload.exactKeys("question_id","code");val code=payload.string("code")
                if(code !in setOf("question.ended","interaction.stale","rate.limited","internal")) throw SessionDataException()
                if(code in setOf("question.ended","interaction.stale")) ended+=claim.question
                error=code;retire(id)
            }
            else->throw SessionDataException()
        }
    }
    fun claimError(requestId: String,code: String): Boolean {
        if(requestId in releases) {releases.remove(requestId);throw QuestionStateException("question.release_unconfirmed")}
        if(requestId !in claims) return requestId in retired
        if(code in setOf("question.ended","interaction.stale")) ended+=claims[requestId]!!.question
        error=code;retire(requestId);return true
    }
    fun timedOut(nowNanos: Long=System.nanoTime()): Boolean = claims.values.any {it.deadline==null && nowNanos-it.sentAt>=10_000_000_000} || releases.values.any {nowNanos-it.second>=5_000_000_000}
    private fun retire(id: String) {claims.remove(id);retired+=id}
}
