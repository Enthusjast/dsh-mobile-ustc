package cn.edu.ustc.dsh.protocol

import java.util.Collections

/** Values retain exact labels/custom text; no normalization or tool decision is introduced. */
class QuestionAnswer(id: String, selected: List<String>, val custom: String? = null) {
    val id = questionText(id, 128).also { if (it.isEmpty()) throw ProtocolException() }
    val selected: List<String>
    init {
        if (selected.size > 32 || selected.toSet().size != selected.size) throw ProtocolException()
        this.selected = Collections.unmodifiableList(selected.map { questionText(it, 4096) })
        custom?.let { questionText(it, 16_384) }
    }
    fun json(): JsonObject {
        var value=jsonObject("id" to id.json(),"selected" to JsonArray(selected.map(String::json)))
        if(custom!=null) value=value.with("custom" to custom.json())
        return value
    }
    override fun toString()="QuestionAnswer"
}
class QuestionAnswers(val questionId: String, values: List<QuestionAnswer>) {
    val values: List<QuestionAnswer>
    init {
        Contract.uuid(questionId)
        if(values.size !in 1..32 || values.map {it.id}.toSet().size!=values.size) throw ProtocolException()
        this.values=Collections.unmodifiableList(values.toList())
    }
    fun json()=jsonObject("question_id" to questionId.json(),"answers" to JsonArray(values.map {it.json()}))
    override fun toString()="QuestionAnswers(count=${values.size})"
    companion object {
        fun parse(root: JsonObject): QuestionAnswers {
            root.exactKeys("question_id","answers")
            val values=root.array("answers").map {value->
                val item=value as? JsonObject ?: throw ProtocolException()
                item.exactKeys(*(setOf("id","selected")+if("custom" in item.fields) setOf("custom") else emptySet()).toTypedArray())
                QuestionAnswer(item.string("id"),item.array("selected").map {(it as? JsonString)?.value ?: throw ProtocolException()},item.fields["custom"]?.let {item.string("custom")})
            }
            return QuestionAnswers(root.string("question_id"),values)
        }
    }
}

/** Matches the stricter configured host adapter's UTF-16 bound and scalar Unicode. */
fun questionText(value: String, max: Int): String {
    if(value.length>max || value.any {Character.isISOControl(it) && it !in "\n\r\t"}) throw ProtocolException()
    var index=0
    while(index<value.length) {
        val char=value[index++]
        if(char.isLowSurrogate() || char.isHighSurrogate() && (index>=value.length || !value[index++].isLowSurrogate())) throw ProtocolException()
    }
    return value
}
