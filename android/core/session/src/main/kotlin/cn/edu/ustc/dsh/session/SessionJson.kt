package cn.edu.ustc.dsh.session

import cn.edu.ustc.dsh.protocol.*
import com.fasterxml.jackson.core.*
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

const val SESSION_PAYLOAD_BYTES = 2 * 1024 * 1024
const val SESSION_MAX_NODES = 65_536

class SessionDataException(val code: String = "protocol.resync_required") : IllegalArgumentException(code)

/** Display-only logical payloads have a separate budget; signing/config JSON keeps its 128 KiB limit. */
object SessionJson {
    private val factory = JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(33).maxStringLength(SESSION_PAYLOAD_BYTES).maxNameLength(1024).maxNumberLength(128).build()).build()
    fun parse(bytes: ByteArray): JsonObject = try {
        if (bytes.size > SESSION_PAYLOAD_BYTES) throw SessionDataException("protocol.snapshot_too_large")
        val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        var nodes = 0
        factory.createParser(text).use { parser ->
            fun read(depth: Int): JsonValue {
                if (++nodes > SESSION_MAX_NODES || depth > 32) throw SessionDataException("protocol.snapshot_too_large")
                return when (parser.currentToken()) {
                    JsonToken.START_OBJECT -> {
                        val map = linkedMapOf<String, JsonValue>()
                        while (parser.nextToken() != JsonToken.END_OBJECT) {
                            if (parser.currentToken() != JsonToken.FIELD_NAME) throw SessionDataException()
                            val name = parser.currentName() ?: throw SessionDataException(); scalar(name)
                            parser.nextToken(); map[name] = read(depth + 1)
                        }
                        JsonObject(map)
                    }
                    JsonToken.START_ARRAY -> {
                        val values = arrayListOf<JsonValue>()
                        while (parser.nextToken() != JsonToken.END_ARRAY) values += read(depth + 1)
                        JsonArray(values)
                    }
                    JsonToken.VALUE_STRING -> JsonString(parser.text.also(::scalar))
                    JsonToken.VALUE_NUMBER_INT, JsonToken.VALUE_NUMBER_FLOAT -> JsonNumber(parser.doubleValue.also { if (!it.isFinite()) throw SessionDataException() })
                    JsonToken.VALUE_TRUE -> JsonBoolean(true)
                    JsonToken.VALUE_FALSE -> JsonBoolean(false)
                    JsonToken.VALUE_NULL -> JsonNull
                    else -> throw SessionDataException()
                }
            }
            parser.nextToken()
            val root = read(0) as? JsonObject ?: throw SessionDataException()
            if (parser.nextToken() != null) throw SessionDataException()
            root
        }
    } catch (error: SessionDataException) { throw error }
    catch (_: Exception) { throw SessionDataException("protocol.invalid") }

    fun fields(root: JsonObject, required: Set<String>, optional: Set<String> = emptySet()) {
        if (!root.fields.keys.containsAll(required) || root.fields.keys.any { it !in required && it !in optional }) throw SessionDataException("protocol.invalid")
    }
    fun boolean(root: JsonObject, name: String): Boolean = (root[name] as? JsonBoolean)?.value ?: throw SessionDataException("protocol.invalid")
    fun same(a: JsonValue, b: JsonValue): Boolean = when {
        a is JsonObject && b is JsonObject -> a.fields.keys == b.fields.keys && a.fields.all { (key, value) -> same(value, b[key]) }
        a is JsonArray && b is JsonArray -> a.values.size == b.values.size && a.values.indices.all { same(a.values[it], b.values[it]) }
        else -> a == b
    }
    /** Conservative retained-content accounting, including object/key overhead; not a VM heap claim. */
    fun weight(value: JsonValue): Long = when (value) {
        is JsonObject -> 48L + value.fields.entries.sumOf { 48L + it.key.length * 2L + weight(it.value) }
        is JsonArray -> 32L + value.values.sumOf { 8L + weight(it) }
        is JsonString -> 32L + value.value.length * 2L
        else -> 24L
    }
    private fun scalar(text: String) {
        var index = 0
        while (index < text.length) {
            val next = text[index++]
            if (next.isLowSurrogate() || next.isHighSurrogate() && (index >= text.length || !text[index++].isLowSurrogate())) throw SessionDataException("protocol.invalid")
        }
    }
}
