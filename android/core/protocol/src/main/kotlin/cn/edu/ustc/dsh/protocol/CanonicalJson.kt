package cn.edu.ustc.dsh.protocol

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.StreamReadFeature
import org.erdtman.jcs.JsonCanonicalizer
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.util.Collections

/** Safe for display/logging: never includes a rejected body, token or parser cause. */
class ProtocolException(message: String = "protocol: invalid value") : IllegalArgumentException(message)

sealed interface JsonValue
class JsonObject(values: Map<String, JsonValue>) : JsonValue {
    val fields: Map<String, JsonValue> = Collections.unmodifiableMap(LinkedHashMap(values))
    operator fun get(name: String): JsonValue = fields[name] ?: throw ProtocolException()
    fun string(name: String): String = (get(name) as? JsonString)?.value ?: throw ProtocolException()
    fun obj(name: String): JsonObject = get(name) as? JsonObject ?: throw ProtocolException()
    fun array(name: String): List<JsonValue> = (get(name) as? JsonArray)?.values ?: throw ProtocolException()
    fun integer(name: String, min: Long = 1, max: Long = MAX_SAFE_INTEGER): Long {
        val number = (get(name) as? JsonNumber)?.value ?: throw ProtocolException()
        if (!number.isFinite() || number < min.toDouble() || number > max.toDouble() || number % 1.0 != 0.0) throw ProtocolException()
        return number.toLong()
    }
    fun exactKeys(vararg keys: String) { if (fields.keys != keys.toSet()) throw ProtocolException() }
    fun with(vararg changes: Pair<String, JsonValue>): JsonObject = JsonObject(fields + changes)
}
class JsonArray(values: List<JsonValue>) : JsonValue {
    val values: List<JsonValue> = Collections.unmodifiableList(ArrayList(values))
}
data class JsonString(val value: String) : JsonValue
data class JsonNumber(val value: Double) : JsonValue
data class JsonBoolean(val value: Boolean) : JsonValue
data object JsonNull : JsonValue

const val MAX_SAFE_INTEGER = 9_007_199_254_740_991L

/** An immutable, fully checked object and its RFC 8785 representation. */
class JsonDocument private constructor(val root: JsonObject, private val canonical: String) {
    fun canonicalBytes(): ByteArray = canonical.toByteArray(Charsets.UTF_8)
    fun canonicalText(): String = canonical
    fun sha256(): String = sha256(canonicalBytes())

    companion object {
        const val MAX_BYTES = 128 * 1024
        private const val MAX_NODES = 16_384
        private val factory = JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder()
                .maxNestingDepth(33).maxStringLength(MAX_BYTES).maxNameLength(MAX_BYTES).maxNumberLength(MAX_BYTES).build())
            .build()

        fun parse(bytes: ByteArray): JsonDocument = safe {
            if (bytes.size > MAX_BYTES) throw ProtocolException()
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            parse(text)
        }

        fun parse(text: String): JsonDocument = safe {
            requireText(text)
            if (text.toByteArray(Charsets.UTF_8).size > MAX_BYTES) throw ProtocolException()
            var nodes = 0
            factory.createParser(text).use { parser ->
                fun read(depth: Int): JsonValue {
                    if (++nodes > MAX_NODES || depth > 32) throw ProtocolException()
                    return when (parser.currentToken()) {
                        JsonToken.START_OBJECT -> {
                            val values = linkedMapOf<String, JsonValue>()
                            while (parser.nextToken() != JsonToken.END_OBJECT) {
                                if (parser.currentToken() != JsonToken.FIELD_NAME) throw ProtocolException()
                                val name = parser.currentName() ?: throw ProtocolException()
                                requireText(name)
                                parser.nextToken()
                                values[name] = read(depth + 1)
                            }
                            JsonObject(values)
                        }
                        JsonToken.START_ARRAY -> {
                            val values = arrayListOf<JsonValue>()
                            while (parser.nextToken() != JsonToken.END_ARRAY) values += read(depth + 1)
                            JsonArray(values)
                        }
                        JsonToken.VALUE_STRING -> JsonString(parser.text.also(::requireText))
                        JsonToken.VALUE_NUMBER_INT, JsonToken.VALUE_NUMBER_FLOAT -> JsonNumber(parser.doubleValue.also {
                            if (!it.isFinite()) throw ProtocolException()
                        })
                        JsonToken.VALUE_TRUE -> JsonBoolean(true)
                        JsonToken.VALUE_FALSE -> JsonBoolean(false)
                        JsonToken.VALUE_NULL -> JsonNull
                        else -> throw ProtocolException()
                    }
                }
                parser.nextToken()
                val root = read(0) as? JsonObject ?: throw ProtocolException()
                if (parser.nextToken() != null) throw ProtocolException()
                // The strict bounded parser runs first: the JCS library's parser
                // alone accepts e.g. duplicate-null names and leading zeroes.
                val canonical = JsonCanonicalizer(text).encodedString
                if (canonical.toByteArray(Charsets.UTF_8).size > MAX_BYTES) throw ProtocolException()
                JsonDocument(root, canonical)
            }
        }

        fun of(root: JsonObject): JsonDocument = safe {
            val writer = java.io.StringWriter()
            var nodes = 0
            factory.createGenerator(writer).use { generator ->
                fun write(value: JsonValue, depth: Int) {
                    if (++nodes > MAX_NODES || depth > 32) throw ProtocolException()
                    when (value) {
                        is JsonObject -> {
                            generator.writeStartObject()
                            value.fields.forEach { (name, item) -> requireText(name); generator.writeFieldName(name); write(item, depth + 1) }
                            generator.writeEndObject()
                        }
                        is JsonArray -> { generator.writeStartArray(); value.values.forEach { write(it, depth + 1) }; generator.writeEndArray() }
                        is JsonString -> { requireText(value.value); generator.writeString(value.value) }
                        is JsonNumber -> { if (!value.value.isFinite()) throw ProtocolException(); generator.writeNumber(value.value) }
                        is JsonBoolean -> generator.writeBoolean(value.value)
                        JsonNull -> generator.writeNull()
                    }
                    if (writer.buffer.length > MAX_BYTES) throw ProtocolException()
                }
                write(root, 0)
            }
            parse(writer.toString())
        }

        private inline fun <T> safe(block: () -> T): T = try { block() } catch (_: Exception) {
            throw ProtocolException("canonical: invalid JSON object")
        }
    }
}

fun requireText(value: String) {
    if (value.length > JsonDocument.MAX_BYTES) throw ProtocolException()
    var index = 0
    while (index < value.length) {
        val char = value[index++]
        if (char.isLowSurrogate()) throw ProtocolException()
        if (char.isHighSurrogate() && (index == value.length || !value[index++].isLowSurrogate())) throw ProtocolException()
    }
}

fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
fun jsonObject(vararg values: Pair<String, JsonValue>): JsonObject = JsonObject(linkedMapOf(*values))
fun String.json(): JsonString = JsonString(this)
fun Long.json(): JsonNumber = JsonNumber(toDouble())
