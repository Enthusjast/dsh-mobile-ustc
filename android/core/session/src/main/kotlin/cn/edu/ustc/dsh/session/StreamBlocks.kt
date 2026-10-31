package cn.edu.ustc.dsh.session

import cn.edu.ustc.dsh.protocol.*
import java.util.Collections

enum class BlockKind { TEXT, REASONING, TOOL, IMAGE, OTHER }
class DisplayBlock(val kind: BlockKind, val text: String, val name: String = "", val callId: String = "", val complete: Boolean = false,
    val media: VisibleMediaReference? = null) {
    init { if ((kind == BlockKind.IMAGE) != (media != null)) throw SessionDataException() }
    override fun toString() = "DisplayBlock($kind)"
}

/** Display assembly only. These values never authorize a tool or provide an approval binding. */
internal class StreamBlocks {
    private class Part(var type: String) {
        val text = StringBuilder()
        val args = StringBuilder()
        var name = ""
        var callId = ""
        var closed = false
    }
    private val parts = linkedMapOf<Long, Part>()
    private var characters = 0L
    var chunks = 0L; private set
    private fun account(chars: Int) {
        characters += chars
        if (characters > SESSION_PAYLOAD_BYTES) throw SessionDataException("protocol.snapshot_too_large")
    }
    private fun part(index: Long, type: String): Part {
        if (parts.size >= 4096 && index !in parts) throw SessionDataException("protocol.snapshot_too_large")
        val part = parts.getOrPut(index) { Part(type) }
        if (!part.closed && part.type != type) throw SessionDataException()
        return part
    }
    fun accept(chunk: JsonObject) {
        if (++chunks > SESSION_MAX_NODES) throw SessionDataException("protocol.snapshot_too_large")
        val type = chunk.string("type")
        when (type) {
            "block-start" -> {
                chunk.exactKeys("type", "index", "blockType")
                part(chunk.integer("index", 0, 4095), Contract.boundedText(chunk.string("blockType"), 64))
            }
            "text-delta", "reasoning-delta" -> {
                chunk.exactKeys("type", "index", "text")
                val expected = if (type == "text-delta") "text" else "reasoning"
                val part = part(chunk.integer("index", 0, 4095), expected)
                if (!part.closed) { val text = chunk.string("text"); account(text.length); part.text.append(text) }
            }
            "tool-call-delta" -> {
                SessionJson.fields(chunk, setOf("type", "index", "id", "argumentsDelta"), setOf("name"))
                val part = part(chunk.integer("index", 0, 4095), "tool-call")
                if (!part.closed) {
                    val id = Contract.boundedText(chunk.string("id"), 2048)
                    account(id.length - part.callId.length); part.callId = id
                    if ("name" in chunk.fields) chunk.string("name").takeIf(String::isNotEmpty)?.let { name ->
                        val checked = Contract.boundedText(name, 256); account(checked.length - part.name.length); part.name = checked
                    }
                    val args = chunk.string("argumentsDelta"); account(args.length); part.args.append(args)
                }
            }
            "block-end" -> {
                chunk.exactKeys("type", "index", "block")
                val block = chunk.obj("block")
                SessionJson.fields(block, setOf("type"), setOf("text", "id", "name", "arguments"))
                val blockType = Contract.boundedText(block.string("type"), 64)
                val part = part(chunk.integer("index", 0, 4095), blockType)
                if (!part.closed) {
                    val text = (block.fields["text"] as? JsonString)?.value ?: ""
                    account(text.length - part.text.length); part.text.setLength(0); part.text.append(text); part.type = blockType
                    part.name = (block.fields["name"] as? JsonString)?.value?.let { Contract.boundedText(it, 256) } ?: part.name
                    if ("id" in block.fields) {
                        val id = Contract.boundedText(block.string("id"), 2048)
                        account(id.length - part.callId.length); part.callId = id
                    }
                    part.closed = true
                }
            }
            "usage" -> { chunk.exactKeys("type", "usage"); chunk.obj("usage") }
            "finish" -> { chunk.exactKeys("type", "reason") }
            else -> throw SessionDataException("protocol.unsupported")
        }
    }
    fun compact(records: List<JsonValue>, expectedChunks: Long? = null) {
        for (value in records) {
            val record = value as? JsonObject ?: throw SessionDataException()
            val type = record.string("type")
            if (type == "chunk") {
                record.exactKeys("type", "time", "chunk"); record.integer("time", -MAX_SAFE_INTEGER)
                accept(record.obj("chunk")); continue
            }
            val tool = type == "tool-call-chunks"
            if (type !in setOf("text-chunks", "reasoning-chunks", "tool-call-chunks")) throw SessionDataException("protocol.unsupported")
            SessionJson.fields(record, if (tool) setOf("type", "time0", "index", "dt", "id", "args") else setOf("type", "time0", "index", "dt", "texts"), if (tool) setOf("name") else emptySet())
            var time = record.integer("time0", -MAX_SAFE_INTEGER)
            val index = record.integer("index", 0, 4095)
            val texts = record.array(if (tool) "args" else "texts").map { (it as? JsonString)?.value ?: throw SessionDataException() }
            val deltas = record.array("dt")
            if (texts.isEmpty() || deltas.size != texts.size - 1) throw SessionDataException()
            for ((position, text) in texts.withIndex()) {
                if (position > 0) {
                    val delta = (deltas[position - 1] as? JsonNumber)?.value ?: throw SessionDataException()
                    if (delta % 1.0 != 0.0 || kotlin.math.abs(delta) > MAX_SAFE_INTEGER) throw SessionDataException()
                    time += delta.toLong(); if (time !in -MAX_SAFE_INTEGER..MAX_SAFE_INTEGER) throw SessionDataException()
                }
                val chunk = if (tool) {
                    val id = Contract.boundedText(record.string("id"), 2048)
                    var result = jsonObject("type" to "tool-call-delta".json(), "index" to index.json(), "id" to id.json(), "argumentsDelta" to text.json())
                    if ("name" in record.fields) result = result.with("name" to Contract.boundedText(record.string("name"), 256).json())
                    result
                } else jsonObject("type" to (if (type == "text-chunks") "text-delta" else "reasoning-delta").json(), "index" to index.json(), "text" to text.json())
                accept(chunk)
            }
        }
        if (expectedChunks != null && chunks != expectedChunks) throw SessionDataException()
    }
    fun snapshot(): List<DisplayBlock> = Collections.unmodifiableList(parts.values.map { part ->
        val kind = when (part.type) { "text" -> BlockKind.TEXT; "reasoning" -> BlockKind.REASONING; "tool-call" -> BlockKind.TOOL; else -> BlockKind.OTHER }
        DisplayBlock(kind, part.text.toString(), part.name, part.callId, part.closed)
    })
}
