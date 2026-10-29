package cn.edu.ustc.dsh.mobile

import cn.edu.ustc.dsh.protocol.*

internal const val APPROVAL_READING_PAGE_SIZE = 4096

internal data class ApprovalProjectionLabels(
    val objectType: String,
    val arrayType: String,
    val stringType: String,
    val numberType: String,
    val booleanType: String,
    val nullType: String,
    val fields: Map<String, String>,
)

/** A source node, its complete key/index, and every reading page needed to cover it.
 * Container ranges include their descendants, not just their opening line.
 * Source references belong to the validated immutable context; they are never reconstructed for signing.
 */
internal data class ApprovalValueCoverage(
    val value: JsonValue,
    val parent: Int?,
    val key: String?,
    val index: Int?,
    val pages: IntRange,
)

internal data class ApprovalReadingProjection(
    val pages: List<String>,
    val coverage: List<ApprovalValueCoverage>,
) {
    fun completelyReviewed(reviewed: Set<Int>): Boolean =
        pages.isNotEmpty() && pages.indices.all { it in reviewed } &&
            coverage.all { source -> source.pages.all { it in reviewed } }
}

/** Bounded presentation only: neither projection is used to produce signature bytes. */
internal fun approvalStructuredProjection(context: ApprovalContext, labels: ApprovalProjectionLabels): ApprovalReadingProjection {
    val writer = ApprovalPageWriter()
    data class Source(val value: JsonValue, val parent: Int?, val key: String?, val index: Int?, val first: Int, var last: Int)
    val sources = arrayListOf<Source>()
    fun visit(value: JsonValue, parent: Int?, key: String?, index: Int?, depth: Int) {
        val id = sources.size
        val source = Source(value, parent, key, index, writer.pageIndex, writer.pageIndex)
        sources += source
        writer.text("  ".repeat(depth))
        if (key != null) {
            if (depth == 1) labels.fields[key]?.let { writer.text(it); writer.text(" · ") }
            writer.quoted(key)
            writer.text(": ")
        }
        if (index != null) writer.text("[$index]: ")
        when (value) {
            is JsonObject -> {
                writer.text("${labels.objectType} (${value.fields.size}) {\n")
                value.fields.forEach { (name, item) -> visit(item, id, name, null, depth + 1) }
                writer.text("  ".repeat(depth)); writer.text("}\n")
            }
            is JsonArray -> {
                writer.text("${labels.arrayType} (${value.values.size}) [\n")
                value.values.forEachIndexed { position, item -> visit(item, id, null, position, depth + 1) }
                writer.text("  ".repeat(depth)); writer.text("]\n")
            }
            is JsonString -> { writer.text("${labels.stringType} "); writer.quoted(value.value); writer.text("\n") }
            is JsonNumber -> writer.text("${labels.numberType} ${value.value}\n")
            is JsonBoolean -> writer.text("${labels.booleanType} ${value.value}\n")
            JsonNull -> writer.text("${labels.nullType} null\n")
        }
        source.last = writer.lastContentPage
    }
    // Action fields first, then every identity/policy field. No unknown argument key is filtered.
    val fields = linkedMapOf<String, JsonValue>()
    listOf("tool", "arguments", "workspace", "resources").forEach { fields[it] = context.root[it] }
    context.root.fields.forEach { (key, value) -> if (key !in fields) fields[key] = value }
    visit(JsonObject(fields), null, null, null, 0)
    return ApprovalReadingProjection(writer.finish(), sources.map {
        ApprovalValueCoverage(if (it.parent == null) context.root else it.value, it.parent, it.key, it.index, it.first..it.last)
    })
}

internal fun approvalRawProjection(context: ApprovalContext): ApprovalReadingProjection {
    val writer = ApprovalPageWriter()
    // This is the complete original canonical JSON, not a reserialization of the structured display.
    // The root maps to all pages; acknowledging it requires the entire representation, including binding fields.
    writer.visibleCanonical(context.document.canonicalText())
    val pages = writer.finish()
    return ApprovalReadingProjection(pages, listOf(ApprovalValueCoverage(context.root, null, null, null, pages.indices)))
}

internal fun approvalVisibleText(value: String): String = buildString {
    var offset = 0
    while (offset < value.length) {
        val point = value.codePointAt(offset)
        if (approvalInvisible(point)) Character.toChars(point).forEach { append(approvalUnicodeEscape(it)) }
        else appendCodePoint(point)
        offset += Character.charCount(point)
    }
}

private fun approvalInvisible(point: Int): Boolean = Character.getType(point) == Character.FORMAT.toInt() ||
    Character.isISOControl(point) || point in 0x2028..0x2029

private fun approvalUnicodeEscape(char: Char): String = "\\u" + char.code.toString(16).padStart(4, '0')

/** Appends whole Unicode scalars and whole escape tokens. Even an expanded 128 KiB value has no hidden tail. */
private class ApprovalPageWriter {
    private val completed = arrayListOf<String>()
    private var current = StringBuilder()
    val pageIndex: Int get() = completed.size
    val lastContentPage: Int get() = if (current.isEmpty()) (completed.size - 1).coerceAtLeast(0) else completed.size
    private fun token(value: String) = atomic(value, 0, value.length)
    private fun atomic(value: String, start: Int, end: Int) {
        if (current.length + end - start > APPROVAL_READING_PAGE_SIZE) {
            completed += current.toString()
            current = StringBuilder()
        }
        current.append(value, start, end)
    }
    private fun slice(value: String, start: Int, end: Int) {
        var offset = start
        while (offset < end) {
            var next = minOf(end, offset + APPROVAL_READING_PAGE_SIZE - current.length)
            if (next < end && next > offset && value[next - 1].isHighSurrogate() && value[next].isLowSurrogate()) next--
            if (next == offset) {
                completed += current.toString()
                current = StringBuilder()
            } else {
                current.append(value, offset, next)
                offset = next
            }
        }
    }
    fun text(value: String) = slice(value, 0, value.length)
    fun quoted(value: String) {
        token("\"")
        var offset = 0
        var start = 0
        while (offset < value.length) {
            val point = value.codePointAt(offset)
            if (point == '"'.code || point == '\\'.code || approvalInvisible(point)) {
                slice(value, start, offset)
                when (point) {
                    '"'.code -> token("\\\"")
                    '\\'.code -> token("\\\\")
                    else -> Character.toChars(point).forEach { token(approvalUnicodeEscape(it)) }
                }
                start = offset + Character.charCount(point)
            }
            offset += Character.charCount(point)
        }
        slice(value, start, value.length)
        token("\"")
    }
    fun visibleCanonical(value: String) {
        var offset = 0
        var start = 0
        while (offset < value.length) {
            val point = value.codePointAt(offset)
            if (point == '\\'.code || approvalInvisible(point)) {
                slice(value, start, offset)
                if (point == '\\'.code) {
                    // Canonical JSON was validated: every existing escape has a complete token.
                    val end = offset + if (value[offset + 1] == 'u') 6 else 2
                    atomic(value, offset, end)
                    offset = end
                } else {
                    Character.toChars(point).forEach { token(approvalUnicodeEscape(it)) }
                    offset += Character.charCount(point)
                }
                start = offset
            } else offset += Character.charCount(point)
        }
        slice(value, start, value.length)
    }
    fun finish(): List<String> = completed + if (current.isNotEmpty()) listOf(current.toString()) else emptyList()
}
