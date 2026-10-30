package cn.edu.ustc.dsh.mobile

internal data class MessageTextRange(val start: Int, val end: Int) {
    fun text(source: String): String = source.substring(start, end)
}

/** Offsets refer to the immutable original message, never to a rewritten authority document. */
internal data class MessageInline(val range: MessageTextRange, val style: Int = 0, val link: MessageTextRange? = null)
internal const val MESSAGE_BOLD = 1
internal const val MESSAGE_ITALIC = 2
internal const val MESSAGE_CODE = 4

internal sealed interface MessageMarkdownBlock {
    val range: MessageTextRange
    data class Paragraph(override val range: MessageTextRange, val spans: List<MessageInline>) : MessageMarkdownBlock
    data class Heading(override val range: MessageTextRange, val level: Int, val spans: List<MessageInline>) : MessageMarkdownBlock
    data class ListItem(override val range: MessageTextRange, val depth: Int, val marker: String, val spans: List<MessageInline>) : MessageMarkdownBlock
    data class Quote(override val range: MessageTextRange, val spans: List<MessageInline>) : MessageMarkdownBlock
    data class Code(override val range: MessageTextRange, val content: MessageTextRange, val language: MessageTextRange?, val closed: Boolean) : MessageMarkdownBlock
    data class Table(override val range: MessageTextRange, val headers: List<List<MessageInline>>, val rows: List<List<List<MessageInline>>>) : MessageMarkdownBlock
    data class Plain(override val range: MessageTextRange) : MessageMarkdownBlock
}

internal data class MessageMarkdownDocument(val source: String, val visibleEnd: Int, val blocks: List<MessageMarkdownBlock>) {
    val formatted: Boolean get() = blocks.any { block ->
        when (block) {
            is MessageMarkdownBlock.Plain -> false
            is MessageMarkdownBlock.Paragraph -> block.spans.any { it.style != 0 || it.link != null }
            else -> true
        }
    }
}

/** A deliberately limited, bounded display grammar. No HTML, network, intents or executable options. */
internal fun parseMessageMarkdown(text: String, visibleEnd: Int): MessageMarkdownDocument {
    require(visibleEnd in 0..text.length)
    val end = if (visibleEnd in 1 until text.length && text[visibleEnd - 1].isHighSurrogate() && text[visibleEnd].isLowSurrogate()) visibleEnd - 1 else visibleEnd
    return MessageMarkdownParser(text, end).parse()
}

private class MessageMarkdownParser(private val source: String, private val end: Int) {
    private data class Line(val start: Int, val end: Int, val next: Int, val content: Int)
    private data class Fence(val character: Char, val count: Int, val info: Int)
    private var spanBudget = 4096
    private val separator = Regex(":?-{3,}:?")

    private fun line(start: Int): Line {
        val newline = source.indexOf('\n', start).let { if (it < 0 || it > end) end else it }
        val stop = if (newline > start && source[newline - 1] == '\r') newline - 1 else newline
        var content = start
        while (content < stop && source[content] == ' ') content++
        return Line(start, stop, if (newline < end) newline + 1 else end, content)
    }
    private fun fence(line: Line): Fence? {
        if (line.content - line.start > 3 || line.content == line.end) return null
        val ch = source[line.content]
        if (ch != '`' && ch != '~') return null
        var i = line.content
        while (i < line.end && source[i] == ch) i++
        return if (i - line.content >= 3) Fence(ch, i - line.content, i) else null
    }
    private fun heading(line: Line): Int {
        if (line.content - line.start > 3) return 0
        var i = line.content
        while (i < line.end && source[i] == '#') i++
        return if (i - line.content in 1..6 && i < line.end && source[i] == ' ') i - line.content else 0
    }
    private fun listContent(line: Line): Pair<String, Int>? {
        if (line.content == line.end || (line.content - line.start) / 2 > 8) return null
        val i = line.content
        if (source[i] in "-*+" && i + 1 < line.end && source[i + 1] == ' ') return "•" to i + 2
        var n = i
        while (n < line.end && source[n].isDigit()) n++
        return if (n > i && n + 1 < line.end && source[n] in ".)" && source[n + 1] == ' ')
            source.substring(i, n + 1) to n + 2 else null
    }
    private fun quote(line: Line) = line.content - line.start <= 3 && line.content < line.end && source[line.content] == '>'
    private fun blockStart(line: Line) = line.content == line.end || fence(line) != null || heading(line) > 0 || quote(line) || listContent(line) != null
    private fun trimmed(start: Int, stop: Int): MessageTextRange {
        var a = start; var b = stop
        while (a < b && source[a].isWhitespace()) a++
        while (b > a && source[b - 1].isWhitespace()) b--
        return MessageTextRange(a, b)
    }
    private fun cells(line: Line): List<MessageTextRange>? {
        val result = ArrayList<MessageTextRange>()
        var start = line.content; var i = start; var code = false; var pipes = 0
        if (i < line.end && source[i] == '|') { i++; start = i }
        while (i < line.end) {
            when (source[i]) {
                '\\' -> { i += 2; continue }
                '`' -> code = !code
                '|' -> if (!code) {
                    pipes++; result += trimmed(start, i); start = i + 1
                    if (result.size > 12) return null
                }
            }
            i++
        }
        if (pipes == 0) return null
        if (start < line.end || source.getOrNull(line.end - 1) != '|') result += trimmed(start, line.end)
        return result.takeIf { it.isNotEmpty() && it.size <= 12 }
    }
    private fun tableHeader(first: Line): Pair<List<MessageTextRange>, Line>? {
        if (first.next >= end) return null
        val header = cells(first) ?: return null
        val second = line(first.next)
        val separators = cells(second) ?: return null
        return if (header.size == separators.size && separators.all { separator.matches(it.text(source)) }) header to second else null
    }

    fun parse(): MessageMarkdownDocument {
        val blocks = ArrayList<MessageMarkdownBlock>()
        var at = 0
        while (at < end) {
            if (blocks.size >= 511 || spanBudget == 0) { blocks += MessageMarkdownBlock.Plain(MessageTextRange(at, end)); break }
            val first = line(at)
            if (first.content == first.end) { at = first.next; continue }
            val opening = fence(first)
            if (opening != null) {
                var cursor = first.next; var closing: Line? = null
                while (cursor < end) {
                    val candidate = line(cursor)
                    val f = fence(candidate)
                    if (f != null && f.character == opening.character && f.count >= opening.count &&
                        source.substring(f.info, candidate.end).isBlank()) { closing = candidate; break }
                    cursor = candidate.next
                }
                var languageStart = opening.info
                while (languageStart < first.end && source[languageStart].isWhitespace()) languageStart++
                var languageEnd = languageStart
                while (languageEnd < first.end && !source[languageEnd].isWhitespace()) languageEnd++
                val next = closing?.next ?: end
                blocks += MessageMarkdownBlock.Code(MessageTextRange(at, next), MessageTextRange(first.next, closing?.start ?: end),
                    if (languageStart < languageEnd) MessageTextRange(languageStart, languageEnd) else null, closing != null)
                at = next; continue
            }
            val table = tableHeader(first)
            if (table != null) {
                val rows = ArrayList<List<List<MessageInline>>>()
                val headers = table.first.map { inline(it.start, it.end) }
                var cursor = table.second.next
                while (cursor < end && rows.size < 64 && spanBudget > 0) {
                    val next = line(cursor)
                    val values = cells(next)?.takeIf { it.size == headers.size } ?: break
                    rows += values.map { inline(it.start, it.end) }
                    cursor = next.next
                }
                blocks += MessageMarkdownBlock.Table(MessageTextRange(at, cursor), headers, rows)
                at = cursor; continue
            }
            val level = heading(first)
            val list = listContent(first)
            when {
                level > 0 -> blocks += MessageMarkdownBlock.Heading(MessageTextRange(at, first.next), level, inline(first.content + level + 1, first.end))
                quote(first) -> {
                    val start = first.content + 1 + if (source.getOrNull(first.content + 1) == ' ') 1 else 0
                    blocks += MessageMarkdownBlock.Quote(MessageTextRange(at, first.next), inline(start, first.end))
                }
                list != null -> blocks += MessageMarkdownBlock.ListItem(MessageTextRange(at, first.next), (first.content - first.start) / 2, list.first, inline(list.second, first.end))
                else -> {
                    var cursor = first.next; var stop = first.end
                    while (cursor < end) {
                        val next = line(cursor)
                        if (blockStart(next) || tableHeader(next) != null) break
                        stop = next.end; cursor = next.next
                    }
                    blocks += MessageMarkdownBlock.Paragraph(MessageTextRange(at, cursor), inline(at, stop))
                    at = cursor; continue
                }
            }
            at = first.next
        }
        return MessageMarkdownDocument(source, end, blocks)
    }

    private fun inline(start: Int, stop: Int, depth: Int = 0, style: Int = 0, link: MessageTextRange? = null): List<MessageInline> {
        if (start == stop) return emptyList()
        val result = ArrayList<MessageInline>()
        fun emit(a: Int, b: Int, flags: Int = style, target: MessageTextRange? = link) {
            if (b > a) { result += MessageInline(MessageTextRange(a, b), flags, target); if (spanBudget > 0) spanBudget-- }
        }
        if (depth >= 4 || spanBudget == 0) { emit(start, stop); return result }
        var at = start; var plain = start
        fun flush() { emit(plain, at) }
        while (at < stop && spanBudget > 1) {
            val c = source[at]
            if (c == '\\' && at + 1 < stop && !source[at + 1].isLetterOrDigit() && !source[at + 1].isWhitespace()) {
                flush(); emit(at + 1, at + 2); at += 2; plain = at; continue
            }
            if (c == '!' && at + 1 < stop && source[at + 1] == '[') {
                val bracket = source.indexOf(']', at + 2).takeIf { it in (at + 2) until stop }
                val closing = if (bracket != null && source.getOrNull(bracket + 1) == '(') closeParenthesis(bracket + 1, stop) else null
                flush(); val next = closing?.plus(1) ?: stop; emit(at, next, style, null); at = next; plain = at; continue
            }
            if (c == '`' || c == '*') {
                val marker = if (c == '*' && at + 1 < stop && source[at + 1] == '*') "**" else c.toString()
                val close = source.indexOf(marker, at + marker.length)
                if (close < 0 || close >= stop) { break }
                if (close > at + marker.length) {
                    flush()
                    if (c == '`') emit(at + 1, close, style or MESSAGE_CODE, null)
                    else result += inline(at + marker.length, close, depth + 1, style or if (marker.length == 2) MESSAGE_BOLD else MESSAGE_ITALIC, link)
                    at = close + marker.length; plain = at; continue
                }
            }
            if (c == '[') {
                val bracket = source.indexOf(']', at + 1)
                if (bracket < 0 || bracket >= stop) break
                if (source.getOrNull(bracket + 1) == '(') {
                    val close = closeParenthesis(bracket + 1, stop)
                    if (close != null && bracket > at + 1) {
                        flush(); result += inline(at + 1, bracket, depth + 1, style, MessageTextRange(bracket + 2, close))
                        at = close + 1; plain = at; continue
                    }
                    // A truncated labelled link stays plain, including any URL-looking tail.
                    break
                }
            }
            if (link == null && (source.regionMatches(at, "https://", 0, 8, true) || source.regionMatches(at, "http://", 0, 7, true))) {
                var next = at
                while (next < stop && !source[next].isWhitespace() && source[next] !in "<>[]()") next++
                if (!(next == end && end < source.length)) {
                    flush(); emit(at, next, style, MessageTextRange(at, next)); at = next; plain = at; continue
                }
                at = next; continue
            }
            at++
        }
        emit(plain, stop)
        return result
    }

    private fun closeParenthesis(open: Int, stop: Int): Int? {
        var nesting = 1; var i = open + 1
        while (i < stop) {
            when (source[i]) {
                '\\' -> { i += 2; continue }
                '(' -> { nesting++; if (nesting > 4) return null }
                ')' -> { nesting--; if (nesting == 0) return i }
                '\n', '\r' -> return null
            }
            i++
        }
        return null
    }
}
