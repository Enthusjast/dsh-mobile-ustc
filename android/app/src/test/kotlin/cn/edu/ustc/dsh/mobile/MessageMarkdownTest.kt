package cn.edu.ustc.dsh.mobile

import org.junit.Assert.*
import org.junit.Test

class MessageMarkdownTest {
    private fun parse(text: String, end: Int = text.length) = parseMessageMarkdown(text, end)
    private fun text(source: String, spans: List<MessageInline>) = spans.joinToString("") { it.range.text(source) }

    @Test fun technicalContentKeepsItsMeaningAndCodeCopyRangeExcludesTheFenceAndLanguage() {
        val source = "# 实验🙂\n\n**重要**与*补充*和`a < b`\n- 第一项\n  2. 第二项\n> 引用\n```python\nprint(42)\n```\n"
        val doc = parse(source)
        assertEquals("实验🙂", text(source, (doc.blocks.first() as MessageMarkdownBlock.Heading).spans))
        val paragraph = doc.blocks.filterIsInstance<MessageMarkdownBlock.Paragraph>().single()
        assertEquals("重要与补充和a < b", text(source, paragraph.spans))
        assertEquals(listOf(MESSAGE_BOLD, MESSAGE_ITALIC, MESSAGE_CODE), paragraph.spans.filter { it.style != 0 }.map { it.style })
        assertEquals(listOf(0, 1), doc.blocks.filterIsInstance<MessageMarkdownBlock.ListItem>().map { it.depth })
        val code = doc.blocks.filterIsInstance<MessageMarkdownBlock.Code>().single()
        assertEquals("python", code.language!!.text(source)); assertEquals("print(42)\n", code.content.text(source)); assertTrue(code.closed)
    }
    @Test fun tablesDoNotSplitEscapedOrInlineCodePipesOrLoseEmptyCells() {
        val source = "| A | B | C |\n| --- | :---: | ---: |\n| x\\|y | `a|b` | |\n"
        val table = parse(source).blocks.single() as MessageMarkdownBlock.Table
        assertEquals(3, table.headers.size)
        assertEquals(listOf("x|y", "a|b", ""), table.rows.single().map { text(source, it) })
    }
    @Test fun incompleteLinksAndCodeNeverTurnAHiddenTailIntoAnAction() {
        val source = "[报告](https://example.invalid/path) and https://example.invalid/long-tail"
        val partial = parse(source, source.indexOf("path") + 2)
        val spans = (partial.blocks.single() as MessageMarkdownBlock.Paragraph).spans
        assertTrue(spans.none { it.link != null })
        val complete = (parse(source).blocks.single() as MessageMarkdownBlock.Paragraph).spans
        assertEquals(listOf("https://example.invalid/path", "https://example.invalid/long-tail"), complete.mapNotNull { it.link?.text(source) })
        val codeText = "~~~sh\necho https://example.invalid\n"
        val code = parse(codeText).blocks.single() as MessageMarkdownBlock.Code
        assertFalse(code.closed); assertEquals("echo https://example.invalid\n", code.content.text(codeText))
    }
    @Test fun imagesAndLiteralCodeCannotCreateHiddenResourceRequests() {
        val source = "![alt](https://example.invalid/image.png)\n\n`https://example.invalid/code`"
        val paragraphs = parse(source).blocks.filterIsInstance<MessageMarkdownBlock.Paragraph>()
        assertEquals(source.substringBefore("\n"), text(source, paragraphs.first().spans))
        assertTrue(paragraphs.flatMap { it.spans }.none { it.link != null })
    }
    @Test fun budgetsAndUnicodeBoundariesLeaveAnExplicitReadableTail() {
        val source = "# 标题\n".repeat(600) + "TAIL🙂"
        val doc = parse(source)
        assertTrue(doc.blocks.size <= 512)
        assertTrue((doc.blocks.last() as MessageMarkdownBlock.Plain).range.text(source).endsWith("TAIL🙂"))
        val emoji = "x🙂tail"
        assertEquals(1, parse(emoji, 2).visibleEnd)
        val table = "a|b\n---|---\n" + "x|y\n".repeat(80) + "END"
        val all = parse(table)
        assertEquals(64, (all.blocks.first() as MessageMarkdownBlock.Table).rows.size)
        assertTrue(all.blocks.last().range.text(table).contains("END"))
    }
    @Test fun anUnclosedEmphasisIsReadableRatherThanInventingFormattingOrDroppingItsTail() {
        val source = "prefix **unfinished🙂"
        val doc = parse(source)
        val paragraph = doc.blocks.single() as MessageMarkdownBlock.Paragraph
        assertEquals(source, text(source, paragraph.spans))
        assertFalse(doc.formatted)
    }
}
