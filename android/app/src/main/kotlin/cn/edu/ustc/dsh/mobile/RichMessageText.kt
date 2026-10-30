package cn.edu.ustc.dsh.mobile

import android.net.Uri
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.*
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

private fun safeWebTarget(value: String): Boolean = runCatching {
    val uri = Uri.parse(value)
    uri.scheme?.lowercase() in setOf("http", "https") && !uri.host.isNullOrBlank() && uri.userInfo == null && value.none { it.isISOControl() }
}.getOrDefault(false)

private data class PreparedMessage(val document: MessageMarkdownDocument, val links: Map<MessageTextRange, String>, val excessLinks: Boolean)

private fun MessageMarkdownDocument.forEachSpan(action: (MessageInline) -> Unit) {
    for (block in blocks) when (block) {
        is MessageMarkdownBlock.Paragraph -> block.spans.forEach(action)
        is MessageMarkdownBlock.Heading -> block.spans.forEach(action)
        is MessageMarkdownBlock.ListItem -> block.spans.forEach(action)
        is MessageMarkdownBlock.Quote -> block.spans.forEach(action)
        is MessageMarkdownBlock.Table -> {
            block.headers.forEach { it.forEach(action) }
            block.rows.forEach { row -> row.forEach { it.forEach(action) } }
        }
        else -> Unit
    }
}

/** Presentation only. No HTML, remote resources, automatic launches or generated intents. */
@Composable
internal fun RichMessageText(text: String, initial: Int = 16 * 1024) {
    var limit by remember { mutableIntStateOf(initial.coerceAtLeast(1)) }
    var raw by remember { mutableStateOf(false) }
    var requestedLink by remember(text) { mutableStateOf<String?>(null) }
    var linkFailed by remember { mutableStateOf(false) }
    val end = minOf(limit, text.length).let { if (it in 1 until text.length && text[it - 1].isHighSurrogate() && text[it].isLowSurrogate()) it - 1 else it }
    val prepared by produceState<PreparedMessage?>(null, text, end) {
        value = withContext(Dispatchers.Default) {
            val document = parseMessageMarkdown(text, end)
            val links = linkedMapOf<MessageTextRange, String>()
            var excess = false
            document.forEachSpan { span -> span.link?.let { range ->
                if (range !in links && links.size <= 128) {
                    val target = range.text(text)
                    if (safeWebTarget(target)) {
                        if (links.size < 128) links[range] = target else excess = true
                    }
                }
            } }
            PreparedMessage(document, links, excess)
        }
    }
    val current = prepared?.takeIf { it.document.source === text && it.document.visibleEnd == end }
    val uriHandler = LocalUriHandler.current
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (current?.document?.formatted == true) TextButton({ raw = !raw }, Modifier.heightIn(min = 48.dp)) {
            Text(stringResource(if (raw) R.string.chat_formatted else R.string.chat_raw))
        }
        if (current == null || raw) {
            SelectionContainer { Text(text.substring(0, end), style = MaterialTheme.typography.bodyLarge) }
        } else for (block in current.document.blocks) key(block.range.start) {
            when (block) {
                is MessageMarkdownBlock.Paragraph -> MessageInlineText(current, block.spans, onLink = { requestedLink = it })
                is MessageMarkdownBlock.Plain -> SelectionContainer { Text(block.range.text(text), style = MaterialTheme.typography.bodyLarge) }
                is MessageMarkdownBlock.Heading -> MessageInlineText(current, block.spans,
                    Modifier.semantics { heading() }, when (block.level) {
                        1 -> MaterialTheme.typography.titleLarge
                        2 -> MaterialTheme.typography.titleMedium
                        else -> MaterialTheme.typography.titleSmall
                    }, onLink = { requestedLink = it })
                is MessageMarkdownBlock.ListItem -> Row(Modifier.padding(start = (block.depth * 12).dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(block.marker, style = MaterialTheme.typography.bodyLarge)
                    MessageInlineText(current, block.spans, Modifier.weight(1f), onLink = { requestedLink = it })
                }
                is MessageMarkdownBlock.Quote -> {
                    val color = MaterialTheme.colorScheme.outlineVariant
                    MessageInlineText(current, block.spans, Modifier.drawBehind {
                        drawLine(color, Offset.Zero, Offset(0f, size.height), 2.dp.toPx())
                    }.padding(start = 12.dp), onLink = { requestedLink = it })
                }
                is MessageMarkdownBlock.Code -> MessageCode(text, block, end < text.length)
                is MessageMarkdownBlock.Table -> Column(Modifier.horizontalScroll(rememberScrollState())) {
                    MessageTableRow(current, block.headers, true) { requestedLink = it }
                    block.rows.forEach { row -> MessageTableRow(current, row, false) { requestedLink = it } }
                }
            }
        }
        if (current?.excessLinks == true && !raw) Text(stringResource(R.string.chat_link_limit), style = MaterialTheme.typography.bodySmall)
        if (end < text.length) TextButton({ limit = (limit.toLong() + 16 * 1024).coerceAtMost(Int.MAX_VALUE.toLong()).toInt() }, Modifier.heightIn(min = 48.dp)) {
            Text(stringResource(R.string.chat_show_more))
        }
    }
    requestedLink?.let { target ->
        AlertDialog(onDismissRequest = { requestedLink = null }, title = { Text(stringResource(R.string.chat_link_title)) },
            text = { SelectionContainer { Text(target) } },
            confirmButton = { TextButton({ requestedLink = null; linkFailed = !safeWebTarget(target) || runCatching { uriHandler.openUri(target) }.isFailure }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_link_open)) } },
            dismissButton = { TextButton({ requestedLink = null }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_link_cancel)) } })
    }
    if (linkFailed) AlertDialog(onDismissRequest = { linkFailed = false }, title = { Text(stringResource(R.string.chat_link_failed)) },
        confirmButton = { TextButton({ linkFailed = false }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_link_cancel)) } })
}

@Composable
private fun MessageInlineText(message: PreparedMessage, spans: List<MessageInline>, modifier: Modifier = Modifier,
    style: TextStyle = MaterialTheme.typography.bodyLarge, onLink: (String) -> Unit) {
    val color = MaterialTheme.colorScheme.primary
    val context = LocalContext.current
    val latestLink by rememberUpdatedState(onLink)
    val formatted = remember(message, spans, color) {
        buildAnnotatedString {
            spans.forEach { span ->
                val start = length
                append(message.document.source, span.range.start, span.range.end)
                if (span.style and MESSAGE_BOLD != 0) addStyle(SpanStyle(fontWeight = FontWeight.SemiBold), start, length)
                if (span.style and MESSAGE_ITALIC != 0) addStyle(SpanStyle(fontStyle = FontStyle.Italic), start, length)
                if (span.style and MESSAGE_CODE != 0) addStyle(SpanStyle(fontFamily = FontFamily.Monospace), start, length)
                message.links[span.link]?.let { target ->
                    addLink(LinkAnnotation.Clickable(target,
                        TextLinkStyles(SpanStyle(color = color, textDecoration = TextDecoration.Underline)),
                        LinkInteractionListener { latestLink(target) }), start, length)
                }
            }
        }
    }
    val actions = remember(message, spans, context) {
        spans.mapNotNull { message.links[it.link] }.distinct().map { target ->
            CustomAccessibilityAction(context.getString(R.string.chat_link_accessibility, target)) { latestLink(target); true }
        }
    }
    SelectionContainer { Text(formatted, modifier.semantics { customActions = actions }, style = style) }
}

@Composable
private fun MessageCode(source: String, block: MessageMarkdownBlock.Code, truncated: Boolean) {
    val clipboard = LocalClipboardManager.current
    val content = remember(source, block.content) { block.content.text(source) }
    var copied by remember(content) { mutableStateOf(false) }
    LaunchedEffect(copied) { if (copied) { delay(2000); copied = false } }
    val complete = block.closed || !truncated
    Surface(color = MaterialTheme.colorScheme.surfaceContainerHigh, shape = MaterialTheme.shapes.small) {
        Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                Text(block.language?.text(source) ?: stringResource(R.string.chat_code), Modifier.weight(1f),
                    style = MaterialTheme.typography.labelMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                TextButton({ clipboard.setText(AnnotatedString(content)); copied = true }, enabled = complete,
                    modifier = Modifier.heightIn(min = 48.dp).semantics { liveRegion = LiveRegionMode.Polite }) {
                    Text(stringResource(if (copied) R.string.chat_copied else if (block.closed) R.string.chat_copy_code else R.string.chat_copy_visible_code))
                }
            }
            SelectionContainer { Text(content, Modifier.horizontalScroll(rememberScrollState()),
                fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, softWrap = false) }
            if (!complete) Text(stringResource(R.string.chat_code_incomplete), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun MessageTableRow(message: PreparedMessage, cells: List<List<MessageInline>>, header: Boolean, onLink: (String) -> Unit) {
    Row {
        cells.forEach { spans ->
            Surface(color = if (header) MaterialTheme.colorScheme.surfaceContainer else MaterialTheme.colorScheme.surface) {
                MessageInlineText(message, spans, Modifier.width(180.dp).border(1.dp, MaterialTheme.colorScheme.outlineVariant).padding(12.dp),
                    if (header) MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.SemiBold) else MaterialTheme.typography.bodyLarge, onLink)
            }
        }
    }
}
