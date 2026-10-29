package cn.edu.ustc.dsh.mobile

import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.LinkInteractionListener
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

private val webLinks = Regex("https?://[^\\s<>\\[\\]()]+", RegexOption.IGNORE_CASE)

private fun safeWebTarget(value: String): Boolean = runCatching {
    val uri = Uri.parse(value)
    uri.scheme?.lowercase() in setOf("http", "https") && !uri.host.isNullOrBlank() && uri.userInfo == null && value.none { it.isISOControl() }
}.getOrDefault(false)

/** No HTML, automatic link launches, remote resources or generated intents. */
@Composable
internal fun RichMessageText(text: String, initial: Int = 16 * 1024) {
    var limit by remember { mutableIntStateOf(initial) }
    var requestedLink by remember { mutableStateOf<String?>(null) }
    var linkFailed by remember { mutableStateOf(false) }
    val uriHandler = LocalUriHandler.current
    val context = LocalContext.current
    val linkColor = MaterialTheme.colorScheme.primary
    val end = minOf(limit, text.length).let { if (it in 1 until text.length && text[it - 1].isHighSurrogate() && text[it].isLowSurrogate()) it - 1 else it }
    val visible = remember(text, end) { text.substring(0, end) }
    val segments = remember(visible) { visible.split("```") }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        segments.forEachIndexed { index, segment ->
            if (index % 2 == 1) {
                val clipboard = LocalClipboardManager.current
                Surface(color = MaterialTheme.colorScheme.surfaceContainerHigh, shape = MaterialTheme.shapes.small) {
                    Column(Modifier.fillMaxWidth().padding(12.dp)) {
                        SelectionContainer { Text(segment, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium) }
                        if (index < segments.lastIndex || end == text.length) {
                            TextButton({ clipboard.setText(AnnotatedString(segment)) }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_copy_code)) }
                        }
                    }
                }
            } else {
                val candidates = remember(segment, end == text.length, index == segments.lastIndex) {
                    webLinks.findAll(segment).filter { match ->
                        !(index == segments.lastIndex && end < text.length && match.range.last == segment.lastIndex) && safeWebTarget(match.value)
                    }.take(129).toList()
                }
                val links = candidates.take(128)
                val actions = links.map { match ->
                    CustomAccessibilityAction(context.getString(R.string.chat_link_accessibility, match.value)) {
                        requestedLink = match.value
                        true
                    }
                }
                val formatted = remember(segment, linkColor, candidates) {
                    buildAnnotatedString {
                        append(segment)
                        var lineStart = 0
                        while (lineStart < segment.length) {
                            val lineEnd = segment.indexOf('\n', lineStart).let { if (it < 0) segment.length else it }
                            var marker = lineStart
                            while (marker < lineEnd && segment[marker] == '#') marker++
                            if (marker - lineStart in 1..6 && marker < lineEnd && segment[marker] == ' ') {
                                addStyle(SpanStyle(fontWeight = FontWeight.SemiBold), lineStart, lineEnd)
                            }
                            lineStart = lineEnd + 1
                        }
                        links.forEach { match ->
                            val url = match.value
                            addLink(LinkAnnotation.Clickable(url, TextLinkStyles(style = SpanStyle(color = linkColor, textDecoration = TextDecoration.Underline)),
                                LinkInteractionListener { link -> requestedLink = (link as LinkAnnotation.Clickable).tag }),
                                match.range.first, match.range.first + url.length)
                        }
                    }
                }
                SelectionContainer { Text(formatted, modifier = Modifier.semantics { customActions = actions }, style = MaterialTheme.typography.bodyLarge) }
                if (candidates.size > 128) Text(stringResource(R.string.chat_link_limit), style = MaterialTheme.typography.bodySmall)
            }
        }
        if (end < text.length) TextButton({ limit = (limit.toLong() + 16 * 1024).coerceAtMost(Int.MAX_VALUE.toLong()).toInt() }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_show_more)) }
    }
    requestedLink?.let { target ->
        AlertDialog(onDismissRequest = { requestedLink = null }, title = { Text(stringResource(R.string.chat_link_title)) },
            text = { SelectionContainer { Text(target) } },
            confirmButton = { TextButton({ requestedLink = null; linkFailed = runCatching { uriHandler.openUri(target) }.isFailure }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_link_open)) } },
            dismissButton = { TextButton({ requestedLink = null }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_link_cancel)) } })
    }
    if (linkFailed) AlertDialog(onDismissRequest = { linkFailed = false }, title = { Text(stringResource(R.string.chat_link_failed)) },
        confirmButton = { TextButton({ linkFailed = false }, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.chat_link_cancel)) } })
}
