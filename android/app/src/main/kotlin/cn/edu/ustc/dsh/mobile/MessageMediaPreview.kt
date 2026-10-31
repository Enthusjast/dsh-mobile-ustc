package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy

/** Only the caller's explicitly requested, foreground-owned bitmap is rendered. */
@Composable
fun MessageMediaPreview(state: SessionImageState, onDismiss: () -> Unit) {
    if (!state.previewRequested) return
    val height = LocalConfiguration.current.screenHeightDp.dp
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn, usePlatformDefaultWidth = false),
    ) {
        Surface(
            modifier = Modifier.padding(16.dp).widthIn(max = 720.dp).fillMaxWidth().heightIn(max = height * 0.9f),
            shape = MaterialTheme.shapes.extraLarge,
            tonalElevation = 6.dp,
        ) {
            Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text(stringResource(R.string.media_preview_title), style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.semantics { heading() })
                Column(Modifier.weight(1f, fill = false).verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    val preview = state.preview
                    if (preview != null) {
                        Text(preview.name, style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.testTag("media-preview-name"))
                        Text(stringResource(if (preview.historical) R.string.media_preview_history else R.string.media_preview_local),
                            style = MaterialTheme.typography.bodySmall)
                    }
                    if (state.previewLoading) {
                        LinearProgressIndicator(Modifier.fillMaxWidth())
                        Text(stringResource(R.string.media_preview_loading),
                            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                    } else if (state.error != null) {
                        Text(stringResource(imageErrorResource(state.error)), color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                    } else if (preview != null && !preview.bitmap.isRecycled) {
                        Image(
                            bitmap = preview.bitmap.asImageBitmap(),
                            contentDescription = stringResource(R.string.media_preview_description, preview.name),
                            modifier = Modifier.fillMaxWidth().height((height * 0.5f).coerceAtMost(480.dp))
                                .testTag("media-preview-bitmap"),
                            contentScale = ContentScale.Fit,
                        )
                    } else {
                        Text(stringResource(R.string.media_preview_unavailable), color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                    }
                }
                TextButton(onDismiss, Modifier.align(Alignment.End).heightIn(min = 48.dp)) {
                    Text(stringResource(R.string.media_preview_close))
                }
            }
        }
    }
}
