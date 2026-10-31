package cn.edu.ustc.dsh.mobile

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun FailedMessageInput(original: MessageComposerState, enabled: Boolean,
    resolve: (MessageComposerState, Boolean) -> Unit) {
    var confirm by remember(original) { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(R.string.session_actions_input_recovery), style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton({ resolve(original, false) }, enabled = enabled, modifier = Modifier.heightIn(min = 48.dp)) {
                Text(stringResource(R.string.session_actions_keep_current))
            }
            TextButton({ confirm = true }, enabled = enabled, modifier = Modifier.heightIn(min = 48.dp)) {
                Text(stringResource(R.string.session_actions_recover_input))
            }
        }
    }
    if (confirm) AlertDialog(onDismissRequest = { confirm = false },
        title = { Text(stringResource(R.string.session_actions_replace_draft)) },
        text = { Text(stringResource(R.string.session_actions_recovery_detail)) },
        confirmButton = { TextButton({ confirm = false; resolve(original, true) }, enabled = enabled,
            modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.session_actions_confirm_recovery)) } },
        dismissButton = { TextButton({ confirm = false }, modifier = Modifier.heightIn(min = 48.dp)) {
            Text(stringResource(R.string.action_cancel))
        } })
}
