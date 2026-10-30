package cn.edu.ustc.dsh.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.error
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** A status-bar-aware title row that grows with its text instead of clipping large fonts. */
@Composable
fun DshTopBar(
    title: String,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
    navigationIcon: @Composable () -> Unit = {},
    actions: @Composable RowScope.() -> Unit = {},
    contentMaxWidth: Dp = 800.dp,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surface,
        contentColor = MaterialTheme.colorScheme.onSurface,
    ) {
        Column(
            Modifier.fillMaxWidth()
                .windowInsetsPadding(WindowInsets.statusBars.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Column(Modifier.widthIn(max = contentMaxWidth).fillMaxWidth()) {
                Row(
                    Modifier.fillMaxWidth().heightIn(min = 56.dp).padding(horizontal = DshSpacing.page),
                    horizontalArrangement = Arrangement.spacedBy(DshSpacing.small),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    navigationIcon()
                    Text(
                        text = title,
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.weight(1f).semantics { heading() },
                    )
                    actions()
                }
                if (!subtitle.isNullOrEmpty()) {
                    Text(
                        text = subtitle,
                        modifier = Modifier.fillMaxWidth().padding(horizontal = DshSpacing.page).padding(bottom = DshSpacing.small),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

/** An inline status message; the supplied text must explain the status without color alone. */
@Composable
fun DshStatusNotice(
    text: String,
    modifier: Modifier = Modifier,
    isError: Boolean = false,
) {
    Surface(
        modifier = modifier
            .fillMaxWidth()
            .semantics(mergeDescendants = true) {
                liveRegion = LiveRegionMode.Polite
                if (isError) error(text)
            },
        shape = MaterialTheme.shapes.small,
        color = if (isError) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surfaceContainer,
        contentColor = if (isError) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSurface,
    ) {
        Text(
            text = text,
            modifier = Modifier.padding(horizontal = DshSpacing.medium, vertical = DshSpacing.small),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}
