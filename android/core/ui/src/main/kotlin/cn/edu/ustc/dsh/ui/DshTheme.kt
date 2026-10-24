package cn.edu.ustc.dsh.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val light = lightColorScheme(
    primary = Color(0xFF3F51B5), onPrimary = Color.White,
    primaryContainer = Color(0xFFE1E5FF), onPrimaryContainer = Color(0xFF172568),
    secondary = Color(0xFF535F76), secondaryContainer = Color(0xFFE0E7F4), onSecondaryContainer = Color(0xFF172034),
    background = Color(0xFFF7F8FC), surface = Color(0xFFF7F8FC), onSurface = Color(0xFF191C23),
    surfaceContainer = Color(0xFFEEF0F7), surfaceContainerLow = Color.White,
    onSurfaceVariant = Color(0xFF444753), outline = Color(0xFF747783), error = Color(0xFFBA1A1A),
)
private val dark = darkColorScheme(
    primary = Color(0xFFBAC3FF), onPrimary = Color(0xFF13236B),
    primaryContainer = Color(0xFF2A3C91), onPrimaryContainer = Color(0xFFE1E5FF),
    secondary = Color(0xFFBAC6DF), secondaryContainer = Color(0xFF3C485E), onSecondaryContainer = Color(0xFFDEE7FC),
    background = Color(0xFF11131A), surface = Color(0xFF11131A), onSurface = Color(0xFFE3E5EF),
    surfaceContainer = Color(0xFF1E2029), surfaceContainerLow = Color(0xFF191B23),
    onSurfaceVariant = Color(0xFFC4C6D3), outline = Color(0xFF8E909D), error = Color(0xFFFFB4AB),
)

@Composable
fun DshTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (darkTheme) dark else light, typography = Typography(), content = content)
}
