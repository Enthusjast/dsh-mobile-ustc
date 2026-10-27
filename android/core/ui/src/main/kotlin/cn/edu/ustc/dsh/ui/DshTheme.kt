package cn.edu.ustc.dsh.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val light = lightColorScheme(
    primary = Color(0xFF3F51B5),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE1E5FF),
    onPrimaryContainer = Color(0xFF172568),
    secondary = Color(0xFF535F76),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE0E7F4),
    onSecondaryContainer = Color(0xFF172034),
    tertiary = Color(0xFF765A00),
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFFFE08A),
    onTertiaryContainer = Color(0xFF251A00),
    background = Color(0xFFF7F8FC),
    onBackground = Color(0xFF191C23),
    surface = Color(0xFFF7F8FC),
    onSurface = Color(0xFF191C23),
    surfaceVariant = Color(0xFFE2E4EF),
    onSurfaceVariant = Color(0xFF444753),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color.White,
    surfaceContainer = Color(0xFFEEF0F7),
    surfaceContainerHigh = Color(0xFFE8EAF2),
    surfaceContainerHighest = Color(0xFFE2E4EC),
    outline = Color(0xFF747783),
    outlineVariant = Color(0xFFC4C6D3),
    inverseSurface = Color(0xFF2E3038),
    inverseOnSurface = Color(0xFFF0F1FA),
    inversePrimary = Color(0xFFBAC3FF),
    error = Color(0xFFBA1A1A),
    onError = Color.White,
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
)
private val dark = darkColorScheme(
    primary = Color(0xFFBAC3FF),
    onPrimary = Color(0xFF13236B),
    primaryContainer = Color(0xFF2A3C91),
    onPrimaryContainer = Color(0xFFE1E5FF),
    secondary = Color(0xFFBAC6DF),
    onSecondary = Color(0xFF253047),
    secondaryContainer = Color(0xFF3C485E),
    onSecondaryContainer = Color(0xFFDEE7FC),
    tertiary = Color(0xFFE9C349),
    onTertiary = Color(0xFF3E2E00),
    tertiaryContainer = Color(0xFF594400),
    onTertiaryContainer = Color(0xFFFFE08A),
    background = Color(0xFF11131A),
    onBackground = Color(0xFFE3E5EF),
    surface = Color(0xFF11131A),
    onSurface = Color(0xFFE3E5EF),
    surfaceVariant = Color(0xFF444753),
    onSurfaceVariant = Color(0xFFC4C6D3),
    surfaceContainerLowest = Color(0xFF0C0E14),
    surfaceContainerLow = Color(0xFF191B23),
    surfaceContainer = Color(0xFF1E2029),
    surfaceContainerHigh = Color(0xFF282A33),
    surfaceContainerHighest = Color(0xFF33353E),
    outline = Color(0xFF8E909D),
    outlineVariant = Color(0xFF444753),
    inverseSurface = Color(0xFFE3E5EF),
    inverseOnSurface = Color(0xFF2E3038),
    inversePrimary = Color(0xFF3F51B5),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
)

object DshSpacing {
    val extraSmall = 4.dp
    val small = 8.dp
    val medium = 12.dp
    val page = 16.dp
    val large = 24.dp
    val extraLarge = 32.dp
}

private val typography = Typography(
    headlineSmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        lineHeight = 32.sp,
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 22.sp,
        lineHeight = 28.sp,
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 18.sp,
        lineHeight = 26.sp,
    ),
    titleSmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 13.sp,
        lineHeight = 18.sp,
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp,
    ),
)

private val shapes = Shapes(
    extraSmall = RoundedCornerShape(12.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(16.dp),
)

@Composable
fun DshTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (darkTheme) dark else light,
        typography = typography,
        shapes = shapes,
        content = content,
    )
}
