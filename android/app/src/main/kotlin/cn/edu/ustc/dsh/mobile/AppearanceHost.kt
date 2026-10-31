package cn.edu.ustc.dsh.mobile

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.platform.LocalContext
import androidx.core.view.WindowCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import cn.edu.ustc.dsh.command.CommandOwner
import cn.edu.ustc.dsh.ui.DshTheme
import cn.edu.ustc.dsh.ui.LocalDshReadingStyle
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map

internal class AndroidAppearanceStorage(context: Context) : AppearanceScalarStorage {
    private val application = context.applicationContext
    private fun storedPreferences(ownerKey: String) =
        application.getSharedPreferences("appearance-v1-$ownerKey", Context.MODE_PRIVATE)

    override fun read(ownerKey: String): AppearancePreferences = storedPreferences(ownerKey).let { stored ->
        val theme = stored.getString("theme", null)
        AppearancePreferences(
            theme = AppearanceTheme.entries.firstOrNull { it.name == theme } ?: AppearanceTheme.SYSTEM,
            bodyScale = stored.getFloat("body_scale", 1f),
            codeScale = stored.getFloat("code_scale", 1f),
            wrapCode = stored.getBoolean("wrap_code", false),
        ).bounded()
    }

    override fun write(ownerKey: String, preferences: AppearancePreferences): Boolean {
        val bounded = preferences.bounded()
        return storedPreferences(ownerKey).edit()
            .putString("theme", bounded.theme.name)
            .putFloat("body_scale", bounded.bodyScale)
            .putFloat("code_scale", bounded.codeScale)
            .putBoolean("wrap_code", bounded.wrapCode)
            .commit()
    }
}

internal val LocalAppearanceSession = staticCompositionLocalOf<AppearanceSession?> { null }

/** Observes presentation identity only; transcript changes never reload preferences. */
@Composable
fun AppearanceHost(states: StateFlow<HomeState>, content: @Composable () -> Unit) {
    val scopes = remember(states) { states.map { it.appearanceScope() }.distinctUntilChanged() }
    val scope by scopes.collectAsStateWithLifecycle(initialValue = AppearanceScope(HomePhase.LOADING, null))
    val context = LocalContext.current
    val storage = remember(context.applicationContext) { AndroidAppearanceStorage(context) }
    val session = remember(scope, storage) { scope.ownerKey?.let { AppearanceSession(it, storage) } }
    LaunchedEffect(session) { session?.load() }
    val preferences = key(session) {
        if (session == null) AppearancePreferences()
        else session.state.collectAsStateWithLifecycle().value.preferences
    }
    val systemDark = isSystemInDarkTheme()
    val dark = when (preferences.theme) {
        AppearanceTheme.SYSTEM -> systemDark
        AppearanceTheme.LIGHT -> false
        AppearanceTheme.DARK -> true
    }
    SideEffect {
        context.appearanceActivity()?.window?.let { window ->
            WindowCompat.getInsetsController(window, window.decorView).apply {
                isAppearanceLightStatusBars = !dark
                isAppearanceLightNavigationBars = !dark
            }
        }
    }
    DshTheme(darkTheme = dark) {
        CompositionLocalProvider(
            LocalDshReadingStyle provides preferences.readingStyle(),
            LocalAppearanceSession provides session,
            content = content,
        )
    }
}

/** Standalone UI fixtures can use the screen without constructing an authentication host. */
@Composable
internal fun rememberAppearanceSession(owner: CommandOwner): AppearanceSession {
    val hosted = LocalAppearanceSession.current
    if (hosted?.ownerKey == owner.fingerprint) return hosted
    val context = LocalContext.current
    val session = remember(context.applicationContext, owner.fingerprint) {
        AppearanceSession(owner.fingerprint, AndroidAppearanceStorage(context))
    }
    LaunchedEffect(session) { session.load() }
    return session
}

private tailrec fun Context.appearanceActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.appearanceActivity()
    else -> null
}
