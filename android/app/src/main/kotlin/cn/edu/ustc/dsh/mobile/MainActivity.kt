package cn.edu.ustc.dsh.mobile

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.biometric.BiometricManager
import androidx.browser.customtabs.CustomTabsIntent
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : FragmentActivity() {
    private val model: HomeViewModel by viewModels()
    override fun onStart() { super.onStart(); model.foreground(true) }
    override fun onStop() { model.foreground(false); super.onStop() }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        val biometrics = BiometricUi(this, model::promptOpened, model::authenticated, model::authenticationCancelled)
        biometrics.update(model.state.value.authenticationId, null)
        setContent {
            AppearanceHost(model.state) { HomeRoute(model, onSecuritySettings = ::securitySettings) { biometrics.cancel(); model.cancel() } }
        }
        NotificationOpen.parse(intent)?.let { model.openNotification(it.bindingId, it.notificationId) }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    model.appUpdateEvents.collect { event ->
                        val action = model.consumeAppUpdateLaunch(event) ?: return@collect
                        try { startActivity(action()) }
                        catch (_: Exception) { model.appUpdateLaunchFailed(event) }
                    }
                }
                model.state.collect { state ->
                    biometrics.update(state.authenticationId, state.biometric)
                    state.browser?.let { browser ->
                        model.browserOpened(browser.id)
                        try { CustomTabsIntent.Builder().setShowTitle(true).build().launchUrl(this@MainActivity, browser.uri) }
                        catch (_: Exception) { model.browserUnavailable() }
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        NotificationOpen.parse(intent)?.let { model.openNotification(it.bindingId, it.notificationId) }
    }

    private fun securitySettings() {
        val intent = if (Build.VERSION.SDK_INT >= 30) Intent(Settings.ACTION_BIOMETRIC_ENROLL)
            .putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED, BiometricManager.Authenticators.BIOMETRIC_STRONG)
        else Intent(Settings.ACTION_SECURITY_SETTINGS)
        runCatching { startActivity(intent) }
    }
}

@AndroidEntryPoint
class LoginRedirectActivity : androidx.activity.ComponentActivity() {
    @Inject lateinit var login: LoginController
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        intent.data?.toString()?.let(login::callback)
        startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP))
        finish()
    }
}
