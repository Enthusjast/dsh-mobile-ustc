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
import androidx.biometric.BiometricPrompt
import androidx.browser.customtabs.CustomTabsIntent
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import cn.edu.ustc.dsh.ui.DshTheme
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : FragmentActivity() {
    private val model: HomeViewModel by viewModels()
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        fun attachPrompt(id: Long) = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) { model.authenticated(id, result) }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) { model.authenticationCancelled(id) }
        })
        var prompt: BiometricPrompt? = model.state.value.authenticationId?.let(::attachPrompt)
        setContent {
            DshTheme { HomeRoute(model, onSecuritySettings = ::securitySettings) { prompt?.cancelAuthentication(); model.cancel() } }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                model.state.collect { state ->
                    state.browser?.let { browser ->
                        model.browserOpened(browser.id)
                        try { CustomTabsIntent.Builder().setShowTitle(true).build().launchUrl(this@MainActivity, browser.uri) }
                        catch (_: Exception) { model.browserUnavailable() }
                    }
                    state.biometric?.let { biometric ->
                        val activePrompt = attachPrompt(biometric.id)
                        prompt = activePrompt
                        model.promptOpened(biometric.id)
                        try {
                            activePrompt.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle("确认登记此设备")
                                .setSubtitle("将这部手机的独立密钥登记到学校账号")
                                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                                .setNegativeButtonText("取消").build(), biometric.operation.cryptoObject)
                        } catch (_: Exception) { model.authenticationCancelled(biometric.id) }
                    }
                }
            }
        }
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
