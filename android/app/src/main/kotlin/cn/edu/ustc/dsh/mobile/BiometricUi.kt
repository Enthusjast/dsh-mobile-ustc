package cn.edu.ustc.dsh.mobile

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

/** Activity-owned prompt adapter; account and review authority stay in the controller. */
internal class BiometricUi(private val activity: FragmentActivity, private val onOpened: (Long) -> Unit,
    private val onSucceeded: (Long, BiometricPrompt.AuthenticationResult) -> Unit, private val onCancelled: (Long) -> Unit) {
    private var boundId: Long? = null
    private var prompt: BiometricPrompt? = null
    private fun attach(id: Long) = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) { onSucceeded(id, result) }
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) { onCancelled(id) }
    })
    fun update(authenticationId: Long?, launch: BiometricLaunch?) {
        if (boundId != authenticationId) { cancel(); boundId = authenticationId; prompt = authenticationId?.let(::attach) }
        if (launch == null || launch.id != authenticationId) return
        val active = prompt ?: return
        onOpened(launch.id)
        try {
            active.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle(launch.title).setSubtitle(launch.subtitle)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG).setNegativeButtonText("取消").build(), launch.operation.cryptoObject)
        } catch (_: Exception) { onCancelled(launch.id) }
    }
    fun cancel() { val previous = prompt; prompt = null; boundId = null; previous?.cancelAuthentication() }
}
