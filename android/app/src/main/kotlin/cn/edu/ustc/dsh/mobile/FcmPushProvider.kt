package cn.edu.ustc.dsh.mobile

import android.content.Context
import android.content.Intent
import cn.edu.ustc.dsh.auth.LoginConfiguration
import cn.edu.ustc.dsh.auth.PushDeployment
import com.google.android.gms.common.GoogleApiAvailabilityLight
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.tasks.Task
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.installations.FirebaseInstallations
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.suspendCancellableCoroutine
import javax.inject.Inject
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

internal interface DevicePushProvider {
    val configuration: PushDeployment?
    fun availability(): String
    suspend fun register(): String
    suspend fun unregister()
}
internal fun publicPushConfiguration(context: Context): PushDeployment? = try {
    val main = LoginConfiguration.parse(context.assets.open("deployment.json").use { it.readBytes() })
    PushDeployment.parse(context.assets.open("push-deployment.json").use { it.readBytes() }, main.fingerprint, context.packageName)
} catch (_: Exception) { null }

/** Explicit initialization only. No Google SDK call runs while configuration or consent is absent. */
internal class FcmPushProvider(private val context: Context) : DevicePushProvider {
    override val configuration = publicPushConfiguration(context)
    override fun availability(): String = when {
        configuration == null -> "push.not_configured"
        GoogleApiAvailabilityLight.getInstance().isGooglePlayServicesAvailable(context) != ConnectionResult.SUCCESS -> "push.services_unavailable"
        else -> "ready"
    }
    private fun sdk(): FirebaseMessaging {
        val config = configuration ?: throw IllegalStateException("push.not_configured")
        synchronized(lock) {
            val previous = FirebaseApp.getApps(context).firstOrNull { it.name == FirebaseApp.DEFAULT_APP_NAME }
            if (previous != null && (previous.options.projectId != config.projectId || previous.options.applicationId != config.applicationId)) previous.delete()
            if (FirebaseApp.getApps(context).none { it.name == FirebaseApp.DEFAULT_APP_NAME }) {
                FirebaseApp.initializeApp(context, FirebaseOptions.Builder().setProjectId(config.projectId).setApplicationId(config.applicationId).setGcmSenderId(config.senderId).setApiKey(config.apiKey).build())
            }
            FirebaseApp.getInstance().setDataCollectionDefaultEnabled(false)
            return FirebaseMessaging.getInstance().apply { isAutoInitEnabled = false; setDeliveryMetricsExportToBigQuery(false) }
        }
    }
    override suspend fun register(): String {
        if (availability() != "ready") throw IllegalStateException(availability())
        val sdk = sdk()
        sdk.setNotificationDelegationEnabled(false).awaitPush()
        sdk.register().awaitPush()
        return FirebaseInstallations.getInstance().id.awaitPush()
    }
    override suspend fun unregister() { configuration ?: return; sdk().apply { isAutoInitEnabled = false }.unregister().awaitPush() }
    companion object { private val lock = Any() }
}
private suspend fun <T> Task<T>.awaitPush(): T = suspendCancellableCoroutine { continuation ->
    addOnSuccessListener { if (continuation.isActive) continuation.resume(it) }
    addOnFailureListener { if (continuation.isActive) continuation.resumeWithException(IllegalStateException("push.provider_unavailable")) }
    addOnCanceledListener { continuation.cancel() }
}

@AndroidEntryPoint
class DshMessagingService : FirebaseMessagingService() {
    @Inject lateinit var center: NotificationCenter
    override fun handleIntent(intent: Intent) {
        // Reject SDK auto-display packets before Firebase's background display
        // path can bypass our account fence. The configured sender sends data only.
        val extras = intent.extras
        if (extras != null && extras.keySet().any { it.startsWith("gcm.n.") || it.startsWith("gcm.notification.") }) return
        super.handleIntent(intent)
    }
    override fun onMessageReceived(message: RemoteMessage) {
        val config = publicPushConfiguration(this) ?: return
        if (message.notification != null) return
        runCatching { center.receive(config, message.from, message.data) }
    }
    override fun onRegistered(fid: String) { publicPushConfiguration(this)?.let { config -> runCatching { center.registeredAddress(config, fid) } } }
    override fun onUnregistered(fid: String) { publicPushConfiguration(this)?.let { config -> runCatching { if (center.snapshot().route?.let { it.publicConfig == config.fingerprint && it.address == fid } == true) center.retire() } } }
    override fun onDeletedMessages() { publicPushConfiguration(this)?.let { config -> runCatching { center.lostMessages(config) } } }
}
