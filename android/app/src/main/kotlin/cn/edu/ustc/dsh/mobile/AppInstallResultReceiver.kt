package cn.edu.ustc.dsh.mobile

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class AppInstallResultReceiver : BroadcastReceiver() {
    @Inject internal lateinit var installations: AppInstallations
    override fun onReceive(context: Context, intent: Intent) {
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try { installations.receive(intent) } catch (_: Exception) { /* No hint becomes an installation fact. */ }
            finally { pending.finish() }
        }
    }
}
