package cn.edu.ustc.dsh.mobile

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import cn.edu.ustc.dsh.network.LoginHttp
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.*
import javax.inject.Inject

/** Bounded deletion-only work. No account restore, credential refresh or realtime connection. */
@AndroidEntryPoint
class PushCleanupJob : JobService() {
    @Inject lateinit var center: NotificationCenter
    @Inject lateinit var http: LoginHttp
    private var task: Job? = null
    override fun onStartJob(params: JobParameters): Boolean {
        task = CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            val complete = runCatching { center.drain(http) }.getOrDefault(false)
            if (isActive) withContext(Dispatchers.Main) { jobFinished(params, !complete) }
        }
        return true
    }
    override fun onStopJob(params: JobParameters): Boolean { task?.cancel(); task = null; return true }
    companion object {
        fun schedule(context: Context) {
            context.getSystemService(JobScheduler::class.java).schedule(JobInfo.Builder(0x44534850, ComponentName(context, PushCleanupJob::class.java))
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY).setMinimumLatency(15_000).setBackoffCriteria(30_000, JobInfo.BACKOFF_POLICY_EXPONENTIAL).setPersisted(true).build())
        }
    }
}
