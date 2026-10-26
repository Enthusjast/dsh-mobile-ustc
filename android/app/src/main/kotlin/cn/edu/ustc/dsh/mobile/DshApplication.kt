package cn.edu.ustc.dsh.mobile

import android.app.Application
import cn.edu.ustc.dsh.network.LoginHttp
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.HiltAndroidApp
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton
import javax.inject.Inject
import cn.edu.ustc.dsh.auth.LoginConfiguration

@HiltAndroidApp
class DshApplication : Application() {
    @Inject lateinit var notifications: NotificationCenter
    override fun onCreate() {
        super.onCreate()
        // Process death discards all staging keys. Remove the unusable ciphertext
        // before a new foreground transfer can start.
        java.io.File(cacheDir, "file-exports").deleteRecursively()
        val deployment = runCatching { LoginConfiguration.parse(assets.open("deployment.json").use { it.readBytes() }).fingerprint }.getOrNull()
        notifications.reconcileDeployment(deployment, publicPushConfiguration(this)?.fingerprint)
    }
}

@Module
@InstallIn(SingletonComponent::class)
object AppModule {
    @Provides @Singleton fun loginHttp(): LoginHttp = LoginHttp.create()
}
