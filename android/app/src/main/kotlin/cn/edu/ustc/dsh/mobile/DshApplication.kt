package cn.edu.ustc.dsh.mobile

import android.app.Application
import cn.edu.ustc.dsh.network.LoginHttp
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.HiltAndroidApp
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@HiltAndroidApp
class DshApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Process death discards all staging keys. Remove the unusable ciphertext
        // before a new foreground transfer can start.
        java.io.File(cacheDir, "file-exports").deleteRecursively()
    }
}

@Module
@InstallIn(SingletonComponent::class)
object AppModule {
    @Provides @Singleton fun loginHttp(): LoginHttp = LoginHttp.create()
}
