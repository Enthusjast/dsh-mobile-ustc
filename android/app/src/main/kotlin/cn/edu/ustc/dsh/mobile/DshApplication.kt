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
class DshApplication : Application()

@Module
@InstallIn(SingletonComponent::class)
object AppModule {
    @Provides @Singleton fun loginHttp(): LoginHttp = LoginHttp.create()
}
