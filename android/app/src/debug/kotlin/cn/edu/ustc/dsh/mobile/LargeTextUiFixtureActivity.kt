package cn.edu.ustc.dsh.mobile

import android.content.Context
import android.content.res.Configuration
import androidx.activity.ComponentActivity

/** Debug-only synthetic UI host; child windows inherit the actual Android font configuration. */
class LargeTextUiFixtureActivity : ComponentActivity() {
    override fun attachBaseContext(newBase: Context) {
        val configuration = Configuration(newBase.resources.configuration).apply { fontScale = 2f }
        super.attachBaseContext(newBase.createConfigurationContext(configuration))
    }
}
