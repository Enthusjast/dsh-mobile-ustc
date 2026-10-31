package cn.edu.ustc.dsh.mobile

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.command.CommandOwner
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class AppearanceStorageTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val owner = CommandOwner(UUID.randomUUID().toString(), UUID.randomUUID().toString(), "a".repeat(64), UUID.randomUUID().toString(), UUID.randomUUID().toString())
    private val other = CommandOwner(owner.accountId, owner.organizationId, owner.deploymentHash, owner.userId, UUID.randomUUID().toString())

    @After fun removeScalars() {
        listOf(owner, other).forEach { context.deleteSharedPreferences("appearance-v1-${it.fingerprint}") }
    }

    @Test fun privateStoragePersistsOnlyFourScalarsAndNeverSharesAnotherDeviceNamespace() = runBlocking {
        val selected = AppearancePreferences(AppearanceTheme.DARK, 1.4f, 0.8f, true)
        val session = AppearanceSession(owner.fingerprint, AndroidAppearanceStorage(context))
        session.load()
        session.save(selected)
        assertEquals(AppearancePersistence.SAVED, session.state.value.persistence)
        val restored = AppearanceSession(owner.fingerprint, AndroidAppearanceStorage(context))
        restored.load()
        assertEquals(selected, restored.state.value.preferences)
        val isolated = AppearanceSession(other.fingerprint, AndroidAppearanceStorage(context))
        isolated.load()
        assertEquals(AppearancePreferences(), isolated.state.value.preferences)
        val scalars = context.getSharedPreferences("appearance-v1-${owner.fingerprint}", Context.MODE_PRIVATE).all
        assertEquals(setOf("theme", "body_scale", "code_scale", "wrap_code"), scalars.keys)
        assertEquals(AppearanceTheme.DARK.name, scalars["theme"])
        assertFalse(scalars.values.any { it == owner.accountId || it == owner.deviceId })
    }

    @Test fun corruptedScalarTypeIsReportedAsReadFailureRatherThanSavedDefaults() = runBlocking {
        val stored = context.getSharedPreferences("appearance-v1-${owner.fingerprint}", Context.MODE_PRIVATE)
        check(stored.edit().putString("body_scale", "not-a-float").commit())
        val session = AppearanceSession(owner.fingerprint, AndroidAppearanceStorage(context))
        session.load()
        assertEquals(AppearancePersistence.READ_ERROR, session.state.value.persistence)
        assertFalse(session.state.value.editable)
        assertEquals("not-a-float", stored.getString("body_scale", null))
    }
}
