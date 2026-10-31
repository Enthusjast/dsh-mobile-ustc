package cn.edu.ustc.dsh.mobile

import cn.edu.ustc.dsh.command.CommandOwner
import kotlinx.coroutines.flow.asFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AppearancePreferencesTest {
    private val owner = CommandOwner(
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "a".repeat(64),
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
    )

    private class Storage : AppearanceScalarStorage {
        val values = mutableMapOf<String, AppearancePreferences>()
        var readError = false
        var writeError = false
        var acknowledgeWrite = true
        var writes = 0
        override fun read(ownerKey: String): AppearancePreferences {
            check(!readError)
            return values[ownerKey] ?: AppearancePreferences()
        }
        override fun write(ownerKey: String, preferences: AppearancePreferences): Boolean {
            writes++
            check(!writeError)
            if (acknowledgeWrite) values[ownerKey] = preferences
            return acknowledgeWrite
        }
    }

    @Test fun allOwnerDimensionsIsolateScalarPreferencesAndReopeningRestoresThem() = runBlocking {
        val storage = Storage()
        val selected = AppearancePreferences(AppearanceTheme.DARK, 1.3f, 0.9f, true)
        val session = AppearanceSession(owner.fingerprint, storage)
        session.load()
        assertEquals(AppearancePreferences(), session.state.value.preferences)
        session.save(selected)
        assertEquals(AppearancePersistence.SAVED, session.state.value.persistence)
        val reopened = AppearanceSession(owner.fingerprint, storage)
        reopened.load()
        assertEquals(selected, reopened.state.value.preferences)
        val other = "55555555-5555-4555-8555-555555555555"
        val owners = listOf(
            CommandOwner(other, owner.organizationId, owner.deploymentHash, owner.userId, owner.deviceId),
            CommandOwner(owner.accountId, other, owner.deploymentHash, owner.userId, owner.deviceId),
            CommandOwner(owner.accountId, owner.organizationId, "b".repeat(64), owner.userId, owner.deviceId),
            CommandOwner(owner.accountId, owner.organizationId, owner.deploymentHash, other, owner.deviceId),
            CommandOwner(owner.accountId, owner.organizationId, owner.deploymentHash, owner.userId, other),
        )
        owners.forEach { isolatedOwner ->
            assertNotEquals(owner.fingerprint, isolatedOwner.fingerprint)
            val isolated = AppearanceSession(isolatedOwner.fingerprint, storage)
            isolated.load()
            assertEquals(AppearancePreferences(), isolated.state.value.preferences)
        }
    }

    @Test fun boundsAndNonFiniteValuesCannotChangeTheIndependentScaleOrWrap() = runBlocking {
        val storage = Storage()
        storage.values[owner.fingerprint] = AppearancePreferences(bodyScale = Float.NaN, codeScale = 9f)
        val session = AppearanceSession(owner.fingerprint, storage)
        session.load()
        assertEquals(1f, session.state.value.preferences.bodyScale)
        assertEquals(MAX_READING_SCALE, session.state.value.preferences.codeScale)
        session.save(AppearancePreferences(bodyScale = -1f, codeScale = 1.2f, wrapCode = true))
        assertEquals(MIN_READING_SCALE, session.state.value.preferences.bodyScale)
        assertEquals(1.2f, session.state.value.preferences.codeScale)
        assertTrue(session.state.value.preferences.wrapCode)
        session.save(session.state.value.preferences.copy(bodyScale = 1.5f))
        assertEquals(1.2f, session.state.value.preferences.readingStyle().codeScale)
        assertEquals(1f, boundedReadingScale(Float.POSITIVE_INFINITY))
        assertEquals(1f, boundedReadingScale(Float.NEGATIVE_INFINITY))
    }

    @Test fun failedReadDisablesWritesUntilAnExplicitSuccessfulRead() = runBlocking {
        val storage = Storage().apply { readError = true }
        val session = AppearanceSession(owner.fingerprint, storage)
        session.load()
        assertEquals(AppearancePersistence.READ_ERROR, session.state.value.persistence)
        assertFalse(session.state.value.editable)
        session.save(AppearancePreferences(theme = AppearanceTheme.DARK))
        assertEquals(0, storage.writes)
        storage.readError = false
        session.load()
        assertEquals(AppearancePersistence.READY, session.state.value.persistence)
        assertTrue(session.state.value.editable)
    }

    @Test fun failedCommitAndWriteExceptionsNeverClaimDurabilityAndCanBeRetried() = runBlocking {
        val storage = Storage().apply { acknowledgeWrite = false }
        val session = AppearanceSession(owner.fingerprint, storage)
        session.load()
        val selected = AppearancePreferences(AppearanceTheme.LIGHT, 1.2f, 1.4f, true)
        session.save(selected)
        assertEquals(selected, session.state.value.preferences)
        assertEquals(AppearancePersistence.WRITE_ERROR, session.state.value.persistence)
        assertFalse(storage.values.containsKey(owner.fingerprint))
        storage.writeError = true
        session.save(selected)
        assertEquals(AppearancePersistence.WRITE_ERROR, session.state.value.persistence)
        storage.writeError = false
        storage.acknowledgeWrite = true
        session.save(selected)
        assertEquals(AppearancePersistence.SAVED, session.state.value.persistence)
        assertEquals(selected, storage.values[owner.fingerprint])
    }

    @Test fun onlyDistinctAcceptedOwnerAndPhaseChangesCreateAppearanceScopes() = runBlocking {
        val initial = HomeState(phase = HomePhase.READY, presentationOwner = owner)
        val sameOwner = CommandOwner(owner.accountId, owner.organizationId, owner.deploymentHash, owner.userId, owner.deviceId)
        val states = listOf(
            initial,
            initial.copy(error = "unrelated transcript or operation update"),
            initial.copy(presentationOwner = sameOwner),
            initial.copy(phase = HomePhase.SIGNED_OUT),
            HomeState(phase = HomePhase.SIGNED_OUT),
            initial,
        ).asFlow().map { it.appearanceScope() }.distinctUntilChanged().toList()
        assertEquals(listOf(
            AppearanceScope(HomePhase.READY, owner.fingerprint),
            AppearanceScope(HomePhase.SIGNED_OUT, null),
            AppearanceScope(HomePhase.READY, owner.fingerprint),
        ), states)
    }

    @Test fun interruptedSaveNeverLeavesTheOwnerBindingPermanentlyBusy() = runBlocking {
        val storage = object : AppearanceScalarStorage {
            override fun read(ownerKey: String) = AppearancePreferences()
            override fun write(ownerKey: String, preferences: AppearancePreferences): Boolean {
                throw kotlinx.coroutines.CancellationException("screen closed while saving")
            }
        }
        val session = AppearanceSession(owner.fingerprint, storage)
        session.load()
        try {
            session.save(AppearancePreferences(theme = AppearanceTheme.DARK))
            throw AssertionError("Cancellation must propagate")
        } catch (_: kotlinx.coroutines.CancellationException) {
            assertEquals(AppearancePersistence.WRITE_ERROR, session.state.value.persistence)
            assertTrue(session.state.value.editable)
        }
    }
}
