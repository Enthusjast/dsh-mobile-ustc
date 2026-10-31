package cn.edu.ustc.dsh.mobile

import cn.edu.ustc.dsh.ui.DshReadingStyle
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

internal const val MIN_READING_SCALE = 0.8f
internal const val MAX_READING_SCALE = 1.6f

internal enum class AppearanceTheme { SYSTEM, LIGHT, DARK }

internal data class AppearancePreferences(
    val theme: AppearanceTheme = AppearanceTheme.SYSTEM,
    val bodyScale: Float = 1f,
    val codeScale: Float = 1f,
    val wrapCode: Boolean = false,
) {
    fun bounded() = copy(bodyScale = boundedReadingScale(bodyScale), codeScale = boundedReadingScale(codeScale))
    fun readingStyle() = DshReadingStyle(bodyScale, codeScale, wrapCode)
}

internal fun boundedReadingScale(value: Float): Float =
    if (value.isFinite()) value.coerceIn(MIN_READING_SCALE, MAX_READING_SCALE) else 1f

internal enum class AppearancePersistence { LOADING, READY, SAVING, SAVED, READ_ERROR, WRITE_ERROR }

internal data class AppearanceState(
    val preferences: AppearancePreferences = AppearancePreferences(),
    val persistence: AppearancePersistence = AppearancePersistence.LOADING,
) {
    val editable: Boolean get() = persistence != AppearancePersistence.LOADING &&
        persistence != AppearancePersistence.SAVING && persistence != AppearancePersistence.READ_ERROR
}

/** Only four presentation scalars may cross this boundary. The key is an owner fingerprint, not a grant. */
internal interface AppearanceScalarStorage {
    fun read(ownerKey: String): AppearancePreferences
    fun write(ownerKey: String, preferences: AppearancePreferences): Boolean
}

/** One foreground owner binding; it is discarded when the accepted owner or phase changes. */
internal class AppearanceSession(val ownerKey: String, private val storage: AppearanceScalarStorage) {
    private val lock = Mutex()
    private val mutable = MutableStateFlow(AppearanceState())
    val state: StateFlow<AppearanceState> = mutable.asStateFlow()

    suspend fun load() = lock.withLock {
        mutable.value = AppearanceState(persistence = AppearancePersistence.LOADING)
        try {
            val preferences = withContext(Dispatchers.IO) { storage.read(ownerKey).bounded() }
            mutable.value = AppearanceState(preferences, AppearancePersistence.READY)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            mutable.value = AppearanceState(persistence = AppearancePersistence.READ_ERROR)
        }
    }

    suspend fun save(preferences: AppearancePreferences) = lock.withLock {
        if (!mutable.value.editable) return@withLock
        val bounded = preferences.bounded()
        // A failed SharedPreferences commit may already have changed its in-memory values.
        // Keep the visible selection, but never claim that it is durable until commit succeeds.
        mutable.value = AppearanceState(bounded, AppearancePersistence.SAVING)
        try {
            val persisted = withContext(Dispatchers.IO) { storage.write(ownerKey, bounded) }
            mutable.value = AppearanceState(bounded, if (persisted) AppearancePersistence.SAVED else AppearancePersistence.WRITE_ERROR)
        } catch (cancelled: CancellationException) {
            mutable.value = AppearanceState(bounded, AppearancePersistence.WRITE_ERROR)
            throw cancelled
        } catch (_: Exception) {
            mutable.value = AppearanceState(bounded, AppearancePersistence.WRITE_ERROR)
        }
    }
}

internal data class AppearanceScope(val phase: HomePhase, val ownerKey: String?)

internal fun HomeState.appearanceScope() = AppearanceScope(
    phase,
    presentationOwner?.fingerprint?.takeIf { phase == HomePhase.READY },
)
