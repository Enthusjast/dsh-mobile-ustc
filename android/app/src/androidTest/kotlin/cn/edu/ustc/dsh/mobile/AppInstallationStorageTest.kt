package cn.edu.ustc.dsh.mobile

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.auth.AppUpdateDeployment
import cn.edu.ustc.dsh.protocol.*
import org.junit.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith
import java.security.KeyStore
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class AppInstallationStorageTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var storage: AppInstallationStorage
    private lateinit var slot: String
    private val id = "11111111-1111-4111-8111-111111111111"
    private val hash = "a".repeat(64)
    private val packageName = "cn.edu.ustc.dsh.mobile"
    private val owner = LocalDataOwner(id, id, hash, id, id)
    private val expected = AndroidApkVerifier.Installed(packageName, 1, "b".repeat(64))
    private val configuration = AppUpdateDeployment.parse(JsonDocument.of(jsonObject("v" to 1L.json(), "deployment_sha256" to hash.json(), "package_name" to packageName.json(),
        "download_origins" to JsonArray(listOf("https://updates.example.invalid".json())))).canonicalBytes(), hash, packageName)
    @Before fun setup() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("networkFixture") == "true")
        slot = "apk-ledger-${UUID.randomUUID()}"
        storage = AppInstallationStorage(context, slot)
        assertNull(storage.read())
    }
    @After fun cleanup() { if (::storage.isInitialized) storage.resetAfterSessionCleanup() }
    private fun record(id: String = this.id): AppInstallationRecord {
        val release = AppRelease.parse(jsonObject("release_id" to this.id.json(), "version_code" to 2L.json(), "version_name" to "fixture".json(), "package_name" to packageName.json(),
            "sha256" to hash.json(), "size_bytes" to 123L.json(), "signing_cert_sha256" to expected.signingCertificate.json(), "download_url" to "https://updates.example.invalid/app.apk".json(),
            "minimum_protocol_version" to 1L.json(), "maximum_protocol_version" to 1L.json(), "minimum_android_api" to 26L.json(), "rollout_basis_points" to 10000L.json(), "release_notes" to "PRIVATE_INSTALL_NOTE".json()))
        return AppInstallationRecord.create(id, owner, configuration, expected, release, 13, "A".repeat(43), 1000)
    }
    private fun fails(expected: InstallStorageFailure, action: () -> Unit) {
        try { action(); fail("invalid installation storage operation succeeded") }
        catch (error: InstallStorageException) { assertEquals(expected, error.failure) }
    }
    @Test fun encryptedRecordSurvivesReopeningAndCannotBeErasedWhileAnAttemptIsActive() {
        val first = storage.save(record(), 0)
        assertEquals(1L, first.revision)
        val raw = storage.file.baseFile.readText()
        for (sensitive in listOf("PRIVATE_INSTALL_NOTE", id, "A".repeat(43), "updates.example.invalid")) assertFalse(raw.contains(sensitive))
        val reopened = AppInstallationStorage(context, slot).read()!!
        assertEquals(first.record.document.sha256(), reopened.record.document.sha256())
        val prepared = storage.save(reopened.record.transition(AppInstallPhase.PREPARED, 2000), reopened.revision)
        val committing = storage.save(prepared.record.transition(AppInstallPhase.COMMITTING, 3000), prepared.revision)
        fails(InstallStorageFailure.CONFLICT) { storage.erase(committing.revision) }
        val retired = storage.save(committing.record.transition(AppInstallPhase.RETIRED, 4000), committing.revision)
        storage.erase(retired.revision)
        assertNull(storage.read()); assertFalse(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(storage.alias))
    }
    @Test fun staleRevisionsAndChangedAttemptIdentityCannotRewriteTheOriginalContext() {
        val first = storage.save(record(), 0)
        val prepared = storage.save(first.record.transition(AppInstallPhase.PREPARED, 2000), first.revision)
        fails(InstallStorageFailure.CONFLICT) { storage.save(prepared.record.transition(AppInstallPhase.COMMITTING, 3000), first.revision) }
        fails(InstallStorageFailure.CONFLICT) { storage.save(record(UUID.randomUUID().toString()), prepared.revision) }
        val changed = AppInstallationRecord.parse(prepared.record.document.root.with("nonce" to ("B".repeat(42) + "A").json()))
        fails(InstallStorageFailure.CONFLICT) { storage.save(changed, prepared.revision) }
        assertEquals(prepared.record.document.sha256(), storage.read()!!.record.document.sha256())
    }
    @Test fun headerTamperingAndCiphertextCopiedAcrossSlotsFailClosed() {
        storage.save(record(), 0)
        val original = storage.file.baseFile.readBytes()
        val root = JsonDocument.parse(original).root
        storage.file.baseFile.writeBytes(JsonDocument.of(root.with("revision" to 2L.json())).canonicalBytes())
        fails(InstallStorageFailure.CORRUPT) { storage.read() }
        storage.file.baseFile.writeBytes(original)
        assertNotNull(storage.read())
        val other = AppInstallationStorage(context, "apk-ledger-${UUID.randomUUID()}")
        try {
            assertTrue(other.file.baseFile.parentFile!!.mkdirs()); other.file.baseFile.writeBytes(original)
            fails(InstallStorageFailure.KEY_MISSING) { other.read() }
            assertFalse(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(other.alias))
        } finally { other.resetAfterSessionCleanup() }
    }
    @Test fun aLostPlatformKeyDoesNotRecreateAnEmptyTrustedInstallationHistory() {
        val first = storage.save(record(), 0)
        val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keys.deleteEntry(storage.alias)
        fails(InstallStorageFailure.KEY_MISSING) { storage.read() }
        fails(InstallStorageFailure.KEY_MISSING) { storage.save(first.record, first.revision) }
        assertFalse(keys.containsAlias(storage.alias))
        storage.resetAfterSessionCleanup(); assertNull(storage.read())
    }
}
