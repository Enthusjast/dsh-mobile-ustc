package cn.edu.ustc.dsh.mobile

import cn.edu.ustc.dsh.auth.AppUpdateDeployment
import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test

class AppInstallationRecordTest {
    private val id = "11111111-1111-4111-8111-111111111111"
    private val device = "22222222-2222-4222-8222-222222222222"
    private val hash = "a".repeat(64)
    private val packageName = "cn.edu.ustc.dsh.mobile"
    private val config = AppUpdateDeployment.parse(JsonDocument.of(jsonObject("v" to 1L.json(), "deployment_sha256" to hash.json(), "package_name" to packageName.json(), "download_origins" to JsonArray(listOf("https://updates.example.invalid".json())))).canonicalBytes(), hash, packageName)
    private val owner = LocalDataOwner(id, id, hash, id, device)
    private val expected = AndroidApkVerifier.Installed(packageName, 1, "b".repeat(64))
    private fun release() = AppRelease.parse(jsonObject("release_id" to id.json(), "version_code" to 2L.json(), "version_name" to "fixture".json(), "package_name" to packageName.json(),
        "sha256" to hash.json(), "size_bytes" to 123L.json(), "signing_cert_sha256" to expected.signingCertificate.json(), "download_url" to "https://updates.example.invalid/app.apk".json(),
        "minimum_protocol_version" to 1L.json(), "maximum_protocol_version" to 1L.json(), "minimum_android_api" to 26L.json(), "rollout_basis_points" to 10000L.json(), "release_notes" to "fixture".json()))
    private fun record() = AppInstallationRecord.create(id, owner, config, expected, release(), 13, "A".repeat(43), 1000)
    @Test fun originalActorSessionNonceAndArtifactAreImmutableAcrossPhaseChanges() {
        val original = record()
        val prepared = original.transition(AppInstallPhase.PREPARED, 2000)
        val committing = prepared.transition(AppInstallPhase.COMMITTING, 3000)
        val waiting = committing.transition(AppInstallPhase.WAITING_USER, 4000)
        assertTrue(original.sameAttempt(waiting)); assertEquals(13, waiting.sessionId); assertEquals(4000L, waiting.updatedAt)
        assertNull(original.preparedSHA256); assertEquals(original.release.sha256, waiting.preparedSHA256)
        assertTrue(waiting.belongsTo(owner, config)); assertFalse(waiting.toString().contains("AAAA"))
        assertFalse(waiting.belongsTo(LocalDataOwner(id, id, hash, id, id), config))
        val copy = AppInstallationRecord.parse(JsonDocument.parse(waiting.document.canonicalBytes()).root)
        assertTrue(waiting.sameAttempt(copy))
        for ((key, value) in listOf("session_id" to 14L.json(), "nonce" to "B".repeat(42).plus("A").json(), "installation_id" to device.json())) {
            assertFalse(waiting.sameAttempt(AppInstallationRecord.parse(waiting.document.root.with(key to value))))
        }
    }
    @Test fun incompleteCopiesCannotBecomeCommitAttemptsAndTerminalFactsCannotRegress() {
        val original = record()
        assertThrows(ProtocolException::class.java) { original.transition(AppInstallPhase.COMMITTING, 2000) }
        assertThrows(ProtocolException::class.java) { original.transition(AppInstallPhase.WAITING_USER, 2000) }
        val installed = original.transition(AppInstallPhase.INSTALLED, 3000)
        assertTrue(installed.phase.terminal)
        assertThrows(ProtocolException::class.java) { installed.transition(AppInstallPhase.WAITING_USER, 4000) }
        val reported = original.transition(AppInstallPhase.PREPARED, 2000).transition(AppInstallPhase.COMMITTING, 3000).transition(AppInstallPhase.RESULT_REPORTED, 4000)
        assertFalse(reported.phase.terminal)
        assertThrows(ProtocolException::class.java) { reported.transition(AppInstallPhase.WAITING_USER, 5000) }
        assertEquals(4000L, reported.transition(AppInstallPhase.RESULT_REPORTED, 1000).updatedAt)
    }
    @Test fun storedIdentityCannotBeReplacedOrExtendedWithUntrustedFields() {
        val root = record().document.root
        for (bad in listOf(root.with("nonce" to "short".json()), root.with("session_id" to 0L.json()), root.with("phase" to "INSTALLED_BY_CALLBACK".json()), root.with("path" to "/private".json()),
            root.with("expected_installed" to root.obj("expected_installed").with("signing_cert_sha256" to "c".repeat(64).json())),
            root.with("release" to root.obj("release").with("version_code" to 1L.json())), root.with("phase" to AppInstallPhase.COMMITTING.name.json()),
            root.with("prepared_sha256" to hash.json()))) {
            assertThrows(ProtocolException::class.java) { AppInstallationRecord.parse(bad) }
        }
    }
}
