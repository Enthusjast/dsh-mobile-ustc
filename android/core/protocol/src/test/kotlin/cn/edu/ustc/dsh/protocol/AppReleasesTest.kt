package cn.edu.ustc.dsh.protocol

import org.junit.Assert.*
import org.junit.Test
import java.io.File

class AppReleasesTest {
    private val packageName = "cn.edu.ustc.dsh.mobile"
    private val origin = "https://updates.example.invalid"
    private fun golden() = JsonDocument.parse(File(System.getProperty("contracts.root"), "golden/app-release-selection.json").readBytes()).root
    private fun selection(root: JsonObject = golden(), version: Long = 1, api: Long = 26) = AppReleaseSelection.parse(root, packageName, version, api, setOf(origin))
    @Test fun sharedMetadataBindsTheCandidateWithoutEstablishingSigningTrust() {
        val result = selection()
        assertTrue(result.currentSupported); assertEquals(1L, result.clientWindow.minimum); assertEquals(2L, result.clientWindow.maximum)
        val release = result.release!!
        assertEquals(2L, release.versionCode); assertEquals(packageName, release.packageName); assertEquals("b".repeat(64), release.signingCertificate)
        assertEquals(12_345_678L, release.sizeBytes); assertEquals(origin, release.downloadOrigin)
        assertEquals(JsonDocument.of(golden().obj("release")).sha256(), release.document.sha256())
        assertFalse(release.toString().contains(origin)); assertFalse(result.toString().contains("example"))
    }
    @Test fun selectionRejectsWrongRequestContextAndContradictorySupport() {
        val root = golden()
        for (bad in listOf(root.with("v" to 2L.json()), root.with("protocol_version" to 2L.json()), root.with("current_version_code" to 2L.json()),
            root.with("package_name" to "cn.edu.other".json()), root.with("current_supported" to JsonBoolean(false)), root.with("force_install" to JsonBoolean(true)))) {
            assertThrows(ProtocolException::class.java) { selection(bad) }
        }
        val old = root.with("current_version_code" to 3L.json(), "current_supported" to JsonBoolean(false), "release" to JsonNull)
        assertFalse(selection(old, version = 3).currentSupported)
        assertNull(selection(root.with("release" to JsonNull)).release)
    }
    @Test fun selectedReleaseMustBeNewerCompatibleAndWithinThePublishedWindow() {
        val root = golden(); val release = root.obj("release")
        for (bad in listOf(release.with("version_code" to 1L.json()), release.with("version_code" to 3L.json()), release.with("package_name" to "cn.edu.other".json()),
            release.with("minimum_protocol_version" to 2L.json(), "maximum_protocol_version" to 2L.json()), release.with("minimum_android_api" to 35L.json()),
            release.with("rollout_basis_points" to 0L.json()))) {
            assertThrows(ProtocolException::class.java) { selection(root.with("release" to bad)) }
        }
        assertEquals(35L, selection(root.with("release" to release.with("minimum_android_api" to 35L.json())), api = 35).release!!.minimumAndroidApi)
    }
    @Test fun downloadOriginCannotBeChosenByReleaseMetadata() {
        val root = golden(); val release = root.obj("release")
        for (url in listOf("http://updates.example.invalid/app.apk", "https://other.example/app.apk", "https://user:password@updates.example.invalid/app.apk",
            "$origin/app.apk?token=secret", "$origin/app.apk#", "$origin/a/../app.apk", "$origin/a/%2e%2e/app.apk", "$origin/a\\app.apk", "$origin//app.apk", "$origin")) {
            assertThrows(ProtocolException::class.java) { selection(root.with("release" to release.with("download_url" to url.json()))) }
        }
        for (origins in listOf(emptySet(), setOf("$origin/"), setOf("http://updates.example.invalid"))) {
            assertThrows(ProtocolException::class.java) { AppReleaseSelection.parse(root, packageName, 1, 26, origins) }
        }
    }
    @Test fun metadataRejectsUnboundedIncompleteAndAmbiguousFields() {
        val release = golden().obj("release")
        for (bad in listOf(release.with("sha256" to "A".repeat(64).json()), release.with("size_bytes" to (MAX_APK_BYTES + 1).json()),
            release.with("signing_cert_sha256" to "".json()), release.with("rollout_basis_points" to JsonNull), release.with("version_name" to "\u0085".json()),
            release.with("release_notes" to "\u0000private".json()), release.with("release_notes" to " ".json()), release.with("apk_path" to "/private".json()),
            JsonObject(release.fields.filterKeys { it != "release_notes" }))) {
            assertThrows(ProtocolException::class.java) { AppRelease.parse(bad) }
        }
        assertEquals("line one\nline two\titem", AppRelease.parse(release.with("release_notes" to "line one\nline two\titem".json())).releaseNotes)
        val raw = JsonDocument.of(release).canonicalText().replace("\"version_code\":2", "\"version_code\":2,\"version_code\":3")
        assertThrows(ProtocolException::class.java) { JsonDocument.parse(raw) }
    }
}
