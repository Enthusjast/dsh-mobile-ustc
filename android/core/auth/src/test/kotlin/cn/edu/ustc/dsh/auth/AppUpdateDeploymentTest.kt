package cn.edu.ustc.dsh.auth

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test

class AppUpdateDeploymentTest {
    private val hash = "a".repeat(64)
    private val packageName = "cn.edu.ustc.dsh.mobile"
    private val origin = "https://updates.example.invalid"
    private fun root() = jsonObject("v" to 1L.json(), "deployment_sha256" to hash.json(), "package_name" to packageName.json(), "download_origins" to JsonArray(listOf(origin.json())))
    private fun parse(root: JsonObject = root()) = AppUpdateDeployment.parse(JsonDocument.of(root).canonicalBytes(), hash, packageName)
    @Test fun publicOriginsAreImmutableAndBoundToTheIndependentSchoolDeployment() {
        val value = parse()
        assertEquals(hash, value.deploymentHash); assertEquals(packageName, value.packageName); assertEquals(setOf(origin), value.downloadOrigins)
        assertEquals(JsonDocument.of(root()).sha256(), value.fingerprint)
        assertEquals(value.fingerprint, AppUpdateDeployment.parse(value.bytes(), hash, packageName).fingerprint)
        assertFalse(value.toString().contains(origin))
        assertThrows(UnsupportedOperationException::class.java) { (value.downloadOrigins as MutableSet<String>).add("https://attacker.example") }
        for (bad in listOf(root().with("v" to 2L.json()), root().with("deployment_sha256" to "b".repeat(64).json()), root().with("package_name" to "cn.edu.other".json()))) {
            assertThrows(ProtocolException::class.java) { parse(bad) }
        }
    }
    @Test fun originsCannotIntroduceRedirectTargetsPathsOrCredentials() {
        for (invalid in listOf("http://updates.example.invalid", "$origin/", "$origin/releases", "$origin?token=PRIVATE", "$origin#fragment", "https://user:password@updates.example.invalid", "https://*.example.invalid", "https://UPDATES.example.invalid", " ")) {
            assertThrows(ProtocolException::class.java) { parse(root().with("download_origins" to JsonArray(listOf(invalid.json())))) }
        }
        for (values in listOf(emptyList(), listOf(origin.json(), origin.json()), List(9) { "https://updates$it.example.invalid".json() }, listOf(JsonNull))) {
            assertThrows(ProtocolException::class.java) { parse(root().with("download_origins" to JsonArray(values))) }
        }
    }
    @Test fun aPublicConfigurationCannotAddSigningRootsOrPrivateServiceMaterial() {
        for (field in listOf("client_secret", "private_key", "access_token", "signing_cert_sha256", "metadata_origin")) {
            assertThrows(ProtocolException::class.java) { parse(root().with(field to "PRIVATE".json())) }
        }
        val raw = JsonDocument.of(root()).canonicalText().replace("\"v\":1", "\"v\":1,\"v\":1")
        assertThrows(ProtocolException::class.java) { AppUpdateDeployment.parse(raw.toByteArray(), hash, packageName) }
        assertThrows(ProtocolException::class.java) { AppUpdateDeployment.parse(ByteArray(16 * 1024 + 1) { 32 }, hash, packageName) }
    }
}
