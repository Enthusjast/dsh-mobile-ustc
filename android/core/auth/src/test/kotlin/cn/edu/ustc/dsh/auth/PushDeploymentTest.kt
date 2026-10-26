package cn.edu.ustc.dsh.auth

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test

class PushDeploymentTest {
    private val hash = "a".repeat(64)
    private fun root() = jsonObject("v" to 1L.json(), "deployment_sha256" to hash.json(), "package_name" to "cn.edu.ustc.dsh.mobile".json(),
        "fcm" to jsonObject("project_id" to "fixture-project".json(), "application_id" to "1:123456789:android:abcdef012345".json(), "sender_id" to "123456789".json(), "api_key" to "fixture_public_key_1234567890".json()))
    private fun parse(value: JsonObject = root()) = PushDeployment.parse(JsonDocument.of(value).canonicalBytes(), hash, "cn.edu.ustc.dsh.mobile")
    @Test fun publicOptionsCannotMoveBetweenResourcesOrContainServiceAccountSecrets() {
        val config = parse(); assertEquals("fixture-project", config.projectId); assertFalse(config.toString().contains(config.apiKey))
        for (bad in listOf(root().with("deployment_sha256" to "b".repeat(64).json()), root().with("package_name" to "other.package".json()),
            root().with("fcm" to root().obj("fcm").with("private_key" to "PRIVATE".json())), root().with("fcm" to root().obj("fcm").with("sender_id" to "987654321".json())))) {
            assertThrows(ProtocolException::class.java) { parse(bad) }
        }
    }
}
