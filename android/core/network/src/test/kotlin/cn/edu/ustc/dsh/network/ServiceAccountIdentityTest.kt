package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test

class ServiceAccountIdentityTest {
    private val issuer = "https://id.example.edu"
    private val subject = "opaque-school-subject"
    private val userId = "22222222-2222-4222-8222-222222222222"
    private val organizationId = "11111111-1111-4111-8111-111111111111"
    private val otherOrganizationId = "33333333-3333-4333-8333-333333333333"
    private fun membership(id: String, role: String = "member") = jsonObject("organization_id" to id.json(), "role" to role.json())
    private fun root() = jsonObject(
        "issuer" to issuer.json(), "subject" to subject.json(), "client_id" to "mobile".json(),
        "scopes" to JsonArray(listOf("remote.access".json())), "user_id" to userId.json(),
        "memberships" to JsonArray(listOf(membership(organizationId), membership(otherOrganizationId, "admin"))),
    )
    private fun parse(root: JsonObject) = ServiceAccountIdentity.parse(root, issuer, subject, "mobile", setOf("remote.access"), organizationId)

    @Test fun internalUserAndOrganizationRolesComeFromTheAuthenticatedMapping() {
        val account = parse(root())
        assertEquals(userId, account.userId)
        assertNotEquals(subject, account.userId)
        assertEquals("member", account.memberships[organizationId])
        assertEquals("admin", account.memberships[otherOrganizationId])
        @Suppress("UNCHECKED_CAST")
        assertThrows(UnsupportedOperationException::class.java) { (account.memberships as MutableMap<String, String>)[organizationId] = "admin" }
    }

    @Test fun mismatchedMissingDuplicatedOrMalformedAuthorityCannotEnableEnrollment() {
        for ((field, value) in listOf("issuer" to "https://another.example.edu", "subject" to "another-user", "client_id" to "another-client")) {
            assertEquals("auth.identity_mismatch", assertThrows(RemoteRequestException::class.java) { parse(root().with(field to value.json())) }.code)
        }
        for (memberships in listOf(emptyList(), listOf(membership(otherOrganizationId)))) {
            assertEquals("access.organization_missing", assertThrows(RemoteRequestException::class.java) { parse(root().with("memberships" to JsonArray(memberships))) }.code)
        }
        val bad = listOf(
            JsonObject(root().fields - "user_id"), root().with("user_id" to subject.json()), root().with("user_id" to JsonNull),
            root().with("memberships" to JsonArray(listOf(membership(organizationId), membership(organizationId, "admin")))),
            root().with("memberships" to JsonArray(listOf(membership(organizationId, "owner")))),
            root().with("memberships" to JsonArray(listOf(membership("invalid")))),
            root().with("memberships" to JsonArray(listOf(membership(organizationId).with("scope" to "*".json())))),
            root().with("memberships" to JsonArray(List(257) { membership(organizationId) })),
            root().with("scopes" to JsonArray(listOf("remote.access".json(), "remote.access".json()))),
            root().with("scopes" to JsonArray(listOf("remote.admin".json()))),
        )
        bad.forEach { assertThrows(RemoteRequestException::class.java) { parse(it) } }
    }
}
