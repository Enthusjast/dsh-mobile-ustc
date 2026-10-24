package cn.edu.ustc.dsh.auth

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test

class HostBindingTest {
    private val id = "11111111-1111-4111-8111-111111111111"
    private val other = "22222222-2222-4222-8222-222222222222"
    private val now = System.currentTimeMillis()
    private fun data() = jsonObject("enrollment_id" to id.json(), "request_id" to other.json(), "organization_id" to id.json(), "organization_name" to "测试学校".json(),
        "host_id" to id.json(), "host_alias" to "实验室电脑".json(), "installation_id" to other.json(), "installation_key_jkt" to "A".repeat(43).json(),
        "runtime_id" to other.json(), "profile_ref" to "research".json(), "protocol_version" to 1L.json(), "state" to "pending".json(), "expires_at" to Contract.timestamp(now + 300_000).json(),
        "host_confirmed" to JsonBoolean(false), "user_confirmed" to JsonBoolean(false), "user_confirmed_by_me" to JsonBoolean(false),
        "workspaces" to JsonArray(listOf(jsonObject("reference" to "project".json(), "workspace_id" to other.json()))))
    private fun parse(root: JsonObject = data()) = HostBindingDetails.parse(root, id, id)
    @Test fun onlyPublicFactsEnterReviewAndMutableConfirmationFlagsDoNotChangeItsBinding() {
        val original = data(); val pending = parse(original)
        assertTrue(pending.canConfirm(now)); assertFalse(pending.canConfirm(now + 300_001)); assertEquals("research", pending.profile)
        val partial = original.with("user_confirmed" to JsonBoolean(true), "user_confirmed_by_me" to JsonBoolean(true), "state" to "user_confirmed".json())
        val approved = partial.with("host_confirmed" to JsonBoolean(true), "state" to "approved".json())
        assertEquals(pending.reviewHash, parse(partial).reviewHash); assertEquals(pending.reviewHash, parse(approved).reviewHash)
        assertFalse(parse(approved).canConfirm(now)); assertTrue(parse(approved).confirmedByMe)
        assertFalse(pending.toString().contains("实验室电脑"))
    }
    @Test fun organizationAndEnrollmentIdentityAndEveryReviewFactStayBound() {
        assertEquals("binding.organization_mismatch", assertThrows(HostBindingException::class.java) { HostBindingDetails.parse(data(), other, id) }.code)
        assertEquals("binding.identity_mismatch", assertThrows(HostBindingException::class.java) { HostBindingDetails.parse(data(), id, other) }.code)
        for (changed in listOf(data().with("profile_ref" to "other".json()), data().with("host_alias" to "其他电脑".json()), data().with("installation_key_jkt" to ("B".repeat(42) + "A").json()),
            data().with("expires_at" to Contract.timestamp(now + 200_000).json()), data().with("workspaces" to JsonArray(emptyList())))) assertNotEquals(parse().reviewHash, parse(changed).reviewHash)
    }
    @Test fun malformedAttributionSecretsPathsAndAmbiguousWorkspacesFailClosed() {
        val repeated = data().array("workspaces").single()
        for (bad in listOf(data().with("code" to "secret".json()), data().with("user_confirmed_by_me" to JsonBoolean(true)), data().with("state" to "approved".json()),
            data().with("installation_key_jkt" to ("A".repeat(42) + "B").json()), data().with("profile_ref" to "../other".json()),
            data().with("host_alias" to "bad\nname".json()), data().with("workspaces" to JsonArray(listOf(repeated, repeated))))) {
            val error = assertThrows(ProtocolException::class.java) { parse(bad) }
            assertFalse(error.message!!.contains("secret"))
        }
    }
    @Test fun unsupportedProtocolsAndTerminalOrOtherAccountConfirmationCannotEnableTheButton() {
        assertFalse(parse(data().with("protocol_version" to 2L.json())).canConfirm(now))
        for (state in listOf("expired", "denied", "cancelled")) assertFalse(parse(data().with("state" to state.json())).canConfirm(now))
        val otherAccount = parse(data().with("state" to "user_confirmed".json(), "user_confirmed" to JsonBoolean(true)))
        assertFalse(otherAccount.confirmedByMe); assertFalse(otherAccount.canConfirm(now))
    }
}
