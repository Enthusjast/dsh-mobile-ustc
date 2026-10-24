package cn.edu.ustc.dsh.protocol

import org.junit.Assert.*
import org.junit.Test
import java.io.File

class ApprovalContractTest {
    private fun fixture(): JsonObject = JsonDocument.parse(File(System.getProperty("contracts.root"), "security/approval-signatures.json").readBytes()).root

    @Test fun `contexts enforce exact fields resource uniqueness nonce and interval`() {
        val root = fixture().obj("context")
        val context = ApprovalContext.from(JsonDocument.of(root))
        val invalid = listOf(
            root.with("extra" to JsonNull), root.with("runtime_epoch" to "UPPERCASE".json()),
            root.with("nonce" to (root.string("nonce").dropLast(1) + "_").json()),
            root.with("policy_version" to JsonNumber(0.0)), root.with("policy_version" to JsonNumber(9007199254740992.0)),
            root.with("expires_at" to root["created_at"]),
            root.with("expires_at" to Contract.timestamp(context.createdAt + MAX_APPROVAL_LIFETIME_MS + 1).json()),
            root.with("created_at" to "2026-02-30T00:00:00.000Z".json()),
            root.with("tool" to "line\nbreak".json()), root.with("tool" to "中".repeat(43).json()),
            root.with("resources" to JsonArray(listOf(root.array("resources").first(), root.array("resources").first()))),
            root.with("workspace" to root.obj("workspace").with("path" to "/tmp".json())),
            root.with("required_assurance" to root.obj("required_assurance").with("max_auth_age_seconds" to 901L.json())),
        )
        invalid.forEachIndexed { index, value -> assertThrows("case $index", ProtocolException::class.java) { ApprovalContext.from(JsonDocument.of(value)) } }
        assertTrue(context.current(context.createdAt - APPROVAL_CLOCK_SKEW_MS))
        assertFalse(context.current(context.createdAt - APPROVAL_CLOCK_SKEW_MS - 1))
        assertFalse(context.current(context.expiresAt))
    }

    @Test fun `decisions bind both choices to one exact context and expire at the request boundary`() {
        val fixture = fixture()
        val context = ApprovalContext.from(JsonDocument.of(fixture.obj("context")))
        val key = fixture.obj("registered")
        val now = Contract.utc(fixture.string("now"))
        for (choice in ApprovalChoice.entries) {
            val decision = ApprovalDecision.create(context, choice, key.string("user_id"), key.string("device_id"), key.integer("key_version"), now)
            assertTrue(decision.matches(context, now))
            assertFalse(decision.matches(context, context.expiresAt))
            assertFalse(decision.matches(context, now + MAX_DECISION_AGE_MS + 1))
            val changed = ApprovalContext.from(JsonDocument.of(context.root.with("arguments" to JsonNull)))
            assertFalse(decision.matches(changed, now))
            assertThrows(ProtocolException::class.java) { ApprovalDecision.create(context, choice, key.string("user_id"), key.string("device_id"), 1, now, context.expiresAt + 1) }
        }
    }
}
