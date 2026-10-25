package cn.edu.ustc.dsh.command

import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.protocol.*
import java.io.File
import org.junit.Assert.*
import org.junit.Test

class ApprovalDecisionIntentTest {
    private val fixture = JsonDocument.parse(File(System.getProperty("contracts.root"), "security/approval-signatures.json").readBytes()).root
    private val context = ApprovalContext.from(JsonDocument.of(fixture.obj("context")))
    private val key = RegisteredApprovalKey.parse(fixture.obj("registered"))
    private val now = Contract.utc(fixture.string("now"))
    private val request = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private val other = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    private val owner = CommandOwner(request, other, "c".repeat(64), key.userId, key.deviceId)
    private fun signed(choice: ApprovalChoice = ApprovalChoice.ALLOW_ONCE): SignedApprovalDecision {
        val vector = fixture.array("vectors").map { it as JsonObject }.first { it.fields["invalid"] != JsonBoolean(true) && it.string("decision") == choice.wire }
        return ApprovalSignatures.verify(vector.string("compact"), key, context, now)
    }
    private fun intent(choice: ApprovalChoice = ApprovalChoice.ALLOW_ONCE) = ApprovalDecisionIntent.create(request, owner, key, context, signed(choice), now)
    private fun pending() = ApprovalDecisionEvolution.created(intent(), now)
    private fun status(state: String = "pending", choice: ApprovalChoice? = null, digest: String? = null, host: String? = null, outcome: String? = null): ApprovalStatus {
        val fields = linkedMapOf("approval_id" to context.root["approval_id"], "runtime_id" to context.root["runtime_id"], "runtime_epoch" to context.root["runtime_epoch"],
            "session_id" to context.root["session_id"], "execution_id" to context.root["execution_id"], "binding_sha256" to context.bindingSha256.json(),
            "expires_at" to Contract.timestamp(context.expiresAt).json(), "state" to state.json())
        choice?.let { fields["decision"] = it.wire.json() }; digest?.let { fields["decision_payload_sha256"] = it.json() }
        host?.let { fields["host_state"] = it.json() }; outcome?.let { fields["execution_outcome"] = it.json() }
        return ApprovalStatus.parse(JsonObject(fields))
    }
    private fun accepted(intent: ApprovalDecisionIntent = intent(), host: String? = null, outcome: String? = null) = status(if (host in setOf("consumed", "settled")) "allowed" else "decision_received",
        intent.decision.choice, intent.signed.payloadSha256, host, outcome)

    @Test fun `original proofs retain exact signed bytes and expired restore grants no fresh authority`() {
        for (choice in ApprovalChoice.entries) {
            val original = intent(choice)
            val restored = ApprovalDecisionIntent.restore(request, owner, key, original.context.document.canonicalBytes(), original.signed.compact)
            assertEquals(original.digest, restored.digest); assertEquals(original.signed.compact, restored.signed.compact)
            assertEquals(context.document.canonicalText(), restored.context.document.canonicalText()); assertEquals(choice, restored.decision.choice)
            assertFalse(restored.current(context.expiresAt)); assertFalse(restored.current(restored.decision.issuedAt + MAX_DECISION_AGE_MS + 1))
            assertFalse(restored.toString().contains(original.signed.compact)); assertFalse(restored.toString().contains(context.document.canonicalText()))
            val uncertain = ApprovalDecisionEvolution.begin(ApprovalDecisionEvolution.created(restored, now), now)
            assertEquals(ApprovalDecisionDelivery.RECONCILE, uncertain.delivery); assertEquals(1L, uncertain.attempts)
        }
    }

    @Test fun `restoration independently verifies signature key owner and complete historical context`() {
        val original = intent()
        val wrongOwner = CommandOwner(request, other, owner.deploymentHash, other, key.deviceId)
        assertThrows(CommandDataException::class.java) { ApprovalDecisionIntent.restore(request, wrongOwner, key, context.document.canonicalBytes(), original.signed.compact) }
        val changed = ApprovalContext.from(JsonDocument.of(context.root.with("arguments" to JsonNull)))
        assertThrows(ApprovalSignatureException::class.java) { ApprovalDecisionIntent.restore(request, owner, key, changed.document.canonicalBytes(), original.signed.compact) }
        val parts = original.signed.compact.split('.')
        val bytes = Contract.base64url(parts[2]); bytes[0] = (bytes[0].toInt() xor 1).toByte()
        assertThrows(ApprovalSignatureException::class.java) { ApprovalDecisionIntent.restore(request, owner, key, context.document.canonicalBytes(), "${parts[0]}.${parts[1]}.${Contract.base64url(bytes)}") }
        val inactive = RegisteredApprovalKey.parse(keyFields().with("active" to JsonBoolean(false)))
        assertThrows(CommandDataException::class.java) { ApprovalDecisionIntent.restore(request, owner, inactive, context.document.canonicalBytes(), original.signed.compact) }
    }
    private fun keyFields() = fixture.obj("registered")

    @Test fun `creation and dispatch enforce current context and the short decision age limit`() {
        val original = intent()
        assertThrows(ApprovalSignatureException::class.java) { ApprovalDecisionIntent.create(request, owner, key, context, signed(), context.expiresAt) }
        assertThrows(CommandDataException::class.java) { ApprovalDecisionEvolution.created(original, context.expiresAt) }
        assertThrows(CommandDataException::class.java) { ApprovalDecisionEvolution.begin(pending(), original.decision.issuedAt + MAX_DECISION_AGE_MS + 1) }
        val attempt = ApprovalDecisionEvolution.begin(pending(), now)
        assertThrows(CommandDataException::class.java) { ApprovalDecisionEvolution.begin(attempt, now) }
        assertEquals(ApprovalDecisionDelivery.RECONCILE, attempt.delivery)
    }

    @Test fun `only a fresh pending proof can rearm the same original unconfirmed decision`() {
        val first = ApprovalDecisionEvolution.begin(pending(), now)
        val fresh = status()
        val rearmed = ApprovalDecisionEvolution.rearm(first, fresh, now + 1)
        val second = ApprovalDecisionEvolution.begin(rearmed, now + 2)
        assertEquals(first.intent.digest, second.intent.digest); assertEquals(first.intent.signed.compact, second.intent.signed.compact)
        assertEquals(2L, second.attempts); assertEquals(ApprovalDecisionDelivery.RECONCILE, second.delivery)
        assertThrows(CommandDataException::class.java) { ApprovalDecisionEvolution.rearm(first, status("expired"), now + 1) }
        assertThrows(CommandDataException::class.java) { ApprovalDecisionEvolution.rearm(first, fresh, context.expiresAt) }
        assertThrows(CommandDataException::class.java) { ApprovalDecisionEvolution.rearm(pending(), fresh, now) }
    }

    @Test fun `accepted transport remains separate from host consumption and final result`() {
        val attempted = ApprovalDecisionEvolution.begin(pending(), now)
        val saved = ApprovalDecisionEvolution.record(attempted, accepted(), now, ApprovalDelivery.FORWARDED)
        assertEquals(ApprovalDecisionDelivery.ACCEPTED, saved.delivery); assertNull(saved.remote!!.hostState); assertNull(saved.remote.outcome)
        assertEquals(ApprovalDelivery.FORWARDED, saved.forwarding)
        assertSame(saved, ApprovalDecisionEvolution.record(saved, accepted(), now, ApprovalDelivery.PENDING))
        val consumed = ApprovalDecisionEvolution.record(saved, accepted(host = "consumed"), now + 1)
        assertEquals(ApprovalHostState.CONSUMED, consumed.remote!!.hostState); assertNull(consumed.remote.outcome)
        val ended = ApprovalDecisionEvolution.record(consumed, accepted(host = "settled", outcome = "failed"), now + 2)
        assertEquals(ApprovalExecutionOutcome.FAILED, ended.remote!!.outcome)
        val older = ApprovalDecisionEvolution.record(ended, accepted(), now + 3)
        assertSame(ended, older)
        assertThrows(CommandDataException::class.java) { ApprovalDecisionEvolution.rearm(ended, status(), now + 3) }
    }

    @Test fun `foreign competing decisions end local eligibility without being attributed to this proof`() {
        val row = ApprovalDecisionEvolution.record(pending(), status("denied", ApprovalChoice.REJECT, "d".repeat(64), "denied"), now)
        assertEquals(ApprovalDecisionDelivery.CONFLICT, row.delivery); assertEquals(0L, row.attempts)
        assertThrows(CommandDataException::class.java) { ApprovalDecisionEvolution.begin(row, now) }
        val ended = ApprovalDecisionEvolution.record(pending(), status("cancelled"), now)
        assertEquals(ApprovalDecisionDelivery.ENDED, ended.delivery)
        val older = ApprovalDecisionEvolution.record(ended, status(), now + 1)
        assertEquals(ApprovalDecisionDelivery.ENDED, older.delivery)
    }

    @Test fun `unsent acknowledgements and conflicting request result or decision facts are refused`() {
        assertThrows(CommandDataException::class.java) { ApprovalDecisionEvolution.record(pending(), accepted(), now) }
        val attempt = ApprovalDecisionEvolution.begin(pending(), now)
        val altered = ApprovalStatus.parse(status().root.with("binding_sha256" to "a".repeat(64).json()))
        assertThrows(CommandDataException::class.java) { ApprovalDecisionEvolution.record(attempt, altered, now) }
        val inconsistent = status("decision_received", ApprovalChoice.REJECT, attempt.intent.signed.payloadSha256)
        assertThrows(CommandDataException::class.java) { ApprovalDecisionEvolution.record(attempt, inconsistent, now) }
        assertThrows(CommandDataException::class.java) { ApprovalDecisionEvolution.record(attempt, status("pending", attempt.intent.decision.choice, attempt.intent.signed.payloadSha256), now) }
        val accepted = ApprovalDecisionEvolution.record(attempt, accepted(), now)
        assertThrows(CommandDataException::class.java) { ApprovalDecisionEvolution.record(accepted, status("denied", ApprovalChoice.REJECT, "d".repeat(64)), now) }
        assertThrows(CommandDataException::class.java) { ApprovalDecisionEvolution.record(attempt, status(), now, ApprovalDelivery.FORWARDED) }
    }

    @Test fun `lost receipts preserve reconciliation and sanitize unexpected errors`() {
        val attempted = ApprovalDecisionEvolution.begin(pending(), now)
        val uncertain = ApprovalDecisionEvolution.uncertain(attempted, now + 1, "secret-tool-body")
        assertEquals("approval.delivery_unconfirmed", uncertain.error)
        val freshPending = ApprovalDecisionEvolution.record(uncertain, status(), now + 2)
        assertEquals(ApprovalDecisionDelivery.RECONCILE, freshPending.delivery); assertEquals(1L, freshPending.attempts)
        val accepted = ApprovalDecisionEvolution.record(freshPending, accepted(), now + 3)
        assertSame(accepted, ApprovalDecisionEvolution.uncertain(accepted, now + 4, "approval.status_unavailable"))
        assertSame(accepted, ApprovalDecisionEvolution.record(accepted, status(), now + 4))
    }
}
