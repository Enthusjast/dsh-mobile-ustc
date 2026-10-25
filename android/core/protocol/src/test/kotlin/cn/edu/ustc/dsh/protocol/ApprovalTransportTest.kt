package cn.edu.ustc.dsh.protocol

import java.io.File
import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

class ApprovalTransportTest {
    private val context = ApprovalContext.from(JsonDocument.of(JsonDocument.parse(File(System.getProperty("contracts.root"), "security/approval-signatures.json").readBytes()).root.obj("context")))
    private val request = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private val transfer = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    private val other = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    private val decisionDigest = "a".repeat(64)
    private fun status(body: ApprovalContext = context): JsonObject = jsonObject(
        "approval_id" to body.root["approval_id"], "runtime_id" to body.root["runtime_id"], "runtime_epoch" to body.root["runtime_epoch"],
        "session_id" to body.root["session_id"], "execution_id" to body.root["execution_id"], "binding_sha256" to body.bindingSha256.json(),
        "state" to "pending".json(), "expires_at" to Contract.timestamp(body.expiresAt).json())
    private fun routed(type: String, payload: JsonObject, body: ApprovalContext = context): JsonObject = jsonObject(
        "v" to 1L.json(), "type" to type.json(), "request_id" to request.json(), "runtime_id" to body.root["runtime_id"],
        "runtime_epoch" to body.root["runtime_epoch"], "session_id" to body.root["session_id"], "payload" to payload)
    private fun details(body: ApprovalContext = context) = routed("approval.details", jsonObject("context" to body.root), body)
    private fun receiver(body: ApprovalContext = context) = ApprovalDetailsTransfer(ApprovalStatus.parse(status(body)), request, body.root.string("host_id"))
    private fun part(data: ByteArray, index: Int, count: Int, body: ApprovalContext = context) = routed("approval.fragment", jsonObject(
        "kind" to "approval.details".json(), "transfer_id" to transfer.json(), "index" to index.toLong().json(), "count" to count.toLong().json(),
        "data" to Base64.getEncoder().encodeToString(data).json()), body)
    private fun fragments(body: ApprovalContext): List<JsonObject> {
        val bytes = body.document.canonicalBytes()
        val chunks = bytes.toList().chunked(40 * 1024).map { it.toByteArray() }
        return chunks.mapIndexed { index, data -> part(data, index, chunks.size, body) }
    }
    private fun large(): ApprovalContext = ApprovalContext.from(JsonDocument.of(context.root.with("arguments" to jsonObject("text" to "中🙂".repeat(17_500).json()))))
    private fun invalid(block: () -> Unit) { assertThrows(ProtocolException::class.java, block) }

    @Test fun `metadata keeps native execution facts distinct from decision and delivery facts`() {
        val pending = ApprovalStatus.parse(status())
        assertTrue(pending.pending(context.createdAt)); assertFalse(pending.pending(context.expiresAt)); assertTrue(pending.matches(context))
        val accepted = status().with("state" to "decision_received".json(), "decision" to "allow_once".json(), "decision_payload_sha256" to decisionDigest.json())
        val result = ApprovalAdmission.parse(jsonObject("status" to accepted, "delivery" to "forwarded".json()), pending, ApprovalChoice.ALLOW_ONCE, decisionDigest)
        assertEquals(ApprovalDelivery.FORWARDED, result.delivery); assertNull(result.status.hostState); assertNull(result.status.outcome)
        assertFalse(result.status.pending(context.createdAt))
        val settled = ApprovalStatus.parse(accepted.with("state" to "allowed".json(), "host_state" to "settled".json(), "execution_outcome" to "failed".json()))
        assertEquals(ApprovalRemoteState.ALLOWED, settled.state); assertEquals(ApprovalExecutionOutcome.FAILED, settled.outcome)
        assertTrue(pending.sameRequest(settled))
        for (state in ApprovalRemoteState.entries) assertEquals(state, ApprovalStatus.parse(status().with("state" to state.wire.json())).state)
    }

    @Test fun `unknown status fields malformed optional facts and inconsistent native outcomes are refused`() {
        val root = status()
        val changes = listOf(root.with("arguments" to JsonNull), root.with("decision" to JsonNull), root.with("host_state" to "running".json()),
            root.with("state" to "settled".json()), root.with("decision_payload_sha256" to "A".repeat(64).json()),
            root.with("execution_outcome" to "succeeded".json()), root.with("host_state" to "settled".json()),
            root.with("runtime_epoch" to "UNKNOWN".json()), root.with("expires_at" to "2026-02-30T00:00:00Z".json()))
        changes.forEach { invalid { ApprovalStatus.parse(it) } }
        val changed = ApprovalContext.from(JsonDocument.of(context.root.with("arguments" to JsonNull)))
        assertFalse(ApprovalStatus.parse(root).matches(changed))
    }

    @Test fun `snapshots are bounded unique and correlated to the current runtime watch`() {
        val runtime = context.root.string("runtime_id")
        val frame = jsonObject("v" to 1L.json(), "type" to "approval.snapshot".json(), "runtime_id" to runtime.json(), "request_id" to request.json(),
            "payload" to jsonObject("items" to JsonArray(listOf(status()))))
        assertEquals(context.bindingSha256, ApprovalTransport.snapshot(frame, runtime, request).single().bindingSha256)
        invalid { ApprovalTransport.snapshot(frame, runtime, other) }
        invalid { ApprovalTransport.snapshot(frame, other, request) }
        invalid { ApprovalTransport.snapshot(frame.with("runtime_epoch" to context.root["runtime_epoch"]), runtime, request) }
        for (items in listOf(listOf(status(), status()), List(65) { status() }, listOf(status().with("runtime_id" to other.json())))) {
            invalid { ApprovalTransport.snapshot(frame.with("payload" to jsonObject("items" to JsonArray(items))), runtime, request) }
        }
        val statuses = ApprovalTransport.snapshot(frame, runtime, request)
        assertThrows(UnsupportedOperationException::class.java) { (statuses as MutableList).clear() }
    }

    @Test fun `references and error replies cannot substitute routing or body identities`() {
        val runtime = context.root.string("runtime_id")
        val reference = routed("approval.reference", jsonObject("status" to status()))
        assertTrue(ApprovalTransport.reference(reference, runtime, request).matches(context))
        for (name in listOf("runtime_id", "runtime_epoch", "session_id", "request_id")) invalid { ApprovalTransport.reference(reference.with(name to other.json()), runtime, request) }
        invalid { ApprovalTransport.reference(reference.with("payload" to jsonObject("status" to status().with("session_id" to other.json()))), runtime, request) }
        val error = routed("approval.error", jsonObject("approval_id" to context.root["approval_id"], "code" to "approval.stale".json()))
        assertEquals("approval.stale", ApprovalTransport.error(error, ApprovalStatus.parse(status()), request))
        invalid { ApprovalTransport.error(error.with("payload" to error.obj("payload").with("approval_id" to other.json())), ApprovalStatus.parse(status()), request) }
        invalid { ApprovalTransport.error(error.with("payload" to error.obj("payload").with("code" to "body-secret".json())), ApprovalStatus.parse(status()), request) }
    }

    @Test fun `ordinary details must match the entire reference and expected host`() {
        val body = receiver().accept(details())!!
        assertEquals(context.document.canonicalText(), body.document.canonicalText())
        val mutations = listOf("runtime_id", "runtime_epoch", "session_id", "request_id")
        mutations.forEach { name -> invalid { receiver().accept(details().with(name to other.json())) } }
        for (name in listOf("execution_id", "approval_id", "host_id", "installation_id")) {
            val changed = ApprovalContext.from(JsonDocument.of(context.root.with(name to other.json())))
            invalid { receiver().accept(details(changed)) }
        }
        val changed = ApprovalContext.from(JsonDocument.of(context.root.with("arguments" to JsonNull)))
        invalid { receiver().accept(details(changed)) }
        invalid { ApprovalDetailsTransfer(ApprovalStatus.parse(status()), request, other).accept(details()) }
        invalid { receiver().accept(details().with("payload" to details().obj("payload").with("extra" to JsonNull))) }
    }

    @Test fun `large Unicode contexts become visible only after all original bytes arrive`() {
        val body = large(); val frames = fragments(body); val reader = receiver(body)
        assertEquals(4, frames.size)
        frames.dropLast(1).forEach { assertNull(reader.accept(it, 1_000_000_000)) }
        val restored = reader.accept(frames.last(), 2_000_000_000)!!
        assertEquals(body.bindingSha256, restored.bindingSha256)
        assertEquals(body.document.canonicalText(), restored.document.canonicalText())
        assertNull(reader.pendingMillis())
        invalid { reader.accept(frames.first()) }
        invalid { receiver(body).accept(details(body)) }
    }

    @Test fun `fragment routing ordering and transfer identity cannot be replaced mid-context`() {
        val body = large(); val frames = fragments(body)
        val substitutions = listOf(frames.first(), frames[1].with("request_id" to other.json()), frames[1].with("session_id" to other.json()),
            frames[1].with("payload" to frames[1].obj("payload").with("transfer_id" to other.json())),
            frames[1].with("payload" to frames[1].obj("payload").with("count" to 3L.json())),
            frames[1].with("payload" to frames[1].obj("payload").with("kind" to "approval.request".json())))
        substitutions.forEach { changed ->
            val reader = receiver(body); assertNull(reader.accept(frames.first(), 0))
            invalid { reader.accept(changed, 1) }
            assertNull(reader.pendingMillis()); invalid { reader.accept(frames[1], 2) }
        }
        invalid { receiver(body).accept(frames[1]) }
        val reader = receiver(body); reader.close(); invalid { reader.accept(frames.first()) }
    }

    @Test fun `fragment timeout total bytes malformed encodings and hostile JSON never expose a context`() {
        val body = large(); val frames = fragments(body); val reader = receiver(body)
        reader.accept(frames.first(), 1_000_000_000)
        assertEquals(1L, reader.pendingMillis(3_999_000_000))
        invalid { reader.accept(frames[1], 4_000_000_000) }
        for (data in listOf("Zh==", "Zg", "Zg==\n", "@@@@", "", "A".repeat(54_620))) {
            invalid { receiver().accept(part(byteArrayOf(1), 0, 1).with("payload" to part(byteArrayOf(1), 0, 1).obj("payload").with("data" to data.json()))) }
        }
        for (data in listOf("{\"domain\":null,\"domain\":null}".toByteArray(), byteArrayOf(0xc3.toByte(), 0x28), "{\"x\":\"\\ud800\"}".toByteArray())) {
            invalid { receiver().accept(part(data, 0, 1)) }
        }
        val oversized = receiver()
        repeat(3) { assertNull(oversized.accept(part(ByteArray(40 * 1024) { 120 }, it, 4), 0)) }
        invalid { oversized.accept(part(ByteArray(40 * 1024) { 120 }, 3, 4), 1) }
    }

    @Test fun `HTTP admission proves the original decision without equating forwarding with execution`() {
        val reference = ApprovalStatus.parse(status())
        val accepted = status().with("state" to "decision_received".json(), "decision" to "reject".json(), "decision_payload_sha256" to decisionDigest.json())
        for (delivery in ApprovalDelivery.entries) {
            val root = jsonObject("status" to accepted, "delivery" to delivery.wire.json())
            val result = ApprovalAdmission.parse(root, reference, ApprovalChoice.REJECT, decisionDigest)
            assertEquals(delivery, result.delivery); assertNull(result.status.outcome)
        }
        val root = jsonObject("status" to accepted, "delivery" to "forwarded".json())
        invalid { ApprovalAdmission.parse(root, reference, ApprovalChoice.ALLOW_ONCE, decisionDigest) }
        invalid { ApprovalAdmission.parse(root, reference, ApprovalChoice.REJECT, "b".repeat(64)) }
        invalid { ApprovalAdmission.parse(root.with("status" to accepted.with("binding_sha256" to "b".repeat(64).json())), reference, ApprovalChoice.REJECT, decisionDigest) }
        invalid { ApprovalAdmission.parse(root.with("status" to accepted.with("state" to "pending".json())), reference, ApprovalChoice.REJECT, decisionDigest) }
    }

    @Test fun `outgoing requests use independent correlations and never include a context or decision`() {
        val reference = ApprovalStatus.parse(status())
        for (frame in listOf(ApprovalTransport.subscribe(reference.runtimeId, request), ApprovalTransport.unsubscribe(reference.runtimeId, request), ApprovalTransport.status(reference.runtimeId, request, reference.id))) {
            frame.exactKeys("v", "type", "runtime_id", "request_id", "payload")
            assertEquals(request, frame.string("request_id"))
        }
        val detail = ApprovalTransport.details(reference, request)
        detail.obj("payload").exactKeys("approval_id")
        assertEquals(reference.epoch, detail.string("runtime_epoch")); assertEquals(reference.sessionId, detail.string("session_id"))
    }

    @Test fun `weaker or contradictory metadata cannot erase proved consumption or a final result`() {
        val consumed = ApprovalStatus.parse(status().with("state" to "allowed".json(), "decision" to "allow_once".json(),
            "decision_payload_sha256" to decisionDigest.json(), "host_state" to "consumed".json()))
        assertSame(consumed, consumed.advance(ApprovalStatus.parse(status())))
        val settled = ApprovalStatus.parse(consumed.root.with("host_state" to "settled".json(), "execution_outcome" to "succeeded".json()))
        for (host in listOf("denied", "expired", "cancelled", "invalidated")) {
            val ending = ApprovalStatus.parse(status().with("state" to host.json(), "host_state" to host.json()))
            invalid { consumed.advance(ending) }
            invalid { settled.advance(ending) }
        }
        val contradictory = ApprovalStatus.parse(status().with("state" to "allowed".json(), "host_state" to "settled".json(), "execution_outcome" to "failed".json()))
        invalid { settled.advance(contradictory) }
        assertSame(settled, settled.advance(consumed))
    }
}
