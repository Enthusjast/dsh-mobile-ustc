package cn.edu.ustc.dsh.session

import cn.edu.ustc.dsh.protocol.*
import java.io.File
import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

class SessionApprovalsTest {
    private val context = ApprovalContext.from(JsonDocument.of(JsonDocument.parse(File(System.getProperty("contracts.root"), "security/approval-signatures.json").readBytes()).root.obj("context")))
    private val runtime = context.root.string("runtime_id")
    private val epoch = context.root.string("runtime_epoch")
    private val session = context.root.string("session_id")
    private val id = context.root.string("approval_id")
    private val host = context.root.string("host_id")
    private val watch = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private val request = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    private val connection = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    private val other = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    private val digest = "f".repeat(64)
    private val now = context.createdAt
    private val nanos = 1_000_000_000L
    private fun status(body: ApprovalContext = context) = jsonObject("approval_id" to body.root["approval_id"], "runtime_id" to body.root["runtime_id"],
        "runtime_epoch" to body.root["runtime_epoch"], "session_id" to body.root["session_id"], "execution_id" to body.root["execution_id"],
        "binding_sha256" to body.bindingSha256.json(), "state" to "pending".json(), "expires_at" to Contract.timestamp(body.expiresAt).json())
    private fun snapshot(items: List<JsonObject> = listOf(status())) = jsonObject("v" to 1L.json(), "type" to "approval.snapshot".json(),
        "runtime_id" to runtime.json(), "request_id" to watch.json(), "payload" to jsonObject("items" to JsonArray(items)))
    private fun routed(type: String, payload: JsonObject, correlation: String = request) = jsonObject("v" to 1L.json(), "type" to type.json(), "request_id" to correlation.json(),
        "runtime_id" to runtime.json(), "runtime_epoch" to epoch.json(), "session_id" to session.json(), "payload" to payload)
    private fun reference(item: JsonObject) = routed("approval.reference", jsonObject("status" to item), watch)
    private fun details(body: ApprovalContext = context) = routed("approval.details", jsonObject("context" to body.root))
    private fun model(items: List<JsonObject> = listOf(status())) = SessionApprovals(SessionRoute(runtime, epoch, session, other), host, connection, watch).also { it.snapshot(snapshot(items), now, nanos) }
    private fun reviewed(book: SessionApprovals): ApprovalReviewHandle {
        book.beginDetails(id, request, now, nanos)
        return book.details(details(), now, nanos)!!
    }
    private fun decision(state: String = "decision_received") = status().with("state" to state.json(), "decision" to "allow_once".json(), "decision_payload_sha256" to digest.json())
    private fun state(book: SessionApprovals) = book.state(now, nanos)
    private fun invalid(block: () -> Unit) { assertThrows(ApprovalStateException::class.java, block) }

    @Test fun `watch metadata never reconstructs a review or a tool body`() {
        val book = model()
        val item = state(book).items.single()
        assertTrue(state(book).loaded); assertTrue(item.canReview); assertNull(item.handle); assertNull(item.context)
        assertFalse(item.toString().contains(context.document.canonicalText()))
        val frame = book.beginDetails(id, request, now, nanos)
        assertEquals("approval.details.get", frame.string("type")); assertEquals(id, state(book).loadingId)
        invalid { book.beginDetails(id, other, now, nanos) }
        assertNull(state(book).items.single().context)
        val handle = book.details(details(), now, nanos)!!
        assertEquals(connection, handle.connectionId); assertEquals(context.bindingSha256, handle.bindingSha256)
        assertEquals(context.bindingSha256, book.requireReview(handle, now, nanos).bindingSha256)
        assertEquals(context.document.canonicalText(), state(book).items.single().context!!.document.canonicalText())
    }

    @Test fun `another device decision immediately retires a review and old pending replies cannot revive it`() {
        val book = model(); val handle = reviewed(book)
        book.reference(reference(decision()), nowMillis = now, nowNanos = nanos)
        assertNull(state(book).items.single().context); assertFalse(state(book).items.single().canReview)
        invalid { book.requireReview(handle, now, nanos) }
        book.reference(reference(status()), nowMillis = now, nowNanos = nanos)
        assertEquals(ApprovalRemoteState.DECISION_RECEIVED, state(book).items.single().status.state)
        invalid { book.beginDetails(id, other, now, nanos) }
    }

    @Test fun `a terminal reference cancels incomplete details without exposing partial arguments`() {
        val book = model(); book.beginDetails(id, request, now, nanos)
        val bytes = context.document.canonicalBytes()
        val first = routed("approval.fragment", jsonObject("kind" to "approval.details".json(), "transfer_id" to other.json(), "index" to 0L.json(),
            "count" to 2L.json(), "data" to Base64.getEncoder().encodeToString(bytes.copyOfRange(0, 20)).json()))
        assertNull(book.details(first, now, nanos)); assertNull(state(book).items.single().context)
        book.reference(reference(status().with("state" to "cancelled".json())), nowMillis = now, nowNanos = nanos)
        assertNull(state(book).loadingId); invalid { book.details(details(), now, nanos) }
        assertFalse(state(book).items.single().canReview)
    }

    @Test fun `routing changed contexts conflicting decisions and changed terminal outcomes require resynchronization`() {
        val book = model()
        invalid { book.update(ApprovalStatus.parse(status().with("execution_id" to other.json())), now, nanos) }
        invalid { book.update(ApprovalStatus.parse(status().with("binding_sha256" to digest.json())), now, nanos) }
        book.update(ApprovalStatus.parse(decision()), now, nanos)
        invalid { book.update(ApprovalStatus.parse(decision().with("decision" to "reject".json())), now, nanos) }
        invalid { book.update(ApprovalStatus.parse(decision().with("decision_payload_sha256" to "a".repeat(64).json())), now, nanos) }
        val settled = decision("allowed").with("host_state" to "settled".json(), "execution_outcome" to "succeeded".json())
        book.update(ApprovalStatus.parse(settled), now, nanos)
        invalid { book.update(ApprovalStatus.parse(settled.with("execution_outcome" to "failed".json())), now, nanos) }
    }

    @Test fun `native consumption unknown outcome and final completion remain different facts`() {
        val book = model()
        book.update(ApprovalStatus.parse(decision().with("host_state" to "approved".json())), now, nanos)
        assertNull(state(book).items.single().status.outcome)
        val consumed = decision("allowed").with("host_state" to "consumed".json())
        book.update(ApprovalStatus.parse(consumed), now, nanos)
        book.update(ApprovalStatus.parse(decision()), now, nanos)
        assertEquals(ApprovalHostState.CONSUMED, state(book).items.single().status.hostState)
        book.update(ApprovalStatus.parse(decision("outcome_unknown").with("host_state" to "outcome_unknown".json())), now, nanos)
        book.update(ApprovalStatus.parse(consumed), now, nanos)
        assertEquals(ApprovalRemoteState.OUTCOME_UNKNOWN, state(book).items.single().status.state)
        val settled = decision("allowed").with("host_state" to "settled".json(), "execution_outcome" to "failed".json())
        book.update(ApprovalStatus.parse(settled), now, nanos)
        book.update(ApprovalStatus.parse(consumed), now, nanos)
        assertEquals(ApprovalExecutionOutcome.FAILED, state(book).items.single().status.outcome)
    }

    @Test fun `wall clock rollback and repeated references cannot extend the original review deadline`() {
        val book = model(); val handle = reviewed(book)
        val lifetime = context.expiresAt - now
        book.update(ApprovalStatus.parse(status()), now - 20_000, nanos + 1_000_000)
        assertTrue(book.state(now - 20_000, nanos + 1_000_000).items.single().remainingMillis <= lifetime)
        assertFalse(book.state(now - 20_000, nanos + lifetime * 1_000_000).items.single().canReview)
        invalid { book.requireReview(handle, now, nanos + lifetime * 1_000_000) }
        book.update(ApprovalStatus.parse(status()), now, nanos)
        assertFalse(state(book).items.single().canReview)
    }

    @Test fun `expired or replaced online views never reuse an earlier reviewed handle`() {
        val first = model(); val old = reviewed(first)
        first.clearReview(); invalid { first.requireReview(old, now, nanos) }
        val replacement = reviewed(first)
        assertNotEquals(old, replacement)
        invalid { first.requireReview(old, now, nanos) }
        val reopened = model()
        assertNull(state(reopened).items.single().context)
        invalid { reopened.requireReview(replacement, now, nanos) }
        first.close(); assertTrue(state(first).items.isEmpty()); invalid { first.beginDetails(id, request, now, nanos) }
        val expired = model(); reviewed(expired)
        val state = expired.state(context.expiresAt, nanos + (context.expiresAt - now) * 1_000_000)
        assertNull(state.items.single().context); assertFalse(state.items.single().canReview)
    }

    @Test fun `current host and full details binding are checked independently of transport routing`() {
        val changed = ApprovalContext.from(JsonDocument.of(context.root.with("host_id" to other.json())))
        val book = model(listOf(status(changed)))
        book.beginDetails(id, request, now, nanos)
        assertThrows(ProtocolException::class.java) { book.details(details(changed), now, nanos) }
        assertNull(state(book).items.single().context); assertNull(state(book).loadingId)
        val wrongBody = model(); wrongBody.beginDetails(id, request, now, nanos)
        assertThrows(ProtocolException::class.java) { wrongBody.details(details(changed), now, nanos) }
    }

    @Test fun `old epochs and other sessions can never become current execution reviews`() {
        val book = model(listOf(status().with("runtime_epoch" to other.json()), status().with("approval_id" to other.json(), "session_id" to other.json())))
        assertEquals(1, state(book).items.size); assertFalse(state(book).items.single().canReview)
        invalid { book.beginDetails(id, request, now, nanos) }
        invalid { book.update(ApprovalStatus.parse(status().with("runtime_id" to other.json())), now, nanos) }
        val empty = SessionApprovals(SessionRoute(runtime, epoch, session, other), host, connection, watch)
        invalid { empty.reference(reference(status()), nowMillis = now, nowNanos = nanos) }
        invalid { book.snapshot(snapshot(), now, nanos) }
    }

    @Test fun `timeout and failed detail requests clear bodies and expose only fixed error categories`() {
        val book = model(); book.beginDetails(id, request, now, nanos)
        assertFalse(book.detailsTimedOut(nanos + 9_999_000_000)); assertTrue(book.detailsTimedOut(nanos + 10_000_000_000))
        assertFalse(book.detailsFailed(other, "secret")); assertTrue(book.detailsFailed(request, "body-secret"))
        assertEquals("approval.unavailable", state(book).error); assertNull(state(book).loadingId)
        book.beginDetails(id, request, now, nanos)
        val error = routed("approval.error", jsonObject("approval_id" to id.json(), "code" to "approval.expired".json()))
        assertEquals("approval.expired", book.detailsError(error)); assertEquals("approval.expired", state(book).error)
    }

    @Test fun `metadata growth is bounded for one foreground subscription`() {
        val book = model(emptyList())
        repeat(256) { index ->
            val uuid = "a%07x-aaaa-4aaa-8aaa-%012x".format(index, index)
            book.update(ApprovalStatus.parse(status().with("approval_id" to uuid.json())), now, nanos)
        }
        assertEquals(256, state(book).items.size)
        invalid { book.update(ApprovalStatus.parse(status()), now, nanos) }
    }
}
