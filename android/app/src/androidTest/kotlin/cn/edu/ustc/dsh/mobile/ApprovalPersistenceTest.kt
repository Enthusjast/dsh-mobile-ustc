package cn.edu.ustc.dsh.mobile

import android.app.KeyguardManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.data.SqlCommandJournal
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/** Storage evidence uses ephemeral JCA signing keys; actual per-use AndroidKeyStore signing has its own suite. */
@RunWith(AndroidJUnit4::class)
class ApprovalPersistenceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val account = UUID.randomUUID().toString()
    private val org = UUID.randomUUID().toString()
    private val user = UUID.randomUUID().toString()
    private val device = UUID.randomUUID().toString()
    private val runtime = UUID.randomUUID().toString()
    private val session = UUID.randomUUID().toString()
    private val workspace = UUID.randomUUID().toString()
    private val epoch = UUID.randomUUID().toString()
    private val owner get() = LocalDataOwner(account, org, "a".repeat(64), user, device)
    private val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val public = (pair.public as ECPublicKey).let { value ->
        fun coordinate(number: java.math.BigInteger): JsonString {
            val bytes = number.toByteArray().takeLast(32).toByteArray()
            return Contract.base64url(ByteArray(32 - bytes.size) + bytes).json()
        }
        jsonObject("kty" to "EC".json(), "crv" to "P-256".json(), "x" to coordinate(value.w.affineX), "y" to coordinate(value.w.affineY))
    }
    private fun registered(userId: String = user, deviceId: String = device) = RegisteredApprovalKey.parse(jsonObject("user_id" to userId.json(), "device_id" to deviceId.json(),
        "key_version" to 1L.json(), "active" to JsonBoolean(true), "public_jwk" to public, "approval_key_jkt" to PublicProofKey(public).thumbprint.json()))
    private val parents = mutableListOf<SqlCommandJournal>()
    private val children = mutableListOf<ApprovalDecisionJournal>()
    private fun open(value: LocalDataOwner = owner) = SqlCommandJournal.open(context, value).also { parents += it }
    private fun decisions(parent: SqlCommandJournal, key: RegisteredApprovalKey = registered()) = parent.approvalDecisions(key).also { children += it }
    @Before fun requireFixture() {
        assumeTrue("explicit owned account fixture required", InstrumentationRegistry.getArguments().getString("accountFixture") == "true")
        val guard = context.getSystemService(KeyguardManager::class.java); assertTrue(guard.isDeviceSecure && !guard.isDeviceLocked)
    }
    @After fun cleanup() { children.forEach(ApprovalDecisionJournal::close); parents.forEach(SqlCommandJournal::close); SqlCommandJournal.eraseAccount(context, account, org) }

    private fun body(text: String = "APPROVAL_DB_SECRET_中文🙂_${UUID.randomUUID()}", runtimeId: String = runtime, workspaceId: String = workspace): ApprovalContext {
        val now = System.currentTimeMillis()
        return ApprovalContext.from(JsonDocument.of(jsonObject("domain" to APPROVAL_CONTEXT_DOMAIN.json(), "protocol_version" to 1L.json(),
            "host_id" to UUID.randomUUID().toString().json(), "installation_id" to UUID.randomUUID().toString().json(), "runtime_id" to runtimeId.json(), "runtime_epoch" to epoch.json(),
            "session_id" to session.json(), "dsh_session_id" to "opaque-storage-fixture".json(), "approval_id" to UUID.randomUUID().toString().json(),
            "execution_id" to UUID.randomUUID().toString().json(), "call_id" to "storage-call".json(), "tool" to "bash".json(), "arguments" to jsonObject("command" to text.json()),
            "workspace" to jsonObject("workspace_id" to workspaceId.json(), "root_sha256" to "b".repeat(64).json()), "resources" to JsonArray(emptyList()),
            "nonce" to Contract.base64url(ByteArray(32).also { SecureRandom().nextBytes(it) }).json(), "policy_version" to 1L.json(),
            "required_assurance" to jsonObject("profile" to "fixture/step-up".json(), "max_auth_age_seconds" to 60L.json()),
            "created_at" to Contract.timestamp(now).json(), "expires_at" to Contract.timestamp(now + 120_000).json())))
    }
    private fun intent(body: ApprovalContext = body(), id: String = UUID.randomUUID().toString(), choice: ApprovalChoice = ApprovalChoice.ALLOW_ONCE): ApprovalDecisionIntent {
        val now = System.currentTimeMillis(); val key = registered()
        val prepared = ApprovalSignatures.prepare(body, choice, key, now)
        val signature = Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(prepared.signingInput()); sign() }
        return ApprovalDecisionIntent.create(id, owner, key, body, prepared.finishDerSignature(signature, now), now)
    }
    private fun status(intent: ApprovalDecisionIntent, state: String = "decision_received", own: Boolean = true): ApprovalStatus = ApprovalStatus.parse(jsonObject(
        "approval_id" to intent.context.root["approval_id"], "runtime_id" to intent.context.root["runtime_id"], "runtime_epoch" to intent.context.root["runtime_epoch"],
        "session_id" to intent.context.root["session_id"], "execution_id" to intent.context.root["execution_id"], "binding_sha256" to intent.context.bindingSha256.json(),
        "expires_at" to Contract.timestamp(intent.context.expiresAt).json(), "state" to state.json(), "decision" to (if (own) intent.decision.choice.wire else "reject").json(),
        "decision_payload_sha256" to (if (own) intent.signed.payloadSha256 else "d".repeat(64)).json()))

    @Test fun encryptedOriginalContextAndProofReopenUncertainWithoutNewSigningOrAutomaticReplay(): Unit = runBlocking {
        val original = intent(); val parent = open(); val journal = decisions(parent)
        journal.create(original); journal.beginAttempt(original.requestId)
        val folder = File(context.noBackupFilesDir, "mobile-data/${owner.scopeHash}/${owner.fingerprint}")
        for (marker in listOf(original.context.root.obj("arguments").string("command"), original.signed.compact)) {
            val needle = marker.toByteArray(Charsets.UTF_8)
            for (file in folder.walkTopDown().filter { it.isFile }) {
                val bytes = file.readBytes()
                assertFalse("plaintext in ${file.name}", bytes.size >= needle.size && (0..bytes.size - needle.size).any { offset -> needle.indices.all { bytes[offset + it] == needle[it] } })
            }
        }
        parent.close()
        val restored = decisions(open()).list(runtime, session).single()
        assertEquals(original.digest, restored.intent.digest); assertEquals(original.signed.compact, restored.intent.signed.compact)
        assertArrayEquals(original.context.document.canonicalBytes(), restored.intent.context.document.canonicalBytes())
        assertEquals(ApprovalDecisionDelivery.RECONCILE, restored.delivery); assertEquals(1L, restored.attempts)
        assertThrows(CommandDataException::class.java) { runBlocking { children.last().beginAttempt(original.requestId) } }
        assertFalse(restored.intent.current(original.context.expiresAt))
    }

    @Test fun oneApprovalKeepsOneOriginalDecisionAndSharesTheCommandRequestNamespace(): Unit = runBlocking {
        val original = intent(); val parent = open(); val journal = decisions(parent)
        journal.create(original)
        assertThrows(CommandDataException::class.java) { runBlocking { journal.create(intent(original.context, choice = ApprovalChoice.REJECT)) } }
        assertThrows(CommandDataException::class.java) { runBlocking { parent.create(CommandIntent.message(original.requestId, runtime, session, "queue", "collision")) } }
        val message = CommandIntent.message(UUID.randomUUID().toString(), runtime, session, "queue", "existing")
        parent.create(message)
        assertThrows(CommandDataException::class.java) { runBlocking { journal.create(intent(id = message.requestId)) } }
        assertEquals(original.digest, journal.list(runtime, session).single().intent.digest)
        journal.discard(original.requestId); assertTrue(journal.list(runtime, session).isEmpty())
    }

    @Test fun refusedRetryStillCommitsTheNewlyProvedDecisionBeforeReopen(): Unit = runBlocking {
        val original = intent(); val parent = open(); val journal = decisions(parent)
        journal.create(original); journal.beginAttempt(original.requestId)
        assertThrows(CommandDataException::class.java) { runBlocking { journal.rearm(original.requestId, status(original)) } }
        parent.close()
        val restored = decisions(open()).list(runtime, session).single()
        val proof = restored.remote!!
        assertEquals(ApprovalDecisionDelivery.ACCEPTED, restored.delivery); assertEquals(original.signed.payloadSha256, proof.decisionSha256)
        assertNull(proof.hostState); assertNull(proof.outcome)
        assertThrows(CommandDataException::class.java) { runBlocking { children.last().discard(original.requestId) } }
    }

    @Test fun aCompetingDeviceDecisionIsRetainedAsAConflictWithoutClaimingOurAcceptance(): Unit = runBlocking {
        val original = intent(); val journal = decisions(open())
        journal.create(original); journal.record(original.requestId, status(original, "denied", false))
        val record = journal.list(runtime, session).single()
        assertEquals(ApprovalDecisionDelivery.CONFLICT, record.delivery); assertEquals(0L, record.attempts)
        assertThrows(CommandDataException::class.java) { runBlocking { journal.beginAttempt(original.requestId) } }
    }

    @Test fun deviceIsolationRevocationAndClosedParentsFenceStoredProofs(): Unit = runBlocking {
        val original = intent(); val parent = open(); val journal = decisions(parent); journal.create(original)
        val secondDevice = UUID.randomUUID().toString(); val secondOwner = LocalDataOwner(account, org, owner.deploymentHash, user, secondDevice)
        assertTrue(decisions(open(secondOwner), registered(deviceId = secondDevice)).list(runtime, session).isEmpty())
        assertThrows(CommandDataException::class.java) { parent.approvalDecisions(registered(deviceId = secondDevice)) }
        assertTrue(journal.list(runtime, UUID.randomUUID().toString()).isEmpty())
        val another = intent(body(runtimeId = UUID.randomUUID().toString())); journal.create(another)
        parent.revokeRuntime(runtime)
        assertTrue(journal.list(runtime, session).isEmpty()); assertEquals(1, journal.list(another.runtimeId, session).size)
        parent.close()
        assertThrows(CommandDataException::class.java) { runBlocking { journal.list(another.runtimeId, session) } }
    }

    @Test fun permissionAndResourceShrinkRemoveApprovalBodiesWithoutRemovingAuthorizedChat(): Unit = runBlocking {
        val parent = open(); val journal = decisions(parent); val original = intent(); journal.create(original)
        val message = CommandIntent.message(UUID.randomUUID().toString(), runtime, session, "queue", "retained chat")
        parent.create(message)
        parent.retainApprovals(mapOf(runtime to RelayScope(listOf("session.read", "approval.decide"), listOf(workspace), emptyList())))
        assertEquals(1, journal.list(runtime, session).size)
        parent.retainApprovals(mapOf(runtime to RelayScope(listOf("session.read", "approval.decide"), listOf(UUID.randomUUID().toString()), emptyList())))
        assertTrue(journal.list(runtime, session).isEmpty()); assertEquals(1, parent.list(runtime, session).size)
        journal.create(original)
        parent.retainApprovals(mapOf(runtime to RelayScope(listOf("session.read"), listOf(workspace), emptyList())))
        assertTrue(journal.list(runtime, session).isEmpty()); assertEquals(1, parent.list(runtime, session).size)
    }

    @Test fun aFullSizeContextDoesNotLoseArgumentsToTheSmallerSignatureEnvelopeBudget(): Unit = runBlocking {
        val baseline = body("")
        val length = JsonDocument.MAX_BYTES - baseline.document.canonicalBytes().size - 8
        val body = ApprovalContext.from(JsonDocument.of(baseline.root.with("arguments" to jsonObject("command" to "x".repeat(length).json()))))
        val original = intent(body)
        assertTrue(original.bytes > JsonDocument.MAX_BYTES)
        val parent = open(); decisions(parent).create(original); parent.close()
        val restored = decisions(open()).list(runtime, session).single()
        assertEquals(original.digest, restored.intent.digest); assertEquals(length, restored.intent.context.root.obj("arguments").string("command").length)
    }

    @Test fun concurrentIdenticalSavesProduceOneImmutableRecord(): Unit = runBlocking {
        val journal = decisions(open()); val original = intent()
        coroutineScope { repeat(8) { launch(Dispatchers.IO) { journal.create(original) } } }
        assertEquals(1, journal.list(runtime, session).size)
        assertEquals(original.digest, journal.list(runtime, session).single().intent.digest)
        journal.close(); assertThrows(CommandDataException::class.java) { runBlocking { journal.list(runtime, session) } }
    }

    @Test fun capacityPressurePreservesUnconfirmedDecisionsAndEvictsOnlyFinalRecords(): Unit = runBlocking {
        val journal = decisions(open()); val original = intent(); journal.create(original); journal.beginAttempt(original.requestId)
        repeat(127) { journal.create(intent()) }
        val extraContext = body()
        val blocked = intent(extraContext)
        assertEquals("data.outbox_limit", assertThrows(CommandDataException::class.java) { runBlocking { journal.create(blocked) } }.code)
        assertEquals(128, journal.list(runtime, session).size)
        journal.record(original.requestId, status(original, "denied", false))
        val extra = intent(extraContext)
        journal.create(extra)
        val rows = journal.list(runtime, session)
        assertEquals(128, rows.size); assertTrue(rows.none { it.intent.requestId == original.requestId }); assertTrue(rows.any { it.intent.requestId == extra.requestId })
    }
}
