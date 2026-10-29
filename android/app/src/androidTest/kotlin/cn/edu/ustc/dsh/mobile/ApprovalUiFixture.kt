package cn.edu.ustc.dsh.mobile

import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.*
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import java.security.Signature
import java.util.UUID

internal class ApprovalUiFixture(
    text: String = "printf ui-fixture",
    arguments: JsonValue = jsonObject("command" to text.json()),
) {
    val host = UUID.randomUUID().toString()
    val runtime = UUID.randomUUID().toString()
    val session = UUID.randomUUID().toString()
    private val epoch = UUID.randomUUID().toString()
    private val approval = UUID.randomUUID().toString()
    private val execution = UUID.randomUUID().toString()
    private val workspace = UUID.randomUUID().toString()
    private val owner = LocalDataOwner(UUID.randomUUID().toString(), UUID.randomUUID().toString(), "a".repeat(64), UUID.randomUUID().toString(), UUID.randomUUID().toString())
    val body: ApprovalContext = run {
        val now = System.currentTimeMillis()
        ApprovalContext.from(JsonDocument.of(jsonObject("domain" to APPROVAL_CONTEXT_DOMAIN.json(), "protocol_version" to 1L.json(), "host_id" to host.json(),
            "installation_id" to UUID.randomUUID().toString().json(), "runtime_id" to runtime.json(), "runtime_epoch" to epoch.json(), "session_id" to session.json(),
            "dsh_session_id" to "native-ui".json(), "approval_id" to approval.json(), "execution_id" to execution.json(), "call_id" to "ui-call".json(),
            "tool" to "bash".json(), "arguments" to arguments, "workspace" to jsonObject("workspace_id" to workspace.json(), "root_sha256" to "b".repeat(64).json()),
            "resources" to JsonArray(emptyList()), "nonce" to Contract.base64url(ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }).json(), "policy_version" to 7L.json(),
            "required_assurance" to jsonObject("profile" to "fixture/step-up".json(), "max_auth_age_seconds" to 60L.json()),
            "created_at" to Contract.timestamp(now).json(), "expires_at" to Contract.timestamp(now + 180_000).json())))
    }
    val status = ApprovalStatus.parse(jsonObject("approval_id" to approval.json(), "runtime_id" to runtime.json(), "runtime_epoch" to epoch.json(), "session_id" to session.json(),
        "execution_id" to execution.json(), "binding_sha256" to body.bindingSha256.json(), "expires_at" to Contract.timestamp(body.expiresAt).json(), "state" to "pending".json()))
    val handle = ApprovalReviewHandle(UUID.randomUUID().toString(), runtime, epoch, session, approval, execution, body.bindingSha256, UUID.randomUUID().toString())
    fun original(choice: ApprovalChoice = ApprovalChoice.ALLOW_ONCE): PendingApprovalDecision {
        val key = ECKeyGenerator(Curve.P_256).generate()
        val registered = RegisteredApprovalKey.parse(jsonObject("user_id" to owner.userId.json(), "device_id" to owner.deviceId.json(), "key_version" to 1L.json(), "active" to JsonBoolean(true),
            "public_jwk" to JsonDocument.parse(key.toPublicJWK().toJSONString()).root, "approval_key_jkt" to key.computeThumbprint().toString().json()))
        val now = System.currentTimeMillis(); val prepared = ApprovalSignatures.prepare(body, choice, registered, now)
        val der = Signature.getInstance("SHA256withECDSA").run { initSign(key.toECPrivateKey()); update(prepared.signingInput()); sign() }
        val signed = prepared.finishDerSignature(der, now)
        val intent = ApprovalDecisionIntent.create(UUID.randomUUID().toString(), owner, registered, body, signed, now)
        return ApprovalDecisionEvolution.begin(ApprovalDecisionEvolution.created(intent, now), now)
    }
    fun state(
        role: String = "owner",
        live: Boolean = true,
        records: List<PendingApprovalDecision> = emptyList(),
        error: String? = null,
        reviewHandle: ApprovalReviewHandle = handle,
        connected: Boolean = true,
        contentReady: Boolean = live,
        canReview: Boolean = true,
        remainingMillis: Long = 60_000,
    ): HomeState {
        val authority = RuntimeDirectoryEntry.parse(jsonObject("id" to runtime.json(), "host_id" to host.json(), "protocol_version" to 1L.json(),
            "access" to jsonObject("role" to role.json(), "grant_version" to 7L.json(), "scope" to RelayScope(listOf("session.list", "session.read", "approval.decide", "grant.manage"), emptyList(), listOf(session)).json())))
        val view = SessionApprovalState(if (live) listOf(PresentedApproval(status, remainingMillis, canReview, reviewHandle, body)) else emptyList(), loaded = true)
        return HomeState(HomePhase.READY, selectedRuntimeId = runtime, selectedSessionId = session,
            runtimes = listOf(RuntimeRow(runtime, host, "0.2.1-rc.2", "夹具电脑", authority)), reviewingApprovalId = approval,
            approvals = ApprovalClientState(view, records, supported = true, connected = connected, contentReady = contentReady), approvalError = error)
    }
}
