import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { calculateJwkThumbprint, CompactSign } from 'jose'
import { PersistentCommandJournal } from '../src/command-journal.js'
import { canonicalObject } from '../src/canonical.js'
import { approvalBinding, approvalKeyID, APPROVAL_JWS_TYPE, type ApprovalContext, type ApprovalDecision } from '../src/approval-contract.js'
import type { ApprovalAuthorization } from '../src/approval-authorization.js'
import type { RegisteredApprovalKey } from '../src/approval-signature.js'
import { injectJournalFull, journalDatabase, TEST_JOURNAL_BYTES } from './journal-capacity-fixture.js'

test('SQLite FULL cannot publish approval, return a guard permit or erase already consumed execution', async t => {
  for (const phase of ['register', 'decision', 'consume', 'settle'] as const) {
    await t.test(phase, async t => {
      const root = await mkdtemp(join(tmpdir(), 'dsh-approval-full-'))
      t.after(() => rm(root, { recursive: true, force: true }))
      const path = join(root, 'commands.sqlite'), runtime = randomUUID(), epoch = randomUUID(), now = Date.now()
      let parent = await PersistentCommandJournal.open(path, runtime, { maxDatabaseBytes: TEST_JOURNAL_BYTES })
      let ledger = parent.approvals(epoch, () => now)
      const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), jwk = pair.publicKey.export({ format: 'jwk' })
      const actor: RegisteredApprovalKey = { user_id: randomUUID(), device_id: randomUUID(), key_version: 1,
        approval_key_jkt: await calculateJwkThumbprint(jwk), public_jwk: jwk, active: true }
      const context: ApprovalContext = { domain: 'dsh-mobile-ustc/approval-context/v1', protocol_version: 1,
        host_id: randomUUID(), installation_id: randomUUID(), runtime_id: runtime, runtime_epoch: epoch, session_id: randomUUID(),
        approval_id: randomUUID(), execution_id: randomUUID(), dsh_session_id: 'capacity-session', call_id: randomUUID(), tool: 'protected',
        arguments: { text: 'PRIVATE_FULL_APPROVAL' }, workspace: { workspace_id: randomUUID(), root_sha256: 'a'.repeat(64) }, resources: [],
        nonce: randomBytes(32).toString('base64url'), policy_version: 1, required_assurance: { profile: 'fixture/step-up', max_auth_age_seconds: 300 },
        created_at: new Date(now).toISOString(), expires_at: new Date(now + 120_000).toISOString() }
      const claims: ApprovalDecision = { domain: 'dsh-mobile-ustc/approval-decision/v1', protocol_version: 1,
        host_id: context.host_id, installation_id: context.installation_id, runtime_id: runtime, runtime_epoch: epoch, session_id: context.session_id,
        approval_id: context.approval_id, execution_id: context.execution_id, binding_sha256: approvalBinding(context).sha256,
        decision: 'allow_once', user_id: actor.user_id, device_id: actor.device_id, key_version: 1, policy_version: 1, nonce: context.nonce,
        issued_at: new Date(now).toISOString(), expires_at: new Date(now + 25_000).toISOString() }
      const authority = (): ApprovalAuthorization => ({ lease_id: randomUUID(), action: 'approval.decide', role: 'owner', runtime_id: runtime, runtime_epoch: epoch,
        session_id: context.session_id, approval_id: context.approval_id, execution_id: context.execution_id, binding_sha256: claims.binding_sha256,
        policy_version: 1, user_id: actor.user_id, device_id: actor.device_id, key_version: 1, approval_key_jkt: actor.approval_key_jkt, grant_version: 1,
        assurance_profile: context.required_assurance.profile, authenticated_at: new Date(now - 1000).toISOString(),
        issued_at: new Date(now).toISOString(), expires_at: new Date(now + 2000).toISOString() })
      const compact = await new CompactSign(canonicalObject(claims)).setProtectedHeader({ alg: 'ES256', kid: approvalKeyID(actor.device_id, 1), typ: APPROVAL_JWS_TYPE }).sign(pair.privateKey)
      let restore: (() => void) | undefined
      let executed = 0
      try {
        if (phase !== 'register') ledger.register(context)
        if (phase === 'consume' || phase === 'settle') await ledger.decide(context.approval_id, compact, actor, authority)
        if (phase === 'settle') { ledger.consume(context.approval_id, context, authority); executed++ }
        restore = injectJournalFull(parent, 'approval_records', phase === 'register' ? 'INSERT' : 'UPDATE', phase === 'register' ? '1'
          : phase === 'decision' ? "NEW.state='approved'" : phase === 'consume' ? "NEW.state='consumed'" : "NEW.state='settled'")
        if (phase === 'decision') await assert.rejects(ledger.decide(context.approval_id, compact, actor, authority), /approval.storage_unavailable/)
        else assert.throws(() => {
          if (phase === 'register') ledger.register(context)
          else if (phase === 'consume') { ledger.consume(context.approval_id, context, authority); executed++ }
          else ledger.settle(context.approval_id, 'succeeded')
        }, /approval.storage_unavailable/)
        const raw = journalDatabase(parent).prepare('SELECT state,decision_sha256,outcome FROM approval_records WHERE approval_id=?').get(context.approval_id)
        assert.equal(raw?.state, phase === 'register' ? undefined : phase === 'decision' ? 'pending' : phase === 'consume' ? 'approved' : 'consumed')
        assert.equal(raw?.outcome ?? null, null)
        if (phase === 'decision') assert.equal(raw?.decision_sha256, null)
        assert.equal(executed, phase === 'settle' ? 1 : 0)
        assert.throws(() => ledger.consume(context.approval_id, context, authority), /approval.storage_unavailable/)
        restore(); restore = undefined
        parent.close()
        parent = await PersistentCommandJournal.open(path, runtime, { maxDatabaseBytes: TEST_JOURNAL_BYTES })
        ledger = parent.approvals(epoch, () => now)
        if (phase !== 'register') {
          assert.equal(ledger.get(context.approval_id).status.state, phase === 'settle' ? 'outcome_unknown' : 'invalidated')
          assert.throws(() => ledger.consume(context.approval_id, context, authority), /approval.stale/)
        }
        assert.equal(executed, phase === 'settle' ? 1 : 0, 'reopen replayed an old execution')
      } finally { restore?.(); parent.close() }
    })
  }
})
