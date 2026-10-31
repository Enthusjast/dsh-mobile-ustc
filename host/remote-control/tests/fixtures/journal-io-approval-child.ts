import assert from 'node:assert/strict'
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto'
import { lstat, readFile, realpath, unlink, writeFile } from 'node:fs/promises'
import { basename, join } from 'node:path'
import { CompactSign, calculateJwkThumbprint } from 'jose'
import { NativeObservations, NativeObservationWindow } from '../../src/native-observations.js'
import { PersistentCommandJournal } from '../../src/command-journal.js'
import { canonicalObject } from '../../src/canonical.js'
import { approvalBinding, approvalKeyID, APPROVAL_JWS_TYPE, type ApprovalContext, type ApprovalDecision } from '../../src/approval-contract.js'
import type { ApprovalAuthorization } from '../../src/approval-authorization.js'
import type { RegisteredApprovalKey } from '../../src/approval-signature.js'

const root = process.env.DSH_JOURNAL_IO_ROOT, phase = process.argv[2]
assert.ok(root && root.startsWith('/') && /^dsh-journal-io-[A-Za-z0-9_-]+$/.test(basename(root)) && ['decision-write', 'consume-sync'].includes(phase!))
assert.equal(await realpath(root), root)
const metadata = await lstat(root)
assert.equal(metadata.uid, process.getuid!()); assert.equal(metadata.mode & 0o777, 0o700)
const path = join(root, 'state', 'commands.sqlite'), flag = join(root, 'inject')
const runtime = randomUUID(), epoch = randomUUID(), now = Date.now()
const observations = new NativeObservations(), window = new NativeObservationWindow()
const dispose = observations.listen((operation, result, micros) => window.record(operation, result, micros), true)
let parent = await PersistentCommandJournal.open(path, runtime, { observations })
let ledger = parent.approvals(epoch, () => now)
const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), jwk = pair.publicKey.export({ format: 'jwk' })
const actor: RegisteredApprovalKey = { user_id: randomUUID(), device_id: randomUUID(), key_version: 1,
  approval_key_jkt: await calculateJwkThumbprint(jwk), public_jwk: jwk, active: true }
const context: ApprovalContext = { domain: 'dsh-mobile-ustc/approval-context/v1', protocol_version: 1,
  host_id: randomUUID(), installation_id: randomUUID(), runtime_id: runtime, runtime_epoch: epoch, session_id: randomUUID(),
  approval_id: randomUUID(), execution_id: randomUUID(), dsh_session_id: 'io-session', call_id: randomUUID(), tool: 'protected',
  arguments: { text: 'PRIVATE_IO_APPROVAL' }, workspace: { workspace_id: randomUUID(), root_sha256: 'a'.repeat(64) }, resources: [],
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
let executions = 0
try {
  ledger.register(context)
  if (phase === 'consume-sync') await ledger.decide(context.approval_id, compact, actor, authority)
  await writeFile(flag, phase === 'decision-write' ? 'write-wal' : 'sync-wal', { mode: 0o600 })
  if (phase === 'decision-write') await assert.rejects(ledger.decide(context.approval_id, compact, actor, authority), /approval.storage_unavailable/)
  else assert.throws(() => { ledger.consume(context.approval_id, context, authority); executions++ }, /approval.storage_unavailable/)
  assert.equal(executions, 0)
  await unlink(flag)
  const faults = await readFile(join(root, 'faults'), 'utf8')
  assert.ok(faults.length > 0 && faults.includes(phase === 'decision-write' ? 'w' : 's'))
  assert.throws(() => ledger.consume(context.approval_id, context, authority), /approval.storage_unavailable/)
  parent.close()
  parent = await PersistentCommandJournal.open(path, runtime)
  ledger = parent.approvals(epoch, () => now)
  const restored = ledger.get(context.approval_id).status.state
  assert.ok(restored === 'invalidated' || restored === 'outcome_unknown')
  assert.throws(() => ledger.consume(context.approval_id, context, authority), /approval.stale/)
  assert.equal(executions, 0)
  process.stdout.write(JSON.stringify({ phase, executions, restored, faults: faults.length, journalFailed: window.snapshot(randomUUID())!.series.filter(item => item.operation === 'journal_approval' && item.result === 'failed').reduce((sum, item) => sum + item.count, 0) }) + '\n')
} finally {
  dispose()
  await unlink(flag).catch(error => { if (error.code !== 'ENOENT') throw error })
  parent.close()
}
