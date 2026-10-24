import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Ajv2020 } from 'ajv/dist/2020.js'
import { ApprovalLeaseCache, verifyApprovalLease, type TrustedApprovalAuthority } from '../src/approval-lease.js'
import { PersistentCommandJournal } from '../src/command-journal.js'
import { type ApprovalContext, type ApprovalDecision } from '../src/approval-contract.js'

const fixture = JSON.parse(await readFile(new URL('../../../contracts/security/approval-leases.json', import.meta.url), 'utf8')) as {
  now: string; context: ApprovalContext; decision_jws: string; connection_id: string; lease: Record<string, unknown>; authorities: TrustedApprovalAuthority[];
  vectors: Array<{ name: string; compact: string; authority: number; invalid?: boolean; now?: string; decision_jws?: string; trusted_overrides?: Partial<TrustedApprovalAuthority> }>
}
const valid = fixture.vectors[0]!
const now = Date.parse(fixture.now)
const connection = { host_id: fixture.context.host_id, installation_id: fixture.context.installation_id, runtime_id: fixture.context.runtime_id,
  runtime_epoch: fixture.context.runtime_epoch, connection_id: fixture.connection_id }

test('Go/TypeScript authority vectors bind the accepted phone decision, registered key, scope and three-second connection lease', async () => {
  const schema = JSON.parse(await readFile(new URL('../../../contracts/security/approval.schema.json', import.meta.url), 'utf8'))
  const validate = new Ajv2020({ strict: true }).compile(schema)
  assert.equal(validate(fixture.lease), true)
  for (const vector of fixture.vectors) {
    const authority = { ...structuredClone(fixture.authorities[vector.authority]!), ...vector.trusted_overrides }
    const result = verifyApprovalLease(vector.compact, authority, fixture.context, vector.decision_jws ?? fixture.decision_jws, fixture.connection_id, Date.parse(vector.now ?? fixture.now))
    if (vector.invalid) await assert.rejects(result, /approval: invalid signed authorization/, vector.name)
    else {
      const verified = await result
      assert.equal(verified.lease.binding_sha256, fixture.lease.binding_sha256, vector.name)
      assert.equal(verified.key.active, true)
      assert.equal(verified.authorization.role, 'owner')
      assert.equal(validate(verified.lease), true)
    }
  }
})

test('untrusted anchors, changed actual execution contexts and replaced host connections cannot verify a lease', async () => {
  for (const field of ['host_id', 'installation_id', 'runtime_id', 'runtime_epoch', 'session_id', 'approval_id', 'execution_id', 'arguments', 'policy_version', 'required_assurance'] as const) {
    const context = structuredClone(fixture.context)
    if (field === 'arguments') context.arguments = { command: 'changed command' }
    else if (field === 'policy_version') context.policy_version++
    else if (field === 'required_assurance') context.required_assurance.max_auth_age_seconds--
    else context[field] = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'
    await assert.rejects(verifyApprovalLease(valid.compact, fixture.authorities[0]!, context, fixture.decision_jws, fixture.connection_id, now), /invalid signed authorization/, field)
  }
  for (const authority of [
    { ...fixture.authorities[0]!, public_jwk: { ...fixture.authorities[0]!.public_jwk, d: 'private' } },
    { ...fixture.authorities[0]!, public_jwk: { ...fixture.authorities[0]!.public_jwk, jku: 'https://attacker.example/key' } },
    { ...fixture.authorities[0]!, key_id: 'dsh-approval-authority/unknown' },
  ]) await assert.rejects(verifyApprovalLease(valid.compact, authority, fixture.context, fixture.decision_jws, fixture.connection_id, now), /invalid signed authorization/)
  await assert.rejects(verifyApprovalLease(valid.compact, fixture.authorities[0]!, fixture.context, fixture.decision_jws, 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', now), /invalid signed authorization/)
})

test('verified lease cache supplies synchronous guard evidence, copies caller values and expires without refreshing itself', async () => {
  let time = now
  const anchors = structuredClone(fixture.authorities)
  const cache = new ApprovalLeaseCache(connection, anchors, () => time)
  anchors[0]!.active = false
  anchors[0]!.public_jwk.x = 'A'.repeat(43)
  const key = await cache.admit(fixture.context, fixture.decision_jws, valid.compact)
  const verified = await verifyApprovalLease(valid.compact, fixture.authorities[0]!, fixture.context, fixture.decision_jws, fixture.connection_id, time)
  key.active = false
  const evidence = cache.authorization(fixture.context, verified.decision)
  assert.equal(evidence?.grant_version, 4)
  evidence!.role = 'owner'
  evidence!.grant_version = 100
  assert.equal(cache.authorization(fixture.context, verified.decision)?.grant_version, 4)
  const changedDecision = structuredClone(verified.decision)
  changedDecision.decision = 'reject'
  assert.equal(cache.authorization(fixture.context, changedDecision), undefined)
  const changedContext = structuredClone(fixture.context)
  changedContext.arguments = { command: 'changed' }
  assert.equal(cache.authorization(changedContext, verified.decision), undefined)
  time = now + 2999
  assert.ok(cache.authorization(fixture.context, verified.decision))
  time++
  assert.equal(cache.authorization(fixture.context, verified.decision), undefined)
  await assert.rejects(cache.admit(fixture.context, fixture.decision_jws, valid.compact), /invalid signed authorization/)
  cache.close()
})

test('closing, revoking or rolling back the clock destroys guard authority, including in-flight verification', async () => {
  const verified = await verifyApprovalLease(valid.compact, fixture.authorities[0]!, fixture.context, fixture.decision_jws, fixture.connection_id, now)
  for (const mode of ['close', 'clock', 'in-flight', 'replacement'] as const) {
    let time = now
    const cache = new ApprovalLeaseCache(mode === 'replacement' ? { ...connection, connection_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' } : connection, fixture.authorities, () => time)
    if (mode === 'replacement') { await assert.rejects(cache.admit(fixture.context, fixture.decision_jws, valid.compact)); continue }
    const admission = cache.admit(fixture.context, fixture.decision_jws, valid.compact)
    if (mode === 'in-flight') { cache.close(); await assert.rejects(admission); continue }
    await admission
    if (mode === 'close') cache.close()
    else time--
    assert.equal(cache.authorization(fixture.context, verified.decision), undefined, mode)
    time = now
    await assert.rejects(cache.admit(fixture.context, fixture.decision_jws, valid.compact), /invalid signed authorization/)
  }
})

test('lease verification bounds in-flight work even for concurrent retries of one approval', async () => {
  const cache = new ApprovalLeaseCache(connection, fixture.authorities, () => now)
  const work = Array.from({ length: 64 }, () => cache.admit(fixture.context, fixture.decision_jws, valid.compact))
  await assert.rejects(cache.admit(fixture.context, fixture.decision_jws, valid.compact), /invalid signed authorization/)
  await Promise.all(work)
  cache.close()
})

test('actor invalidations remove only matching authority and never lower a processed grant floor', async () => {
  const verified = await verifyApprovalLease(valid.compact, fixture.authorities[0]!, fixture.context, fixture.decision_jws, fixture.connection_id, now)
  const cache = new ApprovalLeaseCache(connection, fixture.authorities, () => now)
  await cache.admit(fixture.context, fixture.decision_jws, valid.compact)
  assert.deepEqual(cache.invalidateDevice('dddddddd-dddd-4ddd-8ddd-dddddddddddd'), [])
  assert.deepEqual(cache.invalidateGrant('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 99), [])
  assert.deepEqual(cache.invalidateGrant(verified.key.user_id, verified.lease.grant_version), [])
  assert.ok(cache.authorization(fixture.context, verified.decision))
  assert.deepEqual(cache.invalidateGrant(verified.key.user_id, verified.lease.grant_version + 1), [fixture.context.approval_id])
  assert.equal(cache.authorization(fixture.context, verified.decision), undefined)
  cache.invalidateGrant(verified.key.user_id, verified.lease.grant_version)
  await assert.rejects(cache.admit(fixture.context, fixture.decision_jws, valid.compact), /authorization revoked/)
  cache.close()
})

test('a processed device or grant invalidation fences even a signature verification already in flight', async () => {
  const verified = await verifyApprovalLease(valid.compact, fixture.authorities[0]!, fixture.context, fixture.decision_jws, fixture.connection_id, now)
  for (const kind of ['device', 'grant'] as const) {
    const cache = new ApprovalLeaseCache(connection, fixture.authorities, () => now)
    const pending = cache.admit(fixture.context, fixture.decision_jws, valid.compact)
    if (kind === 'device') cache.invalidateDevice(verified.key.device_id)
    else cache.invalidateGrant(verified.key.user_id, verified.lease.grant_version + 1)
    await assert.rejects(pending, /authorization revoked/)
    await assert.rejects(cache.admit(fixture.context, fixture.decision_jws, valid.compact), /authorization revoked/)
    cache.close()
  }
})

test('a signed lease enables one durable guard consumption and cannot revive it after disconnect or restart', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-signed-approval-lease-'))
  let parent: PersistentCommandJournal | undefined
  try {
    parent = await PersistentCommandJournal.open(join(root, 'commands.sqlite'), fixture.context.runtime_id)
    const journal = parent.approvals(fixture.context.runtime_epoch, () => now)
    const cache = new ApprovalLeaseCache(connection, fixture.authorities, () => now)
    journal.register(fixture.context)
    const key = await cache.admit(fixture.context, fixture.decision_jws, valid.compact)
    const authorize = (context: ApprovalContext, decision: ApprovalDecision) => cache.authorization(context, decision)
    assert.equal((await journal.decide(fixture.context.approval_id, fixture.decision_jws, key, authorize)).state, 'approved')
    assert.equal(journal.consume(fixture.context.approval_id, fixture.context, authorize).state, 'consumed')
    assert.throws(() => journal.consume(fixture.context.approval_id, fixture.context, authorize), /approval.stale/)
    cache.close()
    journal.close()
    await parent.close()
    parent = await PersistentCommandJournal.open(join(root, 'commands.sqlite'), fixture.context.runtime_id)
    const recovered = parent.approvals(fixture.context.runtime_epoch, () => now)
    assert.equal(recovered.get(fixture.context.approval_id).status.state, 'outcome_unknown')
    assert.throws(() => recovered.consume(fixture.context.approval_id, fixture.context, authorize), /approval.stale/)
    recovered.close()
  } finally { await parent?.close(); await rm(root, { recursive: true, force: true }) }
})
