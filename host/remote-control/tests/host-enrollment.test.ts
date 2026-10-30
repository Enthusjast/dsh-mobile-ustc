import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createCipheriv, createDecipheriv, createHash, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from 'node:crypto'
import { once } from 'node:events'
import { writeFileSync } from 'node:fs'
import { lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer, type ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { inspect } from 'node:util'
import { pathToFileURL } from 'node:url'
import { canonicalObject } from '../src/canonical.js'
import { HostRestCredentialProvider } from '../src/host-credentials.js'
import { HostEnrolledRuntimeError, verifyEnrolledHostRuntime } from '../src/host-enrolled-runtime.js'
import { captureEnrollmentBinding, enrollmentRecoveryBinding, HostEnrollmentClient, type HostEnrollmentBinding, type HostEnrollmentOptions } from '../src/host-enrollment.js'
import { HostEnrollmentRecoveryError, HostEnrollmentRecoveryStore, seal } from '../src/host-enrollment-recovery.js'
import { HostEnrollmentBindingError, HostEnrollmentBindingStore } from '../src/host-enrollment-binding.js'
import { HostLocalEnrollmentError, runHostEnrollmentOnTerminal } from '../src/host-local-enrollment.js'
import { HostTerminalEnrollmentWorkflow, HostTerminalEnrollmentWorkflowError } from '../src/host-enrollment-workflow.js'
import { HostEnrollmentError } from '../src/host-enrollment-transport.js'
import type { HostResourceAccess } from '../src/host-credentials.js'
import { protectorFrom, type JournalKeyProtector } from '../src/journal-key-protection.js'
import { createEnrolledRemoteControlPlugin } from '../src/index.js'
import { host as dshHost } from './harness.js'

const expected = { issuer: 'https://id.example.edu', subject: 'fixture-owner', audience: 'urn:fixture-host', clientId: 'fixture-host' }
const organization = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const host = '11111111-1111-4111-8111-111111111111'
const installation = '22222222-2222-4222-8222-222222222222'
const runtime = '33333333-3333-4333-8333-333333333333'
const enrollment = '44444444-4444-4444-8444-444444444444'
const user = '55555555-5555-4555-8555-555555555555'
const alternateUser = '66666666-6666-4666-8666-666666666666'
const token = 'PRIVATE_FIXTURE_RESOURCE_TOKEN'
const hash = (value: string) => createHash('sha256').update(value).digest('base64url')
const part = (value: string) => JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) as any
const nonce = () => randomBytes(32).toString('base64url')
const valid = (code: string) => (cause: unknown) => cause instanceof HostEnrollmentError && cause.code === `host.enrollment.${code}`
const bindingError = (code: string) => (cause: unknown) => cause instanceof HostEnrollmentBindingError && cause.code === `host.enrollment_binding.${code}`
const workflowError = (code: string) => (cause: unknown) => cause instanceof HostTerminalEnrollmentWorkflowError && cause.code === `host.terminal_enrollment.${code}`
const runtimeError = (code: string) => (cause: unknown) => cause instanceof HostEnrolledRuntimeError && cause.code === `host.enrolled_runtime.${code}`
const send = (response: ServerResponse, status: number, body: unknown, next: string) => {
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'dpop-nonce': next })
  response.end(JSON.stringify(body))
}

function recoveryProtector(master: Buffer): JournalKeyProtector {
  return { id: 'fixture-enrollment-recovery',
    async wrap(key, context) {
      const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', master, nonce)
      cipher.setAAD(context)
      return Buffer.concat([nonce, cipher.update(key), cipher.final(), cipher.getAuthTag()])
    },
    async unwrap(wrapped, context) {
      const bytes = Buffer.from(wrapped), decipher = createDecipheriv('aes-256-gcm', master, bytes.subarray(0, 12))
      decipher.setAAD(context); decipher.setAuthTag(bytes.subarray(44))
      return Buffer.concat([decipher.update(bytes.subarray(12, 44)), decipher.final()])
    } }
}

async function fixture(t: test.TestContext) {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const publicJwk = keys.publicKey.export({ format: 'jwk' }) as HostEnrollmentOptions['publicJwk']
  const thumbprint = hash(JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y }))
  const owner = new AbortController(), nonces = new Set<string>(), proofIDs = new Set<string>()
  const requests: Array<{ method: string; path: string; body: any; proof: any }> = []
  let origin = '', input: any, createdCount = 0, confirmedCount = 0, reviews = 0
  const expires = new Date(Date.now() + 300_000).toISOString()
  const state = { phoneConfirmed: false, approved: false, eligible: true, confirmedUser: user, subject: 'fixture-phone', organizationName: 'Fixture organization',
    dropCreate: false, holdCreate: false, redirectCreate: false, dropConfirm: false, dropReviewAt: 0, holdReview: false, denyReview: false, wrongReceipt: false,
    aliasOverride: undefined as string | undefined, dshOverride: undefined as string | undefined, appOverride: undefined as string | undefined,
    pluginOverride: undefined as string | undefined, protocolOverride: undefined as number | undefined,
    onCreate: undefined as undefined | (() => void), onReview: undefined as undefined | ((count: number) => void) }
  const server = createServer(async (request, response) => {
    try {
      assert.equal(request.headers.authorization, `DPoP ${token}`)
      assert.equal(request.headers.cookie, undefined)
      const compact = String(request.headers.dpop), [head, payload, signature] = compact.split('.')
      const header = part(head!), proof = part(payload!)
      assert.deepEqual(header, { alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
      assert.equal(verify('sha256', Buffer.from(`${head}.${payload}`), { key: keys.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature!, 'base64url')), true)
      assert.equal(proof.htm, request.method); assert.equal(proof.htu, origin + request.url); assert.equal(proof.ath, hash(token))
      assert.equal(proofIDs.has(proof.jti), false); proofIDs.add(proof.jti)
      const chunks: Buffer[] = []
      for await (const chunk of request) chunks.push(Buffer.from(chunk))
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : undefined
      requests.push({ method: request.method!, path: request.url!, body, proof })
      const next = nonce(); nonces.add(next)
      if (!proof.nonce || !nonces.delete(proof.nonce)) {
        response.setHeader('www-authenticate', 'DPoP error="use_dpop_nonce"')
        send(response, 401, { ok: false, error: { code: 'auth.proof_invalid' } }, next)
        return
      }
      const workspaces = (input?.workspace_refs ?? []).map((reference: string, index: number) => ({ reference,
        workspace_id: index === 0 ? '77777777-7777-4777-8777-777777777777' : '88888888-8888-4888-8888-888888888888' }))
      if (request.method === 'POST' && request.url === '/v1/enrollments') {
        if (state.redirectCreate) { response.writeHead(307, { location: `${origin}/redirect-target`, 'cache-control': 'no-store' }); response.end(); return }
        if (input && JSON.stringify(input) !== JSON.stringify(body)) { send(response, 409, { ok: false, error: { code: 'enrollment.request_conflict' } }, next); return }
        if (!input) { input = body; createdCount++ }
        const mapped = input.workspace_refs.map((reference: string, index: number) => ({ reference,
          workspace_id: index === 0 ? '77777777-7777-4777-8777-777777777777' : '88888888-8888-4888-8888-888888888888' }))
        if (state.dropCreate) { state.dropCreate = false; response.destroy(); return }
        if (state.holdCreate) { state.holdCreate = false; state.onCreate?.(); return }
        send(response, 201, { ok: true, data: { enrollment_id: enrollment, request_id: state.wrongReceipt ? randomUUID() : input.request_id,
          host_id: host, installation_id: installation, runtime_id: runtime, profile_ref: input.profile_ref,
          state: state.approved ? 'approved' : state.phoneConfirmed ? 'user_confirmed' : 'pending', expires_at: expires, workspaces: mapped } }, next)
      } else if (request.method === 'GET' && request.url === `/v1/enrollments/${enrollment}/host-review`) {
        assert.ok(input); reviews++; state.onReview?.(reviews)
        if (reviews === state.dropReviewAt) { response.destroy(); return }
        if (state.holdReview) { state.holdReview = false; return }
        if (state.denyReview) { send(response, 403, { ok: false, error: { code: 'access.denied' } }, next); return }
        send(response, 200, { ok: true, data: { enrollment: { enrollment_id: enrollment, request_id: input.request_id,
          organization_id: input.organization_id, organization_name: state.organizationName, host_id: host, host_alias: state.aliasOverride ?? input.alias,
          installation_id: installation, installation_key_jkt: thumbprint, runtime_id: runtime, profile_ref: input.profile_ref,
          dsh_version: state.dshOverride ?? input.dsh_version, application_version: state.appOverride ?? input.application_version, plugin_version: state.pluginOverride ?? input.plugin_version,
          protocol_version: state.protocolOverride ?? input.protocol_version, state: state.approved ? 'approved' : state.phoneConfirmed ? 'user_confirmed' : 'pending',
          expires_at: expires, host_confirmed: state.approved, user_confirmed: state.phoneConfirmed, user_confirmed_by_me: false, workspaces },
        confirmed_user: state.phoneConfirmed ? { user_id: state.confirmedUser, issuer: expected.issuer, subject: state.subject, eligible: state.eligible } : null } }, next)
      } else if (request.method === 'POST' && request.url === `/v1/enrollments/${enrollment}/host-confirm`) {
        assert.ok(input)
        if (!state.phoneConfirmed || !state.eligible || body.code !== input.code || body.confirmed_user_id !== state.confirmedUser) {
          send(response, 403, { ok: false, error: { code: 'access.denied' } }, next); return
        }
        if (!state.approved) { state.approved = true; confirmedCount++ }
        if (state.dropConfirm) { state.dropConfirm = false; response.destroy(); return }
        send(response, 200, { ok: true, data: { enrollment_id: enrollment, host_id: host, runtime_id: runtime,
          state: 'approved', expires_at: expires, host_confirmed: true, user_confirmed: true } }, next)
      } else { t.assert.fail('unexpected enrollment route'); response.destroy() }
    } catch (cause) { t.assert.fail(cause instanceof Error ? cause.message : 'fixture protocol failure'); response.destroy() }
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address(); assert.ok(address && typeof address === 'object')
  origin = `http://127.0.0.1:${address.port}`
  const account: HostResourceAccess = { ...expected, token, tokenType: 'DPoP', proofKeyThumbprint: thumbprint, expiresAt: Date.now() + 300_000, scopes: ['remote.access'] }
  const options: HostEnrollmentOptions = { origin, identity: expected, publicJwk, requiredScopes: ['remote.access'], allowLoopbackHttp: true,
    signer: { sign(input) { return sign('sha256', Buffer.from(input), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }) } },
    account: { signal: owner.signal, async acquire() { return account } } }
  const client = new HostEnrollmentClient(options)
  t.after(async () => { client.close(); owner.abort(); server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())) })
  const prepare = () => client.prepare({ organizationId: organization, alias: 'Fixture host', profileRef: 'profile', dshVersion: '0.2.1-rc.2',
    applicationVersion: 'fixture', pluginVersion: '0.0.1', protocolVersion: 1, workspaceRefs: ['z-workspace', 'a-workspace'] })
  return { client, options, account, privateKey: keys.privateKey, owner, requests, prepare, state, resetEnrollment: () => { input = undefined; state.phoneConfirmed = false; state.approved = false },
    counts: () => ({ createdCount, confirmedCount, reviews }) }
}

test('host enrollment restores a private attempt, validates the peer and requires explicit local review', async t => {
  const f = await fixture(t)
  const refs = ['z-workspace', 'a-workspace']
  const first = f.client.prepare({ organizationId: organization, alias: 'Fixture host', profileRef: 'profile', dshVersion: '0.2.1-rc.2',
    applicationVersion: 'fixture', pluginVersion: '0.0.1', protocolVersion: 1, workspaceRefs: refs })
  assert.deepEqual(refs, ['z-workspace', 'a-workspace']); refs[0] = 'changed-after-prepare'
  const code = first.code, recovery = first.exportRecovery()
  assert.equal([String(first), inspect(first), JSON.stringify(first)].some(value => value.includes(code)), false)
  const attempt = f.client.restore(recovery); recovery.fill(0); first.destroy()
  assert.equal(attempt.code, code)
  const receipt = await f.client.create(attempt, AbortSignal.timeout(5_000))
  assert.equal(receipt.details.request_id, attempt.requestId)
  assert.deepEqual(receipt.details.workspaces.map(item => item.reference), ['a-workspace', 'z-workspace'])
  assert.equal((await f.client.review(attempt, receipt, AbortSignal.timeout(5_000))).confirmed_user, null)
  f.state.phoneConfirmed = true
  let approvals = 0
  const result = await f.client.confirm(attempt, receipt, (review, signal) => {
    approvals++; assert.equal(signal.aborted, false); assert.equal(review.confirmed_user?.user_id, user)
    assert.equal(Object.isFrozen(review), true); assert.equal(Object.isFrozen(review.enrollment), true)
    assert.equal(Object.isFrozen(review.enrollment.workspaces), true)
    return true
  }, AbortSignal.timeout(5_000))
  assert.equal(result.state, 'approved'); assert.equal(approvals, 1)
  assert.equal(f.counts().createdCount, 1); assert.equal(f.counts().confirmedCount, 1)
  assert.equal(f.requests.filter(item => item.path.endsWith('/host-confirm') && item.proof.nonce).length, 1)
})

test('host enrollment refuses absent, declined, changed or cancelled local approval', async t => {
  const f = await fixture(t), attempt = f.prepare(), receipt = await f.client.create(attempt, AbortSignal.timeout(5_000))
  let approvals = 0
  await assert.rejects(f.client.confirm(attempt, receipt, () => { approvals++; return true }, AbortSignal.timeout(5_000)), valid('review_required'))
  assert.equal(approvals, 0)
  f.state.phoneConfirmed = true
  await assert.rejects(f.client.confirm(attempt, receipt, () => false, AbortSignal.timeout(5_000)), valid('declined'))
  await assert.rejects(f.client.confirm(attempt, receipt, () => { f.state.confirmedUser = alternateUser; f.state.subject = 'other-user'; return true }, AbortSignal.timeout(5_000)), valid('identity_changed'))
  f.state.confirmedUser = user; f.state.subject = 'fixture-phone'
  await assert.rejects(f.client.confirm(attempt, receipt, () => { f.state.organizationName = 'Changed organization'; return true }, AbortSignal.timeout(5_000)), valid('identity_changed'))
  f.state.organizationName = 'Fixture organization'
  await assert.rejects(f.client.confirm(attempt, receipt, () => { f.state.eligible = false; return true }, AbortSignal.timeout(5_000)), valid('review_required'))
  f.state.eligible = true
  const cancel = new AbortController()
  let entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  const operation = f.client.confirm(attempt, receipt, () => { entered(); return new Promise<boolean>(() => {}) }, cancel.signal)
  await started; cancel.abort()
  await assert.rejects(operation, valid('cancelled'))
  assert.equal(f.counts().confirmedCount, 0)
  assert.equal(f.requests.some(item => item.path.endsWith('/host-confirm')), false)
})

test('unknown create and confirmation outcomes require explicit reconciliation', async t => {
  const f = await fixture(t), attempt = f.prepare()
  f.state.dropCreate = true
  await assert.rejects(f.client.create(attempt, AbortSignal.timeout(5_000)), valid('outcome_unknown'))
  const receipt = await f.client.create(attempt, AbortSignal.timeout(5_000))
  assert.equal(f.counts().createdCount, 1)
  const creates = f.requests.filter(item => item.path === '/v1/enrollments' && item.proof.nonce)
  assert.equal(creates.length, 2); assert.deepEqual(creates[0]!.body, creates[1]!.body)
  f.state.phoneConfirmed = true; f.state.dropConfirm = true
  await assert.rejects(f.client.confirm(attempt, receipt, () => true, AbortSignal.timeout(5_000)), valid('outcome_unknown'))
  assert.equal(f.counts().confirmedCount, 1)
  assert.equal((await f.client.review(attempt, receipt, AbortSignal.timeout(5_000))).enrollment.state, 'approved')
  await assert.rejects(f.client.confirm(attempt, receipt, () => true, AbortSignal.timeout(5_000)), valid('review_required'))
  assert.equal(f.counts().confirmedCount, 1)
})

test('protected recovery reconciles a lost create response without a second enrollment', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-lost-create-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const store = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector: recoveryProtector(master) })
  t.after(() => store.close())
  const attempt = f.prepare(), requestId = attempt.requestId
  f.state.dropCreate = true
  await assert.rejects(store.create(attempt, AbortSignal.timeout(5_000)), valid('outcome_unknown'))
  attempt.destroy()
  const recovered = await store.load(AbortSignal.timeout(5_000))
  assert.ok(recovered); assert.equal(recovered.requestId, requestId)
  const receipt = await store.create(recovered, AbortSignal.timeout(5_000))
  assert.equal(receipt.details.request_id, requestId); assert.equal(f.counts().createdCount, 1)
  assert.equal(await store.remove(recovered, AbortSignal.timeout(5_000)), true)
  recovered.destroy()
})

test('protected local confirmation keeps recovery busy until the prompt ends', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-confirm-lock-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const store = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector: recoveryProtector(master) })
  t.after(() => store.close())
  const attempt = f.prepare(), receipt = await store.create(attempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true
  const controller = new AbortController()
  let entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  const confirming = store.confirm(attempt, receipt, () => { entered(); return new Promise<boolean>(() => {}) }, controller.signal)
  await started
  await assert.rejects(store.remove(attempt, AbortSignal.timeout(1_000)), error =>
    error instanceof Error && 'code' in error && error.code === 'host.enrollment_recovery.busy')
  controller.abort(); await assert.rejects(confirming, valid('cancelled'))
  await assert.rejects(store.confirm(attempt, receipt, () => false, AbortSignal.timeout(5_000)), valid('declined'))
  const recovered = await store.load(AbortSignal.timeout(5_000))
  assert.equal(recovered?.requestId, attempt.requestId); recovered?.destroy()
})

test('protected recovery reconciles a lost host-confirmation response after restart', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-lost-confirm-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const path = join(root, 'pending.bin'), protector = recoveryProtector(master)
  const store = new HostEnrollmentRecoveryStore({ path, client: f.client, protector })
  const attempt = f.prepare(), receipt = await store.create(attempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true; f.state.dropConfirm = true
  await assert.rejects(store.confirm(attempt, receipt, () => true, AbortSignal.timeout(5_000)), valid('outcome_unknown'))
  store.close(); f.client.close(); attempt.destroy()
  const client = new HostEnrollmentClient(f.options), reopened = new HostEnrollmentRecoveryStore({ path, client, protector })
  t.after(() => { reopened.close(); client.close() })
  const recovered = await reopened.load(AbortSignal.timeout(5_000))
  assert.ok(recovered)
  const historical = await reopened.create(recovered, AbortSignal.timeout(5_000))
  assert.equal((await client.review(recovered, historical, AbortSignal.timeout(5_000))).enrollment.state, 'approved')
  assert.equal(f.counts().createdCount, 1); assert.equal(f.counts().confirmedCount, 1)
  assert.equal(await reopened.remove(recovered, AbortSignal.timeout(5_000)), true)
  recovered.destroy()
})

test('binding pointer survives confirmation, recovery cleanup and attempt expiry', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-binding-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), pendingPath = join(root, 'pending.bin'), bindingPath = join(root, 'binding.bin')
  const recovery = new HostEnrollmentRecoveryStore({ path: pendingPath, client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: bindingPath, client: f.client, protector })
  t.after(() => { recovery.close(); binding.close() })
  const attempt = f.prepare(), receipt = await recovery.create(attempt, AbortSignal.timeout(5_000))
  const captured = JSON.stringify(captureEnrollmentBinding(f.client, attempt, receipt))
  assert.equal(captured.includes(attempt.code), false); assert.equal(captured.includes('fixture-phone'), false)
  await binding.reserve(attempt, receipt, AbortSignal.timeout(5_000))
  const before = await readFile(bindingPath)
  await binding.reserve(attempt, receipt, AbortSignal.timeout(5_000))
  assert.deepEqual(await readFile(bindingPath), before)
  assert.equal((await lstat(bindingPath)).mode & 0o777, 0o600)
  assert.equal(before.includes(Buffer.from(attempt.code)), false)
  assert.equal(before.includes(Buffer.from('fixture-phone')), false)
  await assert.rejects(binding.open(AbortSignal.timeout(5_000)), valid('review_required'))
  f.state.phoneConfirmed = true
  const result = await binding.confirm(recovery, attempt, receipt, async review => {
    assert.equal(review.confirmed_user?.user_id, user)
    assert.deepEqual(await readFile(bindingPath), before)
    return true
  }, AbortSignal.timeout(5_000))
  assert.equal(result.requestId, attempt.requestId); assert.equal(result.enrollmentId, enrollment)
  assert.equal(result.organizationId, organization); assert.equal(result.hostId, host)
  assert.equal(result.installationId, installation); assert.equal(result.runtimeId, runtime)
  assert.equal(result.profileRef, 'profile'); assert.equal(result.workspaces.length, 2)
  assert.equal(Object.isFrozen(result), true); assert.equal(Object.isFrozen(result.workspaces), true)
  assert.equal(await recovery.remove(attempt, AbortSignal.timeout(5_000)), true)
  attempt.destroy(); binding.close(); recovery.close(); f.client.close()
  const client = new HostEnrollmentClient(f.options), reopened = new HostEnrollmentBindingStore({ path: bindingPath, client, protector })
  t.after(() => { reopened.close(); client.close() })
  const now = Date.now
  try {
    Date.now = () => now() + 601_000
    f.account.expiresAt = Date.now() + 300_000
    f.state.aliasOverride = 'Renamed host'; f.state.dshOverride = '0.2.2'; f.state.appOverride = 'new-app'; f.state.pluginOverride = 'new-plugin'; f.state.protocolOverride = 2
    assert.deepEqual(await reopened.open(AbortSignal.timeout(5_000)), result)
    f.state.denyReview = true
    await assert.rejects(reopened.open(AbortSignal.timeout(5_000)), valid('denied'))
    assert.deepEqual(await readFile(bindingPath), before)
    f.state.denyReview = false
  } finally { Date.now = now }
})

test('terminal enrollment requires durable recovery before displaying a pairing code', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-terminal-recovery-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), attempt = f.prepare()
  // Exercise callers that created the attempt without the recovery store.
  const receipt = await f.client.create(attempt, AbortSignal.timeout(5_000))
  await writeFile(join(root, 'not-a-directory'), 'fixture')
  const missing = new HostEnrollmentRecoveryStore({ path: join(root, 'not-a-directory', 'pending.bin'), client: f.client, protector })
  const recovery = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: join(root, 'binding.bin'), client: f.client, protector })
  t.after(() => { missing.close(); recovery.close(); binding.close(); attempt.destroy() })
  await assert.rejects(runHostEnrollmentOnTerminal({ client: f.client, recovery: missing, binding, attempt, receipt,
    signal: AbortSignal.timeout(5_000) }), (error: unknown) => error instanceof HostEnrollmentRecoveryError && error.code === 'host.enrollment_recovery.unavailable')
  assert.equal(f.counts().reviews, 0)

  const controller = new AbortController()
  const cancellingRecovery = { async save(value: typeof attempt, signal: AbortSignal) {
    await recovery.save(value, signal); controller.abort()
  } } as unknown as HostEnrollmentRecoveryStore
  await assert.rejects(runHostEnrollmentOnTerminal({ client: f.client, recovery: cancellingRecovery, binding, attempt, receipt,
    signal: controller.signal }), (error: unknown) => error instanceof HostLocalEnrollmentError && error.code === 'host.local_enrollment.cancelled')
  const recovered = await recovery.load(AbortSignal.timeout(5_000))
  assert.ok(recovered); assert.equal(recovered.requestId, attempt.requestId); assert.equal(recovered.code, attempt.code)
  recovered.destroy(); assert.equal(f.counts().reviews, 0)
})

test('terminal enrollment reconciles only the exact request and enrollment', async t => {
  const f = await fixture(t), attempt = f.prepare()
  f.state.phoneConfirmed = true; f.state.approved = true
  const receipt = await f.client.create(attempt, AbortSignal.timeout(5_000))
  const saved = captureEnrollmentBinding(f.client, attempt, receipt)
  const matching: HostEnrollmentBinding = { requestId: saved.request_id, enrollmentId: saved.enrollment_id,
    organizationId: saved.organization_id, hostId: saved.host_id, installationId: saved.installation_id,
    installationKeyThumbprint: saved.installation_key_jkt, runtimeId: saved.runtime_id, profileRef: saved.profile_ref,
    workspaces: saved.workspaces.map(item => ({ reference: item.reference, workspaceId: item.workspace_id })) }
  const recovery = {} as HostEnrollmentRecoveryStore
  const run = async (result: HostEnrollmentBinding) => {
    const binding = { async open() { return result } } as unknown as HostEnrollmentBindingStore
    return await runHostEnrollmentOnTerminal({ client: f.client, recovery, binding, attempt, receipt, signal: AbortSignal.timeout(5_000) })
  }
  assert.equal(await run(matching), matching)
  for (const field of ['requestId', 'enrollmentId'] as const) {
    await assert.rejects(run({ ...matching, [field]: randomUUID() }),
      (error: unknown) => error instanceof HostLocalEnrollmentError && error.code === 'host.local_enrollment.recovery_required')
  }
  attempt.destroy()
})

test('terminal workflow restores the same protected request after an uncertain create and rejects overlap', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-workflow-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master)
  const recovery = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: join(root, 'binding.bin'), client: f.client, protector })
  let workflow = new HostTerminalEnrollmentWorkflow({ client: f.client, recovery, binding })
  t.after(() => { workflow.close(); recovery.close(); binding.close() })
  const request = { organizationId: organization, alias: 'Fixture host', profileRef: 'profile', dshVersion: '0.2.1-rc.2',
    applicationVersion: 'fixture', pluginVersion: '0.0.1', protocolVersion: 1, workspaceRefs: ['z-workspace', 'a-workspace'] }
  assert.equal(await workflow.resume(AbortSignal.timeout(5_000)), undefined)
  let entered!: () => void
  let started = new Promise<void>(resolve => { entered = resolve })
  f.state.holdCreate = true; f.state.onCreate = () => entered()
  const first = workflow.start(request, AbortSignal.timeout(5_000))
  await started
  await assert.rejects(workflow.resume(AbortSignal.timeout(1_000)), workflowError('busy'))
  workflow.close()
  await assert.rejects(first, valid('outcome_unknown'))
  const saved = await recovery.load(AbortSignal.timeout(5_000))
  assert.ok(saved)
  const requestId = saved.requestId, code = saved.code
  saved.destroy()
  workflow = new HostTerminalEnrollmentWorkflow({ client: f.client, recovery, binding })
  await assert.rejects(workflow.start(request, AbortSignal.timeout(5_000)), workflowError('existing'))
  const cancel = new AbortController()
  started = new Promise<void>(resolve => { entered = resolve })
  f.state.holdCreate = true; f.state.onCreate = () => entered()
  const retry = workflow.resume(cancel.signal)
  await started; cancel.abort()
  await assert.rejects(retry, valid('outcome_unknown'))
  const creates = f.requests.filter(item => item.path === '/v1/enrollments' && item.proof.nonce)
  assert.equal(creates.length, 2); assert.equal(f.counts().createdCount, 1)
  assert.deepEqual(creates[0]!.body, creates[1]!.body)
  assert.equal(creates[0]!.body.request_id, requestId); assert.equal(creates[0]!.body.code, code)
})

test('terminal workflow starts a new protected request and requires local confirmation', { skip: process.platform !== 'linux', timeout: 20_000 }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-workflow-start-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  // The local identity fixture supplies a pre-confirmed phone; the PTY driver
  // still has to answer the distinct, fresh host confirmation challenge.
  f.state.phoneConfirmed = true
  const module = (name: string) => pathToFileURL(resolve(`host/remote-control/src/${name}.ts`)).href
  const script = join(root, 'workflow.mts')
  const configuration = { origin: f.options.origin, identity: expected, publicJwk: f.options.publicJwk, account: f.account,
    privateKey: f.privateKey.export({ type: 'pkcs8', format: 'pem' }), master: master.toString('base64'), root }
  await writeFile(script, [
    "import { createCipheriv,createDecipheriv,createPrivateKey,randomBytes,sign } from 'node:crypto'",
    `import { HostEnrollmentClient } from ${JSON.stringify(module('host-enrollment'))}`,
    `import { HostEnrollmentRecoveryStore } from ${JSON.stringify(module('host-enrollment-recovery'))}`,
    `import { HostEnrollmentBindingStore } from ${JSON.stringify(module('host-enrollment-binding'))}`,
    `import { HostTerminalEnrollmentWorkflow } from ${JSON.stringify(module('host-enrollment-workflow'))}`,
    `const c=${JSON.stringify(configuration)},owner=new AbortController(),key=createPrivateKey(c.privateKey),master=Buffer.from(c.master,'base64')`,
    "const protector={id:'fixture-enrollment-recovery',async wrap(value,aad){const n=randomBytes(12),x=createCipheriv('aes-256-gcm',master,n);x.setAAD(aad);return Buffer.concat([n,x.update(value),x.final(),x.getAuthTag()])},async unwrap(value,aad){const b=Buffer.from(value),x=createDecipheriv('aes-256-gcm',master,b.subarray(0,12));x.setAAD(aad);x.setAuthTag(b.subarray(44));return Buffer.concat([x.update(b.subarray(12,44)),x.final()])}}",
    "const client=new HostEnrollmentClient({origin:c.origin,identity:c.identity,publicJwk:c.publicJwk,requiredScopes:['remote.access'],allowLoopbackHttp:true,signer:{sign(input){return sign('sha256',Buffer.from(input),{key,dsaEncoding:'ieee-p1363'})}},account:{signal:owner.signal,async acquire(){return c.account}}})",
    "const recovery=new HostEnrollmentRecoveryStore({path:c.root+'/pending.bin',client,protector}),binding=new HostEnrollmentBindingStore({path:c.root+'/binding.bin',client,protector}),workflow=new HostTerminalEnrollmentWorkflow({client,recovery,binding})",
    `const result=await workflow.start({organizationId:${JSON.stringify(organization)},alias:'Fixture host',profileRef:'profile',dshVersion:'0.2.1-rc.2',applicationVersion:'fixture',pluginVersion:'0.0.1',protocolVersion:1,workspaceRefs:['z-workspace','a-workspace']},AbortSignal.timeout(6500))`,
    "const saved=await recovery.load(AbortSignal.timeout(3000));process.stdout.write(JSON.stringify({requestId:result.requestId,enrollmentId:result.enrollmentId,savedRequestId:saved?.requestId})+'\\n');saved?.destroy();workflow.close();binding.close();recovery.close();client.close();owner.abort();master.fill(0)", '',
  ].join('\n'), { mode: 0o600 })
  const child = spawn('python3', [resolve('host/remote-control/tests/fixtures/host-terminal-pty.py'), 'accept', resolve('node_modules/.bin/tsx'), script],
    { cwd: root, env: { PATH: process.env.PATH ?? '', TMPDIR: root }, stdio: ['ignore', 'pipe', 'pipe'] })
  let stdout = '', stderr = ''
  child.stdout.setEncoding('utf8').on('data', value => { stdout = (stdout + value).slice(-100_000) })
  child.stderr.setEncoding('utf8').on('data', value => { stderr = (stderr + value).slice(-4096) })
  const [exit] = await once(child, 'close')
  assert.equal(exit, 0, `terminal driver failed: ${stderr}`)
  const output = JSON.parse(stdout) as { exit: number; stdout: string; stderr: string; terminal: string }
  assert.equal(output.exit, 0, `workflow child failed: ${output.stderr}`)
  assert.equal(output.stdout.includes(token), false)
  const result = JSON.parse(output.stdout) as { requestId: string; enrollmentId: string; savedRequestId: string }
  assert.equal(result.enrollmentId, enrollment); assert.equal(result.requestId, result.savedRequestId)
  assert.ok(Buffer.from(output.terminal, 'base64').toString('utf8').includes('配对码: '))
  assert.equal(f.counts().createdCount, 1); assert.equal(f.counts().confirmedCount, 1)
})

test('terminal workflow returns an online-verified binding and keeps a pending record for explicit cleanup', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-workflow-bound-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), recovery = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: join(root, 'binding.bin'), client: f.client, protector })
  const workflow = new HostTerminalEnrollmentWorkflow({ client: f.client, recovery, binding })
  t.after(() => { workflow.close(); recovery.close(); binding.close() })
  const attempt = f.prepare(), receipt = await recovery.create(attempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true
  const approved = await binding.confirm(recovery, attempt, receipt, () => true, AbortSignal.timeout(5_000))
  assert.deepEqual(await workflow.resume(AbortSignal.timeout(5_000)), approved)
  await assert.rejects(workflow.start({ organizationId: organization, alias: 'Other host', profileRef: 'profile', protocolVersion: 1, workspaceRefs: [] },
    AbortSignal.timeout(5_000)), workflowError('existing'))
  const saved = await recovery.load(AbortSignal.timeout(5_000))
  assert.ok(saved); assert.equal(saved.requestId, attempt.requestId); saved.destroy()
  assert.equal(f.counts().createdCount, 1); assert.equal(f.counts().confirmedCount, 1)
  assert.equal(await workflow.cleanup(AbortSignal.timeout(5_000)), true)
  assert.equal(await workflow.cleanup(AbortSignal.timeout(5_000)), false); attempt.destroy()
})

test('approved cleanup matches an expired protected attempt without reviving it', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-cleanup-expired-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), recovery = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: join(root, 'binding.bin'), client: f.client, protector })
  const workflow = new HostTerminalEnrollmentWorkflow({ client: f.client, recovery, binding })
  t.after(() => { workflow.close(); recovery.close(); binding.close() })
  const attempt = f.prepare(), receipt = await recovery.create(attempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true
  const approved = await binding.confirm(recovery, attempt, receipt, () => true, AbortSignal.timeout(5_000))
  attempt.destroy(); workflow.close(); binding.close(); recovery.close(); f.client.close()
  const reopenedClient = new HostEnrollmentClient(f.options)
  const reopenedRecovery = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: reopenedClient, protector })
  const reopenedBinding = new HostEnrollmentBindingStore({ path: join(root, 'binding.bin'), client: reopenedClient, protector })
  const reopenedWorkflow = new HostTerminalEnrollmentWorkflow({ client: reopenedClient, recovery: reopenedRecovery, binding: reopenedBinding })
  t.after(() => { reopenedWorkflow.close(); reopenedRecovery.close(); reopenedBinding.close(); reopenedClient.close() })
  const realNow = Date.now
  try {
    Date.now = () => realNow() + 601_000
    f.account.expiresAt = Date.now() + 300_000
    await assert.rejects(reopenedRecovery.load(AbortSignal.timeout(5_000)), (cause: unknown) =>
      cause instanceof HostEnrollmentRecoveryError && cause.code === 'host.enrollment_recovery.unavailable')
    assert.equal(await reopenedWorkflow.cleanup(AbortSignal.timeout(5_000)), true)
    assert.equal(await reopenedWorkflow.cleanup(AbortSignal.timeout(5_000)), false)
    assert.deepEqual(await reopenedBinding.open(AbortSignal.timeout(5_000)), approved)
    assert.equal(f.counts().confirmedCount, 1)
  } finally { Date.now = realNow }
})

test('legacy binding pointers stay usable but cannot authorize digest-based cleanup', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-cleanup-legacy-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), pendingPath = join(root, 'pending.bin'), bindingPath = join(root, 'binding.bin')
  const recovery = new HostEnrollmentRecoveryStore({ path: pendingPath, client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: bindingPath, client: f.client, protector })
  const workflow = new HostTerminalEnrollmentWorkflow({ client: f.client, recovery, binding })
  t.after(() => { workflow.close(); recovery.close(); binding.close() })
  const attempt = f.prepare(), receipt = await recovery.create(attempt, AbortSignal.timeout(5_000))
  const captured = captureEnrollmentBinding(f.client, attempt, receipt)
  assert.equal(captured.version, 2)
  const { recovery_sha256: _digest, ...fields } = captured
  const legacy = { ...fields, version: 1 as const }
  const plaintext = Buffer.from(canonicalObject(legacy))
  const context = Buffer.from(`dsh-host-enrollment-binding-store-v1\0${bindingPath}\0${legacy.binding}\0${protector.id}`, 'utf8')
  const sealed = await seal(plaintext, protectorFrom(protector), context, AbortSignal.timeout(5_000), Buffer.from('DSHENB01'))
  await writeFile(bindingPath, sealed, { mode: 0o600 })
  plaintext.fill(0); context.fill(0); sealed.fill(0)
  const originalBinding = await readFile(bindingPath), originalRecovery = await readFile(pendingPath)
  await binding.reserve(attempt, receipt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true
  const approved = await binding.confirm(recovery, attempt, receipt, () => true, AbortSignal.timeout(5_000))
  assert.deepEqual(await binding.open(AbortSignal.timeout(5_000)), approved)
  assert.deepEqual(await readFile(bindingPath), originalBinding)
  await assert.rejects(workflow.cleanup(AbortSignal.timeout(5_000)), (cause: unknown) =>
    cause instanceof HostEnrollmentRecoveryError && cause.code === 'host.enrollment_recovery.conflict')
  assert.deepEqual(await readFile(pendingPath), originalRecovery)
  assert.equal(await recovery.remove(attempt, AbortSignal.timeout(5_000)), true)
  attempt.destroy()
})

test('new binding pointers reject a different recovery payload even with the same request metadata', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-binding-digest-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const bindingPath = join(root, 'binding.bin'), binding = new HostEnrollmentBindingStore({ path: bindingPath, client: f.client, protector: recoveryProtector(master) })
  t.after(() => binding.close())
  const first = f.prepare(), receipt = await f.client.create(first, AbortSignal.timeout(5_000))
  await binding.reserve(first, receipt, AbortSignal.timeout(5_000))
  const original = await readFile(bindingPath), exported = first.exportRecovery()
  const altered = JSON.parse(exported.toString('utf8')) as { code: string }
  exported.fill(0); altered.code = randomBytes(32).toString('base64url')
  const changed = Buffer.from(JSON.stringify(altered)), second = f.client.restore(changed)
  changed.fill(0); assert.equal(second.requestId, first.requestId)
  f.resetEnrollment()
  const changedReceipt = await f.client.create(second, AbortSignal.timeout(5_000))
  await assert.rejects(binding.reserve(second, changedReceipt, AbortSignal.timeout(5_000)), bindingError('conflict'))
  assert.deepEqual(await readFile(bindingPath), original)
  first.destroy(); second.destroy()
})

test('approved cleanup preserves absent, pending, mismatched, forged and wrong-owner records', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-cleanup-conflict-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), path = join(root, 'pending.bin')
  const recovery = new HostEnrollmentRecoveryStore({ path, client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: join(root, 'binding.bin'), client: f.client, protector })
  const workflow = new HostTerminalEnrollmentWorkflow({ client: f.client, recovery, binding })
  t.after(() => { workflow.close(); recovery.close(); binding.close() })
  const first = f.prepare(), receipt = await recovery.create(first, AbortSignal.timeout(5_000))
  const initial = await readFile(path)
  await assert.rejects(workflow.cleanup(AbortSignal.timeout(5_000)), (cause: unknown) =>
    cause instanceof HostEnrollmentRecoveryError && cause.code === 'host.enrollment_recovery.conflict')
  await binding.reserve(first, receipt, AbortSignal.timeout(5_000))
  await assert.rejects(workflow.cleanup(AbortSignal.timeout(5_000)), valid('review_required'))
  assert.deepEqual(await readFile(path), initial)
  f.state.phoneConfirmed = true
  const approved = await binding.confirm(recovery, first, receipt, () => true, AbortSignal.timeout(5_000))
  const fakeStore = { signal: binding.signal, async open() { return { ...approved } } } as unknown as HostEnrollmentBindingStore
  await assert.rejects(recovery.removeApproved(fakeStore, AbortSignal.timeout(5_000)), valid('invalid_config'))
  assert.deepEqual(await readFile(path), initial)
  const exported = first.exportRecovery()
  const altered = JSON.parse(exported.toString('utf8')) as { code: string; input: { alias: string } }
  exported.fill(0); altered.code = randomBytes(32).toString('base64url'); altered.input.alias = 'Different host alias'
  const alteredBytes = Buffer.from(JSON.stringify(altered)), sameRequestWrongPayload = f.client.restore(alteredBytes)
  alteredBytes.fill(0)
  assert.equal(await recovery.remove(first, AbortSignal.timeout(5_000)), true)
  await recovery.save(sameRequestWrongPayload, AbortSignal.timeout(5_000))
  const changedPayload = await readFile(path)
  await assert.rejects(workflow.cleanup(AbortSignal.timeout(5_000)), (cause: unknown) =>
    cause instanceof HostEnrollmentRecoveryError && cause.code === 'host.enrollment_recovery.conflict')
  assert.deepEqual(await readFile(path), changedPayload)
  assert.equal(await recovery.remove(sameRequestWrongPayload, AbortSignal.timeout(5_000)), true)
  const second = f.prepare()
  await recovery.save(second, AbortSignal.timeout(5_000))
  const otherRecord = await readFile(path)
  await assert.rejects(workflow.cleanup(AbortSignal.timeout(5_000)), (cause: unknown) =>
    cause instanceof HostEnrollmentRecoveryError && cause.code === 'host.enrollment_recovery.conflict')
  assert.deepEqual(await readFile(path), otherRecord)
  const damaged = Buffer.from(otherRecord); damaged[damaged.length - 1] = damaged[damaged.length - 1]! ^ 1
  await writeFile(path, damaged, { mode: 0o600 })
  await assert.rejects(workflow.cleanup(AbortSignal.timeout(5_000)), (cause: unknown) =>
    cause instanceof HostEnrollmentRecoveryError && cause.code === 'host.enrollment_recovery.unavailable')
  assert.deepEqual(await readFile(path), damaged)

  const other = new HostEnrollmentClient({ ...f.options, identity: { ...expected, subject: 'other-owner' } })
  const wrongOwner = new HostEnrollmentRecoveryStore({ path: join(root, 'other-pending.bin'), client: other, protector })
  t.after(() => { wrongOwner.close(); other.close() })
  const otherAttempt = other.prepare({ organizationId: organization, alias: 'Other host', profileRef: 'profile', protocolVersion: 1, workspaceRefs: [] })
  await wrongOwner.save(otherAttempt, AbortSignal.timeout(5_000))
  const ownedBytes = await readFile(join(root, 'other-pending.bin'))
  await assert.rejects(wrongOwner.removeApproved(binding, AbortSignal.timeout(5_000)), valid('invalid_config'))
  assert.deepEqual(await readFile(join(root, 'other-pending.bin')), ownedBytes)
  first.destroy(); sameRequestWrongPayload.destroy(); second.destroy(); otherAttempt.destroy()
})

test('approved cleanup locks the pending file during online review and preserves it on cancellation', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-cleanup-lock-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), path = join(root, 'pending.bin')
  const recovery = new HostEnrollmentRecoveryStore({ path, client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: join(root, 'binding.bin'), client: f.client, protector })
  const workflow = new HostTerminalEnrollmentWorkflow({ client: f.client, recovery, binding })
  t.after(() => { workflow.close(); recovery.close(); binding.close() })
  const attempt = f.prepare(), receipt = await recovery.create(attempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true
  await binding.confirm(recovery, attempt, receipt, () => true, AbortSignal.timeout(5_000))
  const before = await readFile(path), cancel = new AbortController()
  let entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  f.state.holdReview = true; f.state.onReview = () => entered()
  const cleaning = workflow.cleanup(cancel.signal)
  await started
  await assert.rejects(recovery.discard(AbortSignal.timeout(1_000)), (cause: unknown) =>
    cause instanceof HostEnrollmentRecoveryError && cause.code === 'host.enrollment_recovery.busy')
  cancel.abort(); await assert.rejects(cleaning, valid('cancelled'))
  assert.deepEqual(await readFile(path), before)
  f.state.onReview = undefined
  assert.equal(await workflow.cleanup(AbortSignal.timeout(5_000)), true)
  attempt.destroy()
})

test('terminal workflow refuses missing recovery and conflicting pointers before displaying a code', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-workflow-conflict-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), recovery = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: join(root, 'binding.bin'), client: f.client, protector })
  const workflow = new HostTerminalEnrollmentWorkflow({ client: f.client, recovery, binding })
  t.after(() => { workflow.close(); recovery.close(); binding.close() })
  const first = f.prepare(), firstReceipt = await f.client.create(first, AbortSignal.timeout(5_000))
  await binding.reserve(first, firstReceipt, AbortSignal.timeout(5_000))
  await assert.rejects(workflow.resume(AbortSignal.timeout(5_000)), workflowError('recovery_required'))
  await assert.rejects(workflow.start({ organizationId: organization, alias: 'Other host', profileRef: 'profile', protocolVersion: 1, workspaceRefs: [] },
    AbortSignal.timeout(5_000)), workflowError('existing'))
  f.resetEnrollment()
  const second = f.prepare()
  await recovery.create(second, AbortSignal.timeout(5_000))
  // This fixture stores only one server enrollment. Keep the first pending
  // pointer while the second is current, and model the first review as pending.
  const pendingView = { signal: binding.signal, async open() { throw new HostEnrollmentError('host.enrollment.review_required') },
    reserve: binding.reserve.bind(binding), confirm: binding.confirm.bind(binding) } as unknown as HostEnrollmentBindingStore
  const conflicting = new HostTerminalEnrollmentWorkflow({ client: f.client, recovery, binding: pendingView })
  t.after(() => conflicting.close())
  const reviews = f.counts().reviews
  await assert.rejects(conflicting.resume(AbortSignal.timeout(5_000)), bindingError('conflict'))
  assert.equal(f.counts().reviews, reviews)
  assert.equal(f.counts().confirmedCount, 0)
  first.destroy(); second.destroy()
})

test('enrolled runtime admits only the verified account, profile and workspace mappings', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrolled-runtime-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), recovery = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: join(root, 'binding.bin'), client: f.client, protector })
  const credentials = new HostRestCredentialProvider({ ...f.options, installationId: installation })
  t.after(() => { credentials.close(); recovery.close(); binding.close() })
  assert.equal(enrollmentRecoveryBinding(f.client), createHash('sha256').update(JSON.stringify({ purpose: 'dsh-host-enrollment-intent-v1',
    origin: f.options.origin, identity: expected, thumbprint: f.account.proofKeyThumbprint, requiredScopes: ['remote.access'] })).digest('hex'))
  const attempt = f.prepare(), receipt = await recovery.create(attempt, AbortSignal.timeout(5_000))
  const pendingWorkspace = receipt.details.workspaces.find(item => item.reference === 'a-workspace')!
  const pendingGuard = { client: f.client, binding, credentials, profileRef: 'profile' }
  const pendingLocal = { runtimeId: runtime, requireProtectedJournalKey: true,
    workspaces: [{ id: pendingWorkspace.reference, remoteId: pendingWorkspace.workspace_id, cwd: join(root, 'project') }] }
  const pendingSigned = { hostId: host, installationId: installation }
  await assert.rejects(verifyEnrolledHostRuntime(pendingGuard, pendingLocal, pendingSigned, AbortSignal.timeout(5_000)), runtimeError('unavailable'))
  await binding.reserve(attempt, receipt, AbortSignal.timeout(5_000))
  await assert.rejects(verifyEnrolledHostRuntime(pendingGuard, pendingLocal, pendingSigned, AbortSignal.timeout(5_000)), runtimeError('unavailable'))
  f.state.phoneConfirmed = true
  const approved = await binding.confirm(recovery, attempt, receipt, () => true, AbortSignal.timeout(5_000))
  const first = approved.workspaces.find(item => item.reference === 'a-workspace')!, second = approved.workspaces.find(item => item.reference === 'z-workspace')!
  const guard = { client: f.client, binding, credentials, profileRef: 'profile' }
  const local = { runtimeId: runtime, requireProtectedJournalKey: true, workspaces: [{ id: first.reference, remoteId: first.workspaceId, cwd: join(root, 'project') }] }
  const signed = { hostId: host, installationId: installation }, signal = AbortSignal.timeout(5_000)
  await verifyEnrolledHostRuntime(guard, local, signed, signal)
  await verifyEnrolledHostRuntime(guard, { ...local, workspaces: [...local.workspaces, { id: second.reference, remoteId: second.workspaceId, cwd: join(root, 'other') }] }, signed, signal)
  for (const changed of [
    { ...local, runtimeId: randomUUID() },
    { ...local, workspaces: [{ ...local.workspaces[0]!, id: 'unregistered' }] },
    { ...local, workspaces: [{ ...local.workspaces[0]!, remoteId: second.workspaceId }] },
    { ...local, workspaces: [{ ...local.workspaces[0]!, cwd: 'relative/path' }] },
    { ...local, workspaces: [...local.workspaces, { ...local.workspaces[0]! }] },
    { ...local, workspaces: [...local.workspaces, { id: second.reference, remoteId: second.workspaceId, cwd: join(root, 'project', '..', 'project') }] },
  ]) await assert.rejects(verifyEnrolledHostRuntime(guard, changed, signed, signal), runtimeError('identity_changed'))
  await assert.rejects(verifyEnrolledHostRuntime(guard, { ...local, requireProtectedJournalKey: false }, signed, signal), runtimeError('invalid_config'))
  await assert.rejects(verifyEnrolledHostRuntime({ ...guard, profileRef: 'another-profile' }, local, signed, signal), runtimeError('identity_changed'))
  await assert.rejects(verifyEnrolledHostRuntime(guard, local, { ...signed, hostId: randomUUID() }, signal), runtimeError('identity_changed'))
  await assert.rejects(verifyEnrolledHostRuntime(guard, local, { ...signed, installationId: randomUUID() }, signal), runtimeError('identity_changed'))
  const wrongInstallation = new HostRestCredentialProvider({ ...f.options, installationId: randomUUID() })
  const otherClient = new HostEnrollmentClient({ ...f.options, identity: { ...expected, subject: 'other-owner' } })
  const unrelatedKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }) as HostEnrollmentOptions['publicJwk']
  const wrongKey = new HostRestCredentialProvider({ ...f.options, publicJwk: unrelatedKey, installationId: installation })
  const wrongOrigin = new HostRestCredentialProvider({ ...f.options, origin: 'http://127.0.0.1:1', installationId: installation })
  const wrongScopes = new HostRestCredentialProvider({ ...f.options, requiredScopes: ['another.scope'], installationId: installation })
  t.after(() => { wrongInstallation.close(); otherClient.close(); wrongKey.close(); wrongOrigin.close(); wrongScopes.close() })
  await assert.rejects(verifyEnrolledHostRuntime({ ...guard, credentials: wrongInstallation }, local, signed, signal), runtimeError('identity_changed'))
  await assert.rejects(verifyEnrolledHostRuntime({ ...guard, client: otherClient }, local, signed, signal), runtimeError('identity_changed'))
  const reviewsBeforeMismatches = f.counts().reviews
  for (const wrong of [wrongKey, wrongOrigin, wrongScopes]) {
    await assert.rejects(verifyEnrolledHostRuntime({ ...guard, credentials: wrong }, local, signed, signal), runtimeError('identity_changed'))
  }
  assert.equal(f.counts().reviews, reviewsBeforeMismatches)
  const forgedStore = { signal: binding.signal, async open() { return { ...approved } } } as unknown as HostEnrollmentBindingStore
  await assert.rejects(verifyEnrolledHostRuntime({ ...guard, binding: forgedStore }, local, signed, signal), runtimeError('identity_changed'))
  f.state.denyReview = true
  await assert.rejects(verifyEnrolledHostRuntime(guard, local, signed, signal), runtimeError('unavailable'))
  assert.equal(f.requests.filter(item => item.path.includes('host-credentials')).length, 0)
  attempt.destroy()
})

test('enrolled plugin rejects a wrong workspace before opening its journal or endpoint', { skip: process.platform !== 'linux', timeout: 15_000 }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrolled-plugin-reject-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), recovery = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: join(root, 'binding.bin'), client: f.client, protector })
  const credentials = new HostRestCredentialProvider({ ...f.options, installationId: installation })
  t.after(() => { credentials.close(); recovery.close(); binding.close() })
  const attempt = f.prepare(), receipt = await recovery.create(attempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true
  const approved = await binding.confirm(recovery, attempt, receipt, () => true, AbortSignal.timeout(5_000))
  const h = await dshHost({ probe: false })
  const signed = { hostId: host, installationId: installation, policyVersion: 7, requiredAssurance: { profile: 'fixture/verified', max_auth_age_seconds: 60 }, authorities: [] }
  const plugin = createEnrolledRemoteControlPlugin({ client: f.client, binding, credentials, profileRef: 'profile' }, signed, protector)
  const journal = join(h.directory, 'guarded', 'commands.sqlite')
  try {
    const fiber = h.ctx.plugin(plugin, { enabled: true, runtimeId: runtime, relayUrl: f.options.origin, applicationVersion: 'fixture', socketPath: h.socketPath,
      commandJournalPath: journal, requireProtectedJournalKey: true, workspaces: [{ id: 'a-workspace', cwd: h.cwd, remoteId: approved.workspaces.find(item => item.reference === 'z-workspace')!.workspaceId }], presets: ['fixture'] })
    await assert.rejects(fiber.await(), runtimeError('identity_changed'))
    for (const path of [journal, `${journal}.wrapped-key`, h.socketPath]) await assert.rejects(lstat(path), error => (error as NodeJS.ErrnoException).code === 'ENOENT')
    await fiber.dispose()
  } finally { attempt.destroy(); await h.close() }
})

test('disposing an enrolled plugin cancels an in-flight binding review without opening local state', { skip: process.platform !== 'linux', timeout: 15_000 }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrolled-plugin-cancel-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), recovery = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: join(root, 'binding.bin'), client: f.client, protector })
  const credentials = new HostRestCredentialProvider({ ...f.options, installationId: installation })
  t.after(() => { credentials.close(); recovery.close(); binding.close() })
  const attempt = f.prepare(), receipt = await recovery.create(attempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true
  const approved = await binding.confirm(recovery, attempt, receipt, () => true, AbortSignal.timeout(5_000))
  const h = await dshHost({ probe: false }), journal = join(h.directory, 'cancelled', 'commands.sqlite')
  const signed = { hostId: host, installationId: installation, policyVersion: 7, requiredAssurance: { profile: 'fixture/verified', max_auth_age_seconds: 60 }, authorities: [] }
  const plugin = createEnrolledRemoteControlPlugin({ client: f.client, binding, credentials, profileRef: 'profile' }, signed, protector)
  let entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  f.state.holdReview = true; f.state.onReview = () => entered()
  try {
    const fiber = h.ctx.plugin(plugin, { enabled: true, runtimeId: runtime, relayUrl: f.options.origin, applicationVersion: 'fixture', socketPath: h.socketPath,
      commandJournalPath: journal, requireProtectedJournalKey: true, workspaces: [{ id: 'a-workspace', cwd: h.cwd, remoteId: approved.workspaces.find(item => item.reference === 'a-workspace')!.workspaceId }], presets: ['fixture'] })
    const completion = fiber.await(); void completion.catch(() => {})
    await started
    let timer: NodeJS.Timeout | undefined
    try { await Promise.race([fiber.dispose(), new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('disposal waited for enrollment review')), 1_000) })]) }
    finally { if (timer) clearTimeout(timer) }
    await assert.rejects(completion, runtimeError('cancelled'))
    for (const path of [journal, `${journal}.wrapped-key`, h.socketPath]) await assert.rejects(lstat(path), error => (error as NodeJS.ErrnoException).code === 'ENOENT')
    f.state.onReview = undefined
    assert.ok(await binding.open(AbortSignal.timeout(5_000)))
  } finally { attempt.destroy(); await h.close() }
})

test('binding pointer reconciles a lost confirmation without the expired pairing attempt', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-binding-lost-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), pendingPath = join(root, 'pending.bin'), bindingPath = join(root, 'binding.bin')
  const recovery = new HostEnrollmentRecoveryStore({ path: pendingPath, client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: bindingPath, client: f.client, protector })
  const attempt = f.prepare(), receipt = await recovery.create(attempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true; f.state.dropConfirm = true
  await assert.rejects(binding.confirm(recovery, attempt, receipt, () => true, AbortSignal.timeout(5_000)), valid('outcome_unknown'))
  assert.equal(f.counts().confirmedCount, 1)
  binding.close(); recovery.close(); f.client.close(); attempt.destroy()
  const client = new HostEnrollmentClient(f.options), reopened = new HostEnrollmentBindingStore({ path: bindingPath, client, protector })
  t.after(() => { reopened.close(); client.close() })
  const now = Date.now
  try {
    Date.now = () => now() + 601_000
    f.account.expiresAt = Date.now() + 300_000
    const result = await reopened.open(AbortSignal.timeout(5_000))
    assert.equal(result?.installationId, installation); assert.equal(result?.runtimeId, runtime)
    assert.equal(f.counts().confirmedCount, 1)
  } finally { Date.now = now }
})

test('binding confirmation preserves its pointer if the subsequent server review fails', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-binding-review-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), recovery = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: join(root, 'binding.bin'), client: f.client, protector })
  t.after(() => { recovery.close(); binding.close() })
  const attempt = f.prepare(), receipt = await recovery.create(attempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true; f.state.dropReviewAt = 3
  await assert.rejects(binding.confirm(recovery, attempt, receipt, () => true, AbortSignal.timeout(5_000)), valid('outcome_unknown'))
  assert.equal(f.counts().confirmedCount, 1)
  f.state.dropReviewAt = 0
  assert.equal((await binding.open(AbortSignal.timeout(5_000)))?.runtimeId, runtime)
})

test('cancellation after confirmation is reported as unknown and remains reconcilable', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-binding-cancel-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), recovery = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: join(root, 'binding.bin'), client: f.client, protector })
  t.after(() => { recovery.close(); binding.close() })
  const attempt = f.prepare(), receipt = await recovery.create(attempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true
  const controller = new AbortController()
  f.state.onReview = count => { if (count === 3) controller.abort() }
  await assert.rejects(binding.confirm(recovery, attempt, receipt, () => true, controller.signal), valid('outcome_unknown'))
  assert.equal(f.counts().confirmedCount, 1)
  assert.equal((await binding.open(AbortSignal.timeout(5_000)))?.installationId, installation)
})

test('a binding file changed during final review never produces a durable success', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-binding-replaced-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), recovery = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector })
  const path = join(root, 'binding.bin'), binding = new HostEnrollmentBindingStore({ path, client: f.client, protector })
  t.after(() => { recovery.close(); binding.close() })
  const attempt = f.prepare(), receipt = await recovery.create(attempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true
  f.state.onReview = count => { if (count === 3) writeFileSync(path, 'corrupt-after-confirmation', { mode: 0o600 }) }
  await assert.rejects(binding.confirm(recovery, attempt, receipt, () => true, AbortSignal.timeout(5_000)), valid('outcome_unknown'))
  assert.equal(f.counts().confirmedCount, 1)
  await assert.rejects(binding.open(AbortSignal.timeout(5_000)), bindingError('unavailable'))
  assert.equal((await recovery.load(AbortSignal.timeout(5_000)))?.requestId, attempt.requestId)
})

test('binding pointer remains locked throughout local confirmation', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-binding-lock-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), recovery = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector })
  const binding = new HostEnrollmentBindingStore({ path: join(root, 'binding.bin'), client: f.client, protector })
  t.after(() => { recovery.close(); binding.close() })
  const attempt = f.prepare(), receipt = await recovery.create(attempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true
  let entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve }), controller = new AbortController()
  const confirming = binding.confirm(recovery, attempt, receipt, () => { entered(); return new Promise<boolean>(() => {}) }, controller.signal)
  await started
  await assert.rejects(binding.discard(AbortSignal.timeout(1_000)), bindingError('busy'))
  controller.abort(); await assert.rejects(confirming, valid('cancelled'))
  await assert.rejects(binding.open(AbortSignal.timeout(5_000)), valid('review_required'))
  assert.equal(f.counts().confirmedCount, 0)
})

test('binding pointers reject forged, conflicting, corrupted and wrong-account data', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-binding-conflict-')), master = randomBytes(32)
  t.after(async () => { master.fill(0); await rm(root, { recursive: true, force: true }) })
  const protector = recoveryProtector(master), path = join(root, 'binding.bin')
  const binding = new HostEnrollmentBindingStore({ path, client: f.client, protector })
  const recovery = new HostEnrollmentRecoveryStore({ path: join(root, 'pending.bin'), client: f.client, protector })
  t.after(() => { binding.close(); recovery.close() })
  const first = f.prepare(), receipt = await f.client.create(first, AbortSignal.timeout(5_000))
  await assert.rejects(binding.reserve(first, { details: receipt.details }, AbortSignal.timeout(5_000)), valid('invalid_config'))
  await assert.rejects(lstat(path), error => (error as NodeJS.ErrnoException).code === 'ENOENT')
  await recovery.save(first, AbortSignal.timeout(5_000))
  await writeFile(path, await readFile(join(root, 'pending.bin')), { mode: 0o600 })
  await assert.rejects(binding.open(AbortSignal.timeout(5_000)), bindingError('unavailable'))
  await assert.rejects(binding.discard(AbortSignal.timeout(5_000)), bindingError('unavailable'))
  await rm(path)
  await binding.reserve(first, receipt, AbortSignal.timeout(5_000))
  const original = await readFile(path)
  f.resetEnrollment()
  const second = f.prepare(), secondReceipt = await f.client.create(second, AbortSignal.timeout(5_000))
  await assert.rejects(binding.reserve(second, secondReceipt, AbortSignal.timeout(5_000)), bindingError('conflict'))
  assert.deepEqual(await readFile(path), original)
  const different = new HostEnrollmentClient({ ...f.options, identity: { ...expected, subject: 'other-owner' } })
  const wrongOwner = new HostEnrollmentBindingStore({ path, client: different, protector })
  t.after(() => { wrongOwner.close(); different.close() })
  await assert.rejects(wrongOwner.open(AbortSignal.timeout(5_000)), bindingError('unavailable'))
  const damaged = Buffer.from(original); damaged[damaged.length - 1] = damaged[damaged.length - 1]! ^ 1
  await writeFile(path, damaged, { mode: 0o600 })
  await assert.rejects(binding.open(AbortSignal.timeout(5_000)), bindingError('unavailable'))
  await assert.rejects(binding.discard(AbortSignal.timeout(5_000)), bindingError('unavailable'))
  assert.deepEqual(await readFile(path), damaged)
})

test('host enrollment pins account, proof key and response identity before publishing results', async t => {
  const f = await fixture(t)
  const recovery = f.prepare().exportRecovery()
  const altered = new HostEnrollmentClient({ ...f.options, identity: { ...expected, subject: 'other-owner' } })
  t.after(() => altered.close())
  const alteredScope = new HostEnrollmentClient({ ...f.options, requiredScopes: ['another.scope'] })
  t.after(() => alteredScope.close())
  assert.throws(() => altered.restore(recovery), valid('invalid_config'))
  assert.throws(() => alteredScope.restore(recovery), valid('invalid_config'))
  const expired = JSON.parse(recovery.toString('utf8')) as { preparedAt: number }
  expired.preparedAt = Date.now() - 601_000
  const expiredRecovery = Buffer.from(JSON.stringify(expired))
  assert.throws(() => f.client.restore(expiredRecovery), valid('invalid_config'))
  expiredRecovery.fill(0); recovery.fill(0)
  assert.throws(() => f.client.restore(Buffer.from('{"version":1,"version":1}')), valid('invalid_config'))
  assert.throws(() => f.client.prepare({ organizationId: organization, alias: '\ud800', profileRef: 'profile', protocolVersion: 1, workspaceRefs: [] }), valid('invalid_config'))
  f.account.proofKeyThumbprint = nonce()
  await assert.rejects(f.client.create(f.prepare(), AbortSignal.timeout(5_000)), valid('identity_changed'))
  assert.equal(f.requests.length, 0)
  f.account.proofKeyThumbprint = hash(JSON.stringify({ crv: f.options.publicJwk.crv, kty: f.options.publicJwk.kty, x: f.options.publicJwk.x, y: f.options.publicJwk.y }))
  const wrongKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const wrongSigner = new HostEnrollmentClient({ ...f.options, signer: { sign(input) { return sign('sha256', Buffer.from(input), { key: wrongKeys.privateKey, dsaEncoding: 'ieee-p1363' }) } } })
  t.after(() => wrongSigner.close())
  await assert.rejects(wrongSigner.create(wrongSigner.prepare({ organizationId: organization, alias: 'Fixture host', profileRef: 'profile', protocolVersion: 1, workspaceRefs: [] }), AbortSignal.timeout(5_000)), valid('proof_invalid'))
  assert.equal(f.requests.length, 0)
  const failedAccount = new HostEnrollmentClient({ ...f.options, account: { signal: f.owner.signal, async acquire() { throw new Error('PRIVATE_ACCOUNT_FAILURE') } } })
  t.after(() => failedAccount.close())
  await assert.rejects(failedAccount.create(failedAccount.prepare({ organizationId: organization, alias: 'Fixture host', profileRef: 'profile', protocolVersion: 1, workspaceRefs: [] }), AbortSignal.timeout(5_000)),
    error => valid('unavailable')(error) && !String(error).includes('PRIVATE_ACCOUNT_FAILURE'))
  assert.equal(f.requests.length, 0)
  f.state.wrongReceipt = true
  await assert.rejects(f.client.create(f.prepare(), AbortSignal.timeout(5_000)), valid('outcome_unknown'))
})

test('owner cancellation and destroyed attempts stop pending local work', async t => {
  const f = await fixture(t), attempt = f.prepare()
  f.owner.abort()
  assert.throws(() => attempt.code, valid('cancelled'))
  assert.throws(() => attempt.exportRecovery(), valid('cancelled'))
  await assert.rejects(f.client.create(attempt, AbortSignal.timeout(5_000)), valid('cancelled'))
  assert.equal(f.requests.length, 0)
})

test('destroying an attempt cancels an unfinished local review', async t => {
  const f = await fixture(t), attempt = f.prepare(), receipt = await f.client.create(attempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true
  let entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  const operation = f.client.confirm(attempt, receipt, () => { entered(); return new Promise<boolean>(() => {}) }, AbortSignal.timeout(5_000))
  await started; attempt.destroy()
  await assert.rejects(operation, valid('cancelled'))
  assert.throws(() => attempt.code, valid('invalid_config'))
  assert.equal(f.requests.some(item => item.path.endsWith('/host-confirm')), false)
})

test('one attempt cannot display concurrent local confirmation prompts', async t => {
  const f = await fixture(t), attempt = f.prepare(), receipt = await f.client.create(attempt, AbortSignal.timeout(5_000))
  const recovery = attempt.exportRecovery(), restored = f.client.restore(recovery)
  const duplicateModule = await import(`${pathToFileURL(resolve('host/remote-control/src/host-enrollment.ts')).href}?fixture=${randomBytes(8).toString('hex')}`) as typeof import('../src/host-enrollment.js')
  const duplicate = new duplicateModule.HostEnrollmentClient(f.options), duplicateAttempt = duplicate.restore(recovery)
  t.after(() => duplicate.close())
  recovery.fill(0)
  const restoredReceipt = await f.client.create(restored, AbortSignal.timeout(5_000))
  const duplicateReceipt = await duplicate.create(duplicateAttempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true
  const controller = new AbortController()
  let entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  const first = f.client.confirm(attempt, receipt, () => { entered(); return new Promise<boolean>(() => {}) }, controller.signal)
  await started
  await assert.rejects(f.client.confirm(attempt, receipt, () => true, AbortSignal.timeout(5_000)), valid('busy'))
  await assert.rejects(f.client.confirm(restored, restoredReceipt, () => true, AbortSignal.timeout(5_000)), valid('busy'))
  await assert.rejects(duplicate.confirm(duplicateAttempt, duplicateReceipt, () => true, AbortSignal.timeout(5_000)), error =>
    error instanceof Error && 'code' in error && error.code === 'host.enrollment.busy')
  controller.abort(); await assert.rejects(first, valid('cancelled'))
  await assert.rejects(f.client.confirm(attempt, receipt, () => false, AbortSignal.timeout(5_000)), valid('declined'))
  assert.equal(f.counts().confirmedCount, 0)
})

test('cancelled create after dispatch is unknown and an explicit retry preserves identity', async t => {
  const f = await fixture(t), attempt = f.prepare(), controller = new AbortController()
  let entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  f.state.holdCreate = true; f.state.onCreate = entered
  const operation = f.client.create(attempt, controller.signal)
  await started; controller.abort()
  await assert.rejects(operation, valid('outcome_unknown'))
  const receipt = await f.client.create(attempt, AbortSignal.timeout(5_000))
  assert.equal(receipt.details.request_id, attempt.requestId)
  assert.equal(f.counts().createdCount, 1)
})

test('host enrollment never follows a resource redirect', async t => {
  const f = await fixture(t), attempt = f.prepare()
  f.state.redirectCreate = true
  await assert.rejects(f.client.create(attempt, AbortSignal.timeout(5_000)), valid('outcome_unknown'))
  assert.equal(f.counts().createdCount, 0)
  assert.equal(f.requests.some(item => item.path === '/redirect-target'), false)
})

test('concurrent reviews use independent one-use nonces', async t => {
  const f = await fixture(t), attempt = f.prepare(), receipt = await f.client.create(attempt, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true
  const results = await Promise.all(Array.from({ length: 4 }, () => f.client.review(attempt, receipt, AbortSignal.timeout(5_000))))
  assert.ok(results.every(value => value.confirmed_user?.user_id === user))
  assert.equal(f.counts().reviews, 4)
})
