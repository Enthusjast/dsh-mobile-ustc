import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from 'node:crypto'
import { createServer, type ServerResponse } from 'node:http'
import { inspect } from 'node:util'
import { HostEnrollmentClient, type HostEnrollmentOptions } from '../src/host-enrollment.js'
import { HostEnrollmentError } from '../src/host-enrollment-transport.js'
import type { HostResourceAccess } from '../src/host-credentials.js'

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
const send = (response: ServerResponse, status: number, body: unknown, next: string) => {
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'dpop-nonce': next })
  response.end(JSON.stringify(body))
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
    dropCreate: false, holdCreate: false, redirectCreate: false, dropConfirm: false, wrongReceipt: false,
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
        send(response, 200, { ok: true, data: { enrollment: { enrollment_id: enrollment, request_id: input.request_id,
          organization_id: input.organization_id, organization_name: state.organizationName, host_id: host, host_alias: input.alias,
          installation_id: installation, installation_key_jkt: thumbprint, runtime_id: runtime, profile_ref: input.profile_ref,
          dsh_version: input.dsh_version, application_version: input.application_version, plugin_version: input.plugin_version,
          protocol_version: input.protocol_version, state: state.approved ? 'approved' : state.phoneConfirmed ? 'user_confirmed' : 'pending',
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
  return { client, options, account, owner, requests, prepare, state, counts: () => ({ createdCount, confirmedCount, reviews }) }
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
  recovery.fill(0)
  const restoredReceipt = await f.client.create(restored, AbortSignal.timeout(5_000))
  f.state.phoneConfirmed = true
  const controller = new AbortController()
  let entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  const first = f.client.confirm(attempt, receipt, () => { entered(); return new Promise<boolean>(() => {}) }, controller.signal)
  await started
  await assert.rejects(f.client.confirm(attempt, receipt, () => true, AbortSignal.timeout(5_000)), valid('busy'))
  await assert.rejects(f.client.confirm(restored, restoredReceipt, () => true, AbortSignal.timeout(5_000)), valid('busy'))
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
