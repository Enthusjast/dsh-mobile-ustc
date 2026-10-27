import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from 'node:crypto'
import { createServer, type ServerResponse } from 'node:http'
import { createRequire } from 'node:module'
import { inspect } from 'node:util'
import { HostCredentialError, HostRestCredentialProvider, type HostResourceAccess, type HostRestCredentialOptions } from '../src/host-credentials.js'
import { startHostRelay } from '../src/relay-client.js'

const installationId = '88888888-8888-4888-8888-888888888888'
const expected = { issuer: 'https://id.example.edu', subject: 'fixture-owner', audience: 'urn:remote-host-fixture', clientId: 'fixture-host' }
const token = 'PRIVATE_REMOTE_RESOURCE_TOKEN'
const hash = (value: string) => createHash('sha256').update(value).digest('base64url')
const part = (value: string) => JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) as any
const nonce = () => randomBytes(32).toString('base64url')
const send = (response: ServerResponse, status: number, body: unknown, next = nonce()) => {
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'dpop-nonce': next })
  response.end(JSON.stringify(body))
}
type Hooks = {
  lifetime?: number
  session?: (value: HostResourceAccess, signal: AbortSignal) => Promise<HostResourceAccess>
  reply?: (path: string, response: ServerResponse, body: any) => boolean
  signing?: (input: Uint8Array, normal: (input: Uint8Array) => Uint8Array) => Uint8Array | Promise<Uint8Array>
  challengePatch?: Record<string, unknown>
  issuedPatch?: Record<string, unknown>
  exchangeNonceOnce?: boolean
}

async function fixture(t: test.TestContext, hooks: Hooks = {}) {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const jwk = keys.publicKey.export({ format: 'jwk' }) as HostRestCredentialOptions['publicJwk']
  const thumbprint = hash(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))
  const owner = new AbortController()
  const challenges = new Map<string, string>()
  const nonces = new Set<string>(), ids = new Set<string>()
  const requests: Array<{ path: string; proof: any; body: any; headers: Record<string, any> }> = []
  let origin = '', acquisitions = 0, challengeWrites = 0, exchangeWrites = 0, exchangeNonceSent = false
  const credentials: string[] = []
  const normalSign = (input: Uint8Array) => sign('sha256', Buffer.from(input), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' })
  const server = createServer(async (request, response) => {
    try {
      assert.equal(request.method, 'POST')
      assert.equal(request.headers.authorization, `DPoP ${token}`)
      assert.equal(request.headers.cookie, undefined)
      assert.equal(request.headers['cache-control'], 'no-store')
      const compact = String(request.headers.dpop), [header, payload, signature] = compact.split('.')
      const claims = part(payload!), protectedHeader = part(header!)
      assert.equal(protectedHeader.typ, 'dpop+jwt'); assert.deepEqual(protectedHeader.jwk, jwk)
      assert.equal(verify('sha256', Buffer.from(`${header}.${payload}`), { key: keys.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature!, 'base64url')), true)
      assert.equal(claims.htm, 'POST'); assert.equal(claims.htu, origin + request.url); assert.equal(claims.ath, hash(token))
      assert.ok(Math.abs(claims.iat - Math.floor(Date.now() / 1000)) < 2)
      assert.equal(ids.has(claims.jti), false); ids.add(claims.jti)
      const chunks: Buffer[] = []
      for await (const chunk of request) chunks.push(Buffer.from(chunk))
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'))
      requests.push({ path: request.url!, proof: claims, body, headers: request.headers })
      if (hooks.reply?.(request.url!, response, body)) return
      const exchangeNonce = hooks.exchangeNonceOnce && request.url === '/v1/host-credentials' && !exchangeNonceSent
      if (exchangeNonce) exchangeNonceSent = true
      if (exchangeNonce || !claims.nonce || !nonces.delete(claims.nonce)) {
        const next = nonce(); nonces.add(next)
        response.setHeader('www-authenticate', 'DPoP error="use_dpop_nonce"')
        send(response, 401, { ok: false, error: { code: 'auth.proof_invalid' } }, next)
        return
      }
      const next = nonce(); nonces.add(next)
      if (request.url === '/v1/host-credentials/challenges') {
        challengeWrites++
        const id = randomUUID(), value = nonce(); challenges.set(id, value)
        send(response, 201, { ok: true, data: { challenge_id: id, challenge: value, installation_id: installationId,
          audience: 'urn:dsh-mobile-ustc:host-credential', expires_at: new Date(Date.now() + 90_000).toISOString(), ...hooks.challengePatch } }, next)
      } else {
        assert.equal(request.url, '/v1/host-credentials')
        const [head, data, signature] = body.proof.split('.')
        assert.deepEqual(part(head), { alg: 'ES256', typ: 'dsh-host-credential-proof+jwt' })
        const proof = part(data)
        assert.deepEqual(Object.keys(proof).sort(), ['aud', 'challenge_id', 'iat', 'iss', 'jti', 'nonce'])
        assert.equal(proof.iss, installationId); assert.equal(proof.aud, 'urn:dsh-mobile-ustc:host-credential')
        assert.equal(proof.challenge_id, body.challenge_id); assert.equal(proof.nonce, challenges.get(body.challenge_id))
        assert.equal(verify('sha256', Buffer.from(`${head}.${data}`), { key: keys.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url')), true)
        challenges.delete(body.challenge_id)
        exchangeWrites++
        const credential = nonce(); credentials.push(credential)
        send(response, 201, { ok: true, data: { credential, token_type: 'DSH-Host', installation_id: installationId,
          key_thumbprint: thumbprint, expires_at: new Date(Date.now() + (hooks.lifetime ?? 300_000)).toISOString(), ...hooks.issuedPatch } }, next)
      }
    } catch (cause) { t.assert.fail(cause instanceof Error ? cause.message : 'fixture protocol failure'); response.destroy() }
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address(); assert.ok(address && typeof address === 'object')
  origin = `http://127.0.0.1:${address.port}`
  const options: HostRestCredentialOptions = { origin, installationId, identity: expected, publicJwk: jwk,
    requiredScopes: ['remote.access'], allowLoopbackHttp: true,
    signer: { sign: input => hooks.signing ? hooks.signing(input, normalSign) : normalSign(input) },
    account: { signal: owner.signal, async acquire(request, signal) {
      acquisitions++
      assert.deepEqual(request, { ...expected, origin, proofKeyThumbprint: thumbprint, requiredScopes: ['remote.access'] })
      assert.equal(Object.isFrozen(request), true); assert.equal(Object.isFrozen(request.requiredScopes), true)
      const value: HostResourceAccess = { ...expected, token, tokenType: 'DPoP', proofKeyThumbprint: thumbprint, expiresAt: Date.now() + 300_000, scopes: ['remote.access'] }
      return hooks.session ? hooks.session(value, signal) : value
    } },
  }
  const provider = new HostRestCredentialProvider(options)
  t.after(async () => { provider.close(); server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())) })
  return { provider, options, requests, owner, server, credentials, thumbprint, normalSign, publicKey: keys.publicKey,
    counts: () => ({ acquisitions, challengeWrites, exchangeWrites }) }
}

const denied = (code?: string) => (cause: unknown) => cause instanceof HostCredentialError && (!code || cause.code === `host.credentials.${code}`)

test('Host REST provider signs both purposes, serializes concurrent minting and reuses a valid bound credential', async t => {
  const f = await fixture(t)
  const values = await Promise.all(Array.from({ length: 4 }, () => f.provider.acquire(new AbortController().signal)))
  assert.ok(values.every(value => value === values[0]))
  assert.deepEqual(f.counts(), { acquisitions: 1, challengeWrites: 1, exchangeWrites: 1 })
  assert.equal(f.requests.length, 3, 'only the defined initial nonce challenge may repeat a POST')
  assert.equal(values[0]!.credential, f.credentials[0])
  const input = Buffer.from('private handshake signing input')
  assert.equal(verify('sha256', input, { key: f.publicKey, dsaEncoding: 'ieee-p1363' }, await values[0]!.signer.sign(input)), true)
  assert.equal((await f.provider.acquire(new AbortController().signal)).credential, f.credentials[0])
  for (const encoded of [String(f.provider), inspect(f.provider), JSON.stringify(f.provider), inspect(values[0]), JSON.stringify(values[0]), JSON.stringify({ ...values[0] })]) {
    for (const privateValue of [token, f.credentials[0]!, expected.subject, f.requests[2]!.body.proof]) assert.equal(encoded.includes(privateValue), false)
  }
  f.owner.abort(new Error('PRIVATE_ACCOUNT_CHANGE_REASON'))
  await assert.rejects(f.provider.acquire(new AbortController().signal), denied('cancelled'))
  assert.throws(() => values[0]!.credential, denied('cancelled'))
})

test('near-expiry Host credentials are replaced with a new challenge and new connection secret', async t => {
  const f = await fixture(t, { lifetime: 20_000 })
  const first = await f.provider.acquire(new AbortController().signal)
  const second = await f.provider.acquire(new AbortController().signal)
  assert.notEqual(first.credential, second.credential)
  assert.deepEqual(f.counts(), { acquisitions: 2, challengeWrites: 2, exchangeWrites: 2 })
  assert.notEqual(f.requests[2]!.body.challenge_id, f.requests[4]!.body.challenge_id)
})

test('one cancelled waiter cannot cancel another owner of the same Host credential request', async t => {
  let release!: () => void
  const held = new Promise<void>(resolve => { release = resolve })
  const f = await fixture(t, { async session(value) { await held; return value } })
  const first = new AbortController()
  const cancelled = f.provider.acquire(first.signal)
  const surviving = f.provider.acquire(new AbortController().signal)
  first.abort()
  await assert.rejects(cancelled, denied('cancelled'))
  release()
  assert.ok((await surviving).credential)
  assert.deepEqual(f.counts(), { acquisitions: 1, challengeWrites: 1, exchangeWrites: 1 })
})

test('cancelled/account-retired acquisition cannot use a late resource session', async t => {
  for (const retire of ['caller', 'account'] as const) await t.test(retire, async t => {
    let release!: () => void
    const held = new Promise<void>(resolve => { release = resolve })
    const f = await fixture(t, { async session(value) { await held; return value } })
    const caller = new AbortController()
    const pending = f.provider.acquire(caller.signal)
    await new Promise(resolve => setImmediate(resolve))
    if (retire === 'caller') caller.abort(); else f.owner.abort()
    await assert.rejects(pending, denied('cancelled'))
    release()
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(f.requests.length, 0)
  })
})

test('identity, DPoP key, audience, scopes and expired resource credentials fail before any HTTP write', async t => {
  for (const patch of [{ subject: 'different-owner' }, { issuer: 'https://other.example.edu' }, { audience: 'urn:model' },
    { clientId: 'phone' }, { proofKeyThumbprint: nonce() }, { scopes: ['model.access'] }, { expiresAt: 0 }, { tokenType: 'Bearer' }]) {
    await t.test(Object.keys(patch)[0]!, async t => {
      const f = await fixture(t, { async session(value) { return { ...value, ...patch } as HostResourceAccess } })
      await assert.rejects(f.provider.acquire(new AbortController().signal), denied())
      assert.equal(f.requests.length, 0)
    })
  }
})

test('wrong or mutated installation signing input is rejected locally', async t => {
  for (const mutate of [false, true]) await t.test(String(mutate), async t => {
    const f = await fixture(t, { signing(input, normal) { if (!mutate) return new Uint8Array(64); input[0] = input[0]! ^ 1; return normal(input) } })
    await assert.rejects(f.provider.acquire(new AbortController().signal), denied('proof_invalid'))
    assert.equal(f.requests.length, 0)
  })
})

test('only one explicit nonce challenge may repeat a request, with a new DPoP JTI', async t => {
  const f = await fixture(t, { reply(_path, response) {
    response.setHeader('www-authenticate', 'DPoP error="use_dpop_nonce"')
    send(response, 401, { ok: false, error: { code: 'auth.proof_invalid' } }); return true
  } })
  await assert.rejects(f.provider.acquire(new AbortController().signal), denied('denied'))
  assert.equal(f.requests.length, 2)
  assert.notEqual(f.requests[0]!.proof.jti, f.requests[1]!.proof.jti)
  assert.deepEqual(f.counts(), { acquisitions: 1, challengeWrites: 0, exchangeWrites: 0 })
})

test('a transport loss after exchange never automatically repeats its signed operation', async t => {
  let lost = false
  const f = await fixture(t, { reply(path, response) {
    if (path !== '/v1/host-credentials' || lost) return false
    lost = true; response.destroy(); return true
  } })
  await assert.rejects(f.provider.acquire(new AbortController().signal), denied('unavailable'))
  assert.equal(f.requests.filter(request => request.path === '/v1/host-credentials').length, 1)
  const original = f.requests.find(request => request.path === '/v1/host-credentials')!.body
  await f.provider.acquire(new AbortController().signal)
  const exchanges = f.requests.filter(request => request.path === '/v1/host-credentials')
  assert.equal(exchanges.length, 2)
  assert.notEqual(exchanges[1]!.body.challenge_id, original.challenge_id)
  assert.notEqual(exchanges[1]!.body.proof, original.proof)
})

test('HTTP failure text, redirects, oversized/duplicate/malformed JSON never leak or replay', async t => {
  let redirected = 0
  const target = createServer((_request, response) => { redirected++; response.end() })
  await new Promise<void>(resolve => target.listen(0, '127.0.0.1', resolve))
  const address = target.address(); assert.ok(address && typeof address === 'object')
  t.after(() => new Promise<void>(resolve => target.close(() => resolve())))
  for (const scenario of ['403', '500', 'nonce-auth-expired', 'redirect', 'oversized', 'duplicate', 'utf8', 'missing-store']) await t.test(scenario, async t => {
    const f = await fixture(t, { reply(_path, response) {
      response.setHeader('content-type', 'application/json'); response.setHeader('cache-control', 'no-store')
      response.setHeader('dpop-nonce', nonce())
      if (scenario === 'redirect') { response.writeHead(307, { location: `http://127.0.0.1:${address.port}/private` }); response.end(); return true }
      if (scenario === '403' || scenario === '500') { response.statusCode = Number(scenario); response.end(JSON.stringify({ ok: false, error: { code: 'PRIVATE_RESPONSE' } })); return true }
      if (scenario === 'nonce-auth-expired') { response.statusCode = 401; response.setHeader('www-authenticate', 'DPoP error="use_dpop_nonce"'); response.end('{"ok":false,"error":{"code":"auth.expired"}}'); return true }
      response.statusCode = 201
      if (scenario === 'missing-store') response.removeHeader('cache-control')
      response.end(scenario === 'oversized' ? 'x'.repeat(20 * 1024) : scenario === 'duplicate' ? '{"ok":true,"ok":false}' : scenario === 'utf8' ? Buffer.from([0xff]) : '{"ok":true}')
      return true
    } })
    await assert.rejects(f.provider.acquire(new AbortController().signal), cause => {
      assert.ok(cause instanceof HostCredentialError)
      assert.equal(inspect(cause).includes('PRIVATE_RESPONSE'), false)
      return true
    })
    assert.equal(f.requests.length, 1)
  })
  assert.equal(redirected, 0)
})

test('configuration rejects remote plaintext, selectors, userinfo and private key input', async t => {
  const f = await fixture(t)
  for (const patch of [{ origin: 'http://remote.example.edu' }, { origin: f.options.origin + '/path' }, { origin: f.options.origin + '?token=PRIVATE' },
    { origin: 'https://user:PRIVATE@remote.example.edu' }, { allowLoopbackHttp: false }, { publicJwk: { ...f.options.publicJwk, d: 'PRIVATE' } }]) {
    assert.throws(() => new HostRestCredentialProvider({ ...f.options, ...patch } as HostRestCredentialOptions), denied('invalid_config'))
  }
})

test('later mutable integration configuration cannot retarget the pinned identity, origin or signer', async t => {
  const f = await fixture(t, { lifetime: 20_000 })
  await f.provider.acquire(new AbortController().signal)
  assert.equal(Reflect.set(f.provider, 'origin', 'https://must-not-contact.example.invalid'), false)
  Object.assign(f.options, { origin: 'https://must-not-contact.example.invalid', installationId: randomUUID(), identity: { ...expected, subject: 'other' },
    publicJwk: { ...f.options.publicJwk, x: nonce() }, signer: { sign() { throw new Error('PRIVATE_REPLACED_SIGNER') } },
    requiredScopes: ['model.access'], account: { signal: new AbortController().signal, async acquire() { throw new Error('PRIVATE_REPLACED_ACCOUNT') } } })
  assert.equal((await f.provider.acquire(new AbortController().signal)).installationId, installationId)
  assert.deepEqual(f.counts(), { acquisitions: 2, challengeWrites: 2, exchangeWrites: 2 })
})

test('exchange nonce challenge is pre-operation only, preserves the pending proof and uses a fresh DPoP JTI', async t => {
  const f = await fixture(t, { exchangeNonceOnce: true })
  await f.provider.acquire(new AbortController().signal)
  const requests = f.requests.filter(request => request.path === '/v1/host-credentials')
  assert.equal(requests.length, 2)
  assert.deepEqual(requests[0]!.body, requests[1]!.body)
  assert.notEqual(requests[0]!.proof.jti, requests[1]!.proof.jti)
  assert.deepEqual(f.counts(), { acquisitions: 1, challengeWrites: 1, exchangeWrites: 1 })
})

test('challenge and issued credential must preserve exact installation, purpose, key, expiry and shape', async t => {
  const patches: Array<{ challengePatch?: Record<string, unknown>; issuedPatch?: Record<string, unknown> }> = [
    { challengePatch: { installation_id: randomUUID() } }, { challengePatch: { audience: 'urn:another-purpose' } },
    { challengePatch: { challenge: '_'.repeat(43) } }, { challengePatch: { expires_at: new Date(Date.now() - 1).toISOString() } },
    { challengePatch: { expires_at: new Date(Date.now() + 3_600_000).toISOString() } }, { challengePatch: { private_key: 'PRIVATE_BODY' } },
    { issuedPatch: { installation_id: randomUUID() } }, { issuedPatch: { key_thumbprint: nonce() } }, { issuedPatch: { token_type: 'Bearer' } },
    { issuedPatch: { credential: '_'.repeat(43) } }, { issuedPatch: { expires_at: new Date(Date.now() - 1).toISOString() } },
    { issuedPatch: { expires_at: new Date(Date.now() + 3_600_000).toISOString() } }, { issuedPatch: { private_key: 'PRIVATE_BODY' } },
  ]
  for (const [index, patch] of patches.entries()) await t.test(String(index), async t => {
    const f = await fixture(t, patch)
    for (let attempt = 0; attempt < 2; attempt++) await assert.rejects(f.provider.acquire(new AbortController().signal), cause => {
      assert.ok(cause instanceof HostCredentialError)
      assert.equal(inspect(cause).includes('PRIVATE_BODY'), false)
      return true
    })
    assert.equal(f.counts().challengeWrites, 2, 'failed/changed result populated a usable credential cache')
    if (patch.challengePatch) assert.equal(f.counts().exchangeWrites, 0, 'invalid challenge reached credential exchange')
  })
})

test('provider origin and account lifetime fence the actual authenticated Host socket', async t => {
  const f = await fixture(t)
  const runtimeId = randomUUID(), epoch = randomUUID()
  const runtime = { epoch, client: { runtimeId, async sessionCatalog() { return [] }, watchSessionCatalog() { return () => {} } }, async *follow() {}, async dispatch() { assert.fail('unused native operation') } }
  assert.throws(() => startHostRelay({ url: 'http://127.0.0.1:1', runtime, credentials: f.provider,
    dshVersion: '0.2.1-rc.2', applicationVersion: 'fixture', pluginVersion: 'test' }), /origin/)
  assert.equal(f.counts().acquisitions, 0)
  const ws = createRequire(import.meta.url)('ws') as { WebSocketServer: new (options: object) => any }
  const server = new ws.WebSocketServer({ server: f.server })
  let ready!: () => void, ended!: () => void
  const connected = new Promise<void>(resolve => { ready = resolve }), closed = new Promise<void>(resolve => { ended = resolve })
  server.on('connection', (socket: any, request: any) => {
    assert.equal(request.headers.authorization, `DSH-Host ${f.credentials[0]}`)
    const connectionId = randomUUID(), challengeId = randomUUID(), challengeNonce = nonce()
    socket.once('close', () => ended())
    socket.on('message', (raw: Buffer) => {
      const frame = JSON.parse(raw.toString('utf8'))
      if (frame.type !== 'hello.proof') return
      const [header, payload, signature] = frame.payload.proof.split('.')
      const proof = part(payload)
      assert.equal(verify('sha256', Buffer.from(`${header}.${payload}`), { key: f.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url')), true)
      assert.equal(proof.iss, installationId); assert.equal(proof.challenge_id, challengeId); assert.equal(proof.nonce, challengeNonce)
      assert.equal(part(header).typ, 'dsh-relay-handshake-proof+jwt')
      const now = Date.now()
      socket.send(JSON.stringify({ v: 1, type: 'hello.ok', payload: { role: 'host', connection_id: connectionId, installation_id: installationId,
        runtime_id: runtimeId, runtime_epoch: epoch, protocol_version: 1, protocols: [1], capabilities: ['command.relay.v1', 'connection.heartbeat.v1'],
        server_time: new Date(now).toISOString(), heartbeat_seconds: 20, max_frame_bytes: 65536, lease_expires_at: new Date(now + 60_000).toISOString() } }))
      ready()
    })
    socket.send(JSON.stringify({ v: 1, type: 'challenge', payload: { role: 'installation', connection_id: connectionId, challenge_id: challengeId,
      nonce: challengeNonce, expires_at: new Date(Date.now() + 10_000).toISOString() } }))
  })
  const relay = startHostRelay({ url: f.options.origin, runtime, credentials: f.provider, dshVersion: '0.2.1-rc.2', applicationVersion: 'fixture', pluginVersion: 'test' })
  t.after(async () => { await relay.close(); for (const socket of server.clients) socket.terminate(); await new Promise<void>(resolve => server.close(resolve)) })
  await connected
  f.owner.abort()
  await closed
  await relay.close()
  assert.deepEqual(f.counts(), { acquisitions: 1, challengeWrites: 1, exchangeWrites: 1 })
})
