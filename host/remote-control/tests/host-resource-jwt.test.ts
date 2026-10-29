import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign, type KeyObject } from 'node:crypto'
import { createServer, type ServerResponse } from 'node:http'
import { inspect } from 'node:util'
import { HostResourceJwtError, HostResourceJwtProvider, type HostResourceJwtOptions } from '../src/host-resource-jwt.js'
import type { HostResourceRequest } from '../src/host-credentials.js'

const identity = { issuer: 'https://issuer.example.edu', subject: 'fixture-owner', audience: 'urn:remote', clientId: 'fixture-host' }
const hash = (value: string) => createHash('sha256').update(value).digest('base64url')
const b64 = (value: string) => Buffer.from(value).toString('base64url')
const denied = (code: string) => (cause: unknown) => cause instanceof HostResourceJwtError && cause.code === `host.resource_jwt.${code}`

function token(key: KeyObject, header: object | string, claims: object | string, algorithm: 'ES256' | 'RS256' = 'ES256'): string {
  const input = [header, claims].map(value => b64(typeof value === 'string' ? value : JSON.stringify(value))).join('.')
  const signature = sign('sha256', Buffer.from(input), algorithm === 'ES256' ? { key, dsaEncoding: 'ieee-p1363' } : key)
  return `${input}.${signature.toString('base64url')}`
}

async function fixture(t: test.TestContext) {
  const installation = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const publicJwk = installation.publicKey.export({ format: 'jwk' }) as HostResourceJwtOptions['publicJwk']
  const thumbprint = hash(JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y }))
  const issuerKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), sourceOwner = new AbortController()
  const issuerJwk = { ...issuerKey.publicKey.export({ format: 'jwk' }), kid: 'issuer-a', alg: 'ES256', use: 'sig' }
  const state = { keys: [issuerJwk] as object[], token: '', tokenType: 'DPoP' as string, requests: 0, acquisitions: 0,
    reply: undefined as undefined | ((response: ServerResponse) => void), acquire: undefined as undefined | ((signal: AbortSignal) => Promise<unknown>) }
  const server = createServer((request, response) => {
    state.requests++
    assert.equal(request.method, 'GET'); assert.equal(request.url, '/jwks')
    assert.equal(request.headers.authorization, undefined); assert.equal(request.headers.cookie, undefined)
    if (state.reply) { state.reply(response); return }
    response.setHeader('content-type', 'application/json'); response.end(JSON.stringify({ keys: state.keys }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address(); assert.ok(address && typeof address === 'object')
  const jwksUrl = `http://127.0.0.1:${address.port}/jwks`, origin = 'http://127.0.0.1:4321'
  const options: HostResourceJwtOptions = { origin, identity, publicJwk, requiredScopes: ['remote.access'], jwksUrl, allowLoopbackHttp: true,
    source: { signal: sourceOwner.signal, async acquire(signal) {
      state.acquisitions++
      return state.acquire ? await state.acquire(signal) as { token: string; tokenType: 'DPoP' } : { token: state.token, tokenType: state.tokenType as 'DPoP' }
    } } }
  const provider = new HostResourceJwtProvider(options)
  const request: HostResourceRequest = { ...identity, origin, proofKeyThumbprint: thumbprint, requiredScopes: ['remote.access'] }
  const claims = () => {
    const now = Math.floor(Date.now() / 1000)
    return { iss: identity.issuer, sub: identity.subject, aud: [identity.audience, 'urn:other'], client_id: identity.clientId,
      jti: randomUUID(), iat: now, exp: now + 300, scope: 'remote.access another.scope', cnf: { jkt: thumbprint } }
  }
  const issue = (patch: Record<string, unknown> = {}, header: Record<string, unknown> = {}, key = issuerKey.privateKey) =>
    token(key, { typ: 'at+jwt', alg: 'ES256', kid: 'issuer-a', ...header }, { ...claims(), ...patch })
  state.token = issue()
  t.after(async () => { provider.close(); sourceOwner.abort(); server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())) })
  return { provider, options, request, state, sourceOwner, issuerKey, issuerJwk, thumbprint, claims, issue }
}

test('verified resource JWTs are bound to the configured account, audience, scopes and installation key', async t => {
  const f = await fixture(t), signal = AbortSignal.timeout(5_000)
  const sessions = await Promise.all(Array.from({ length: 4 }, () => f.provider.acquire(f.request, signal)))
  assert.equal(f.state.requests, 1); assert.equal(f.state.acquisitions, 4)
  const result = sessions[0]!
  assert.equal(result.token, f.state.token); assert.equal(result.tokenType, 'DPoP')
  assert.equal(result.proofKeyThumbprint, f.thumbprint); assert.deepEqual(result.scopes, ['remote.access', 'another.scope'])
  assert.ok(result.expiresAt > Date.now()); assert.equal(Object.isFrozen(result), true); assert.equal(Object.isFrozen(result.scopes), true)
  for (const printed of [String(f.provider), inspect(f.provider), JSON.stringify(f.provider), inspect(result), JSON.stringify(result), JSON.stringify({ ...result })]) {
    assert.equal(printed.includes(f.state.token), false)
  }
  f.sourceOwner.abort()
  assert.throws(() => result.token, denied('cancelled'))
  await assert.rejects(f.provider.acquire(f.request, signal), denied('cancelled'))
})

test('resource JWT verification rejects incorrect claims, signatures and ambiguous JSON', async t => {
  const f = await fixture(t), signal = AbortSignal.timeout(5_000)
  await f.provider.acquire(f.request, signal)
  const originalRequests = f.state.requests, now = Math.floor(Date.now() / 1000)
  const wrongKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const tokens = [
    f.issue({ iss: 'https://wrong.example.edu' }), f.issue({ sub: 'wrong-user' }), f.issue({ aud: 'urn:other' }),
    f.issue({ client_id: 'wrong-client' }), f.issue({ cnf: { jkt: randomBytes(32).toString('base64url') } }),
    f.issue({ scope: 'another.scope' }), f.issue({ scope: 'remote.access  another.scope' }), f.issue({ jti: '' }),
    f.issue({ iat: now + 60 }), f.issue({ exp: now - 1 }), f.issue({ exp: now + 901 }), f.issue({ nbf: now + 60 }),
    f.issue({}, { typ: 'JWT' }), f.issue({}, { jku: 'https://attacker.example/jwks' }), f.issue({}, { crit: ['x'] }),
    f.issue({}, {}, wrongKey.privateKey), `${f.state.token}.extra`,
    token(f.issuerKey.privateKey, '{"alg":"ES256","alg":"ES256","typ":"at+jwt","kid":"issuer-a"}', f.claims()),
    token(f.issuerKey.privateKey, { alg: 'ES256', typ: 'at+jwt', kid: 'issuer-a' },
      JSON.stringify(f.claims()).replace('"sub":"fixture-owner"', '"sub":"fixture-owner","sub":"fixture-owner"')),
  ]
  for (const value of tokens) {
    f.state.token = value
    await assert.rejects(f.provider.acquire(f.request, signal), denied('invalid_token'))
  }
  assert.equal(f.state.requests, originalRequests, 'untrusted JWT data selected a different key endpoint')
  f.state.token = f.issue(); f.state.tokenType = 'Bearer'
  await assert.rejects(f.provider.acquire(f.request, signal), denied('invalid_token'))
})

test('RSA signatures and issuer key rotation work without accepting unknown keys or unbounded refresh', async t => {
  const f = await fixture(t), signal = AbortSignal.timeout(5_000)
  await f.provider.acquire(f.request, signal)
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 })
  f.state.keys.push({ ...rsa.publicKey.export({ format: 'jwk' }), kid: 'issuer-b', alg: 'RS256', use: 'sig' })
  f.state.token = token(rsa.privateKey, { alg: 'RS256', typ: 'application/at+jwt', kid: 'issuer-b' }, f.claims(), 'RS256')
  assert.equal((await f.provider.acquire(f.request, signal)).token, f.state.token)
  assert.equal(f.state.requests, 2)
  // The successful unknown-key refresh also rate limits subsequent unknown IDs.
  for (let index = 0; index < 4; index++) {
    f.state.token = f.issue({}, { kid: `unknown-${index}` })
    await assert.rejects(f.provider.acquire(f.request, signal), denied('invalid_token'))
  }
  assert.equal(f.state.requests, 2)
})

test('no-store key sets are fetched again and unknown identifiers remain rate limited', async t => {
  const f = await fixture(t), signal = AbortSignal.timeout(5_000)
  f.state.reply = response => {
    response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' })
    response.end(JSON.stringify({ keys: f.state.keys }))
  }
  await f.provider.acquire(f.request, signal); await f.provider.acquire(f.request, signal)
  assert.equal(f.state.requests, 2)
  const replacement = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  f.state.keys = [{ ...replacement.publicKey.export({ format: 'jwk' }), kid: 'issuer-a', alg: 'ES256', use: 'sig' }]
  f.state.token = f.issue({}, {}, replacement.privateKey)
  assert.equal((await f.provider.acquire(f.request, signal)).token, f.state.token)
  f.state.token = f.issue({}, { kid: 'unknown' })
  await assert.rejects(f.provider.acquire(f.request, signal), denied('invalid_token'))
  f.state.token = f.issue({}, { kid: 'another-unknown' })
  await assert.rejects(f.provider.acquire(f.request, signal), denied('invalid_token'))
  assert.equal(f.state.requests, 4)
})

test('untrusted key-set responses fail closed and cannot redirect verification', async t => {
  for (const mode of ['duplicate', 'private', 'content-type', 'large', 'redirect', 'json'] as const) await t.test(mode, async t => {
    const f = await fixture(t)
    if (mode === 'duplicate') f.state.keys = [f.issuerJwk, f.issuerJwk]
    if (mode === 'private') f.state.keys = [{ ...f.issuerJwk, d: randomBytes(32).toString('base64url') }]
    if (mode === 'content-type') f.state.reply = response => { response.setHeader('content-type', 'text/plain'); response.end('{}') }
    if (mode === 'large') f.state.reply = response => { response.setHeader('content-type', 'application/json'); response.end('x'.repeat(128 * 1024 + 1)) }
    if (mode === 'redirect') f.state.reply = response => { response.writeHead(302, { location: 'http://127.0.0.1:1/attacker' }); response.end() }
    if (mode === 'json') f.state.reply = response => { response.setHeader('content-type', 'application/json'); response.end('{"keys":[],"keys":[]}') }
    await assert.rejects(f.provider.acquire(f.request, AbortSignal.timeout(5_000)), denied('unavailable'))
    assert.equal(f.state.requests, 1)
  })
})

test('a caller cancellation cannot publish a late token or cancel another waiter', async t => {
  const f = await fixture(t)
  let release!: () => void, arrived!: () => void
  const entered = new Promise<void>(resolve => { arrived = resolve })
  f.state.reply = response => { arrived(); release = () => { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify({ keys: f.state.keys })) } }
  const abort = new AbortController()
  const first = f.provider.acquire(f.request, abort.signal)
  const second = f.provider.acquire(f.request, AbortSignal.timeout(5_000))
  await entered; abort.abort()
  await assert.rejects(first, denied('cancelled'))
  release()
  assert.equal((await second).token, f.state.token); assert.equal(f.state.requests, 1)

  let resume!: () => void
  f.state.acquire = async () => { await new Promise<void>(resolve => { resume = resolve }); return { token: f.state.token, tokenType: 'DPoP' } }
  const retiring = f.provider.acquire(f.request, AbortSignal.timeout(5_000))
  await new Promise(resolve => setImmediate(resolve))
  f.sourceOwner.abort()
  await assert.rejects(retiring, denied('cancelled'))
  resume(); await new Promise(resolve => setImmediate(resolve))
  assert.equal(f.state.requests, 1)
})

test('the provider bounds concurrent source acquisitions and retires them with their owner', async t => {
  const f = await fixture(t)
  const releases: Array<() => void> = []
  f.state.acquire = async () => { await new Promise<void>(resolve => { releases.push(resolve) }); return { token: f.state.token, tokenType: 'DPoP' } }
  const pending = Array.from({ length: 8 }, () => f.provider.acquire(f.request, AbortSignal.timeout(5_000)))
  await new Promise(resolve => setImmediate(resolve))
  await assert.rejects(f.provider.acquire(f.request, AbortSignal.timeout(5_000)), denied('busy'))
  f.sourceOwner.abort()
  await Promise.all(pending.map(value => assert.rejects(value, denied('cancelled'))))
  releases.forEach(release => release())
  assert.equal(f.state.requests, 0)
})

test('pinned requests and configuration are checked before reading a source token', async t => {
  const f = await fixture(t), signal = AbortSignal.timeout(5_000)
  for (const changed of [{ subject: 'other' }, { origin: 'http://127.0.0.1:1234' }, { proofKeyThumbprint: randomBytes(32).toString('base64url') },
    { requiredScopes: ['remote.access', 'remote.access'] }]) {
    await assert.rejects(f.provider.acquire({ ...f.request, ...changed }, signal), denied('invalid_config'))
  }
  assert.equal(f.state.acquisitions, 0); assert.equal(f.state.requests, 0)
  const early = new AbortController(), operation = f.provider.acquire(f.request, early.signal)
  early.abort(); await assert.rejects(operation, denied('cancelled'))
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(f.state.acquisitions, 0); assert.equal(f.state.requests, 0)
  for (const altered of [{ jwksUrl: 'http://example.edu/jwks' }, { jwksUrl: 'https://user:secret@example.edu/jwks' },
    { jwksUrl: 'https://example.edu/jwks?url=attacker' }, { allowLoopbackHttp: false }]) {
    assert.throws(() => new HostResourceJwtProvider({ ...f.options, ...altered }), denied('invalid_config'))
  }
})
