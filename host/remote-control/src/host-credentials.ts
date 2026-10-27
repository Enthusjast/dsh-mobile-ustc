import { createHash, createPublicKey, randomUUID, verify, type KeyObject } from 'node:crypto'
import { isIP } from 'node:net'
import { z } from 'zod'
import { parseSigningObject } from './canonical.js'
import type { HostConnectionCredential, HostCredentialProvider, HostHandshakeSigner } from './relay-client.js'

const inspect = Symbol.for('nodejs.util.inspect.custom')
const audience = 'urn:dsh-mobile-ustc:host-credential'
const maxBody = 16 * 1024
const secret = z.string().regex(/^[A-Za-z0-9_-]{43}$/).refine(value => Buffer.from(value, 'base64url').toString('base64url') === value)
const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
const text = z.string().min(1).max(2048).refine(value => value === value.trim() && !/[\x00-\x1f\x7f]/.test(value))
const identity = z.strictObject({ issuer: text, subject: text, audience: text, clientId: text })
const publicKey = z.strictObject({ kty: z.literal('EC'), crv: z.literal('P-256'), x: secret, y: secret })
const access = identity.extend({ token: z.string().min(1).max(16 * 1024).regex(/^[A-Za-z0-9._~+/-]+={0,2}$/),
  tokenType: z.literal('DPoP'), proofKeyThumbprint: secret, expiresAt: z.number().safe(), scopes: z.array(text).min(1).max(64) }).strict()
const challenge = z.strictObject({ ok: z.literal(true), data: z.strictObject({ challenge_id: uuid, challenge: secret,
  installation_id: uuid, audience: z.literal(audience), expires_at: z.string().datetime({ offset: true }) }) })
const issued = z.strictObject({ ok: z.literal(true), data: z.strictObject({ credential: secret, token_type: z.literal('DSH-Host'),
  installation_id: uuid, key_thumbprint: secret, expires_at: z.string().datetime({ offset: true }) }) })
const failure = z.strictObject({ ok: z.literal(false), error: z.strictObject({ code: text }) })

export interface HostResourceIdentity { issuer: string; subject: string; audience: string; clientId: string }
export interface HostResourceAccess extends HostResourceIdentity {
  token: string
  tokenType: 'DPoP'
  proofKeyThumbprint: string
  /** Verified effective resource-token expiry, Unix milliseconds. */
  expiresAt: number
  scopes: string[]
}
export interface HostResourceRequest extends HostResourceIdentity {
  origin: string
  proofKeyThumbprint: string
  requiredScopes: readonly string[]
}
/** The existing login adapter verifies the resource token and owns refresh. Its
 * lifetime MUST end on logout/account/key change, including while acquire waits. */
export interface HostResourceAccessProvider {
  readonly signal: AbortSignal
  acquire(request: Readonly<HostResourceRequest>, signal: AbortSignal): Promise<HostResourceAccess>
}
export interface HostRestCredentialOptions {
  origin: string
  installationId: string
  identity: HostResourceIdentity
  publicJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string }
  signer: HostHandshakeSigner
  account: HostResourceAccessProvider
  requiredScopes: readonly string[]
  allowLoopbackHttp?: boolean
}

type Code = 'invalid_config' | 'cancelled' | 'identity_changed' | 'expired' | 'proof_invalid' | 'denied' | 'unavailable' | 'response_invalid'
export class HostCredentialError extends Error {
  readonly code: `host.credentials.${Code}`
  constructor(code: `host.credentials.${Code}`) {
    const allowed: Code[] = ['invalid_config', 'cancelled', 'identity_changed', 'expired', 'proof_invalid', 'denied', 'unavailable', 'response_invalid']
    const safe = allowed.some(value => code === `host.credentials.${value}`) ? code : 'host.credentials.unavailable'
    super(safe); this.code = safe; this.name = 'HostCredentialError'
  }
}
const error = (code: Code) => new HostCredentialError(`host.credentials.${code}`)

function abortable<T>(task: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const cancelled = () => { signal.removeEventListener('abort', cancelled); reject(error('cancelled')) }
    signal.addEventListener('abort', cancelled, { once: true })
    task.then(value => { signal.removeEventListener('abort', cancelled); resolve(value) }, cause => { signal.removeEventListener('abort', cancelled); reject(cause instanceof HostCredentialError ? cause : error('unavailable')) })
    if (signal.aborted) cancelled()
  })
}

function originFor(value: string, loopback: boolean): string {
  const url = new URL(value)
  const host = url.hostname.replace(/^\[|\]$/g, '')
  const local = host === '::1' || isIP(host) === 4 && host.startsWith('127.')
  if (value !== value.trim() || /[\x00-\x20\x7f]/.test(value) || url.username || url.password || url.search || url.hash
    || url.pathname !== '/' || url.protocol !== 'https:' && !(loopback && local && url.protocol === 'http:')) throw error('invalid_config')
  return url.origin
}

function deadline(expiry: string, maximum: number): () => number {
  const wall = Date.now(), monotonic = performance.now()
  const remaining = Date.parse(expiry) - wall
  if (!Number.isFinite(remaining) || remaining <= 0 || remaining > maximum + 30_000) throw error('response_invalid')
  const duration = Math.min(remaining, maximum)
  return () => {
    const now = Date.now(), elapsed = performance.now() - monotonic
    if (!Number.isFinite(now) || !Number.isFinite(elapsed) || now < wall || elapsed < 0) return 0
    return Math.max(0, Math.min(duration - (now - wall), duration - elapsed))
  }
}

class BoundCredential implements HostConnectionCredential {
  #value: string
  #current: () => void
  constructor(readonly installationId: string, readonly signer: HostHandshakeSigner, value: string, current: () => void) { this.#value = value; this.#current = current }
  get credential(): string { this.#current(); return this.#value }
  toString(): string { return 'HostConnectionCredential' }
  toJSON(): string { return this.toString() }
  [inspect](): string { return this.toString() }
}
interface Cached { credential: HostConnectionCredential; remaining(): number }
interface Flight { task: Promise<HostConnectionCredential>; cancel: AbortController; waiters: number }

/** Resource/installation-bound REST acquisition. No login UI, enrollment, key
 * generation, OAuth refresh implementation, disk storage or automatic POST replay. */
export class HostRestCredentialProvider implements HostCredentialProvider {
  readonly origin: string
  readonly signal: AbortSignal
  #closed = new AbortController()
  #options: HostRestCredentialOptions
  #key: KeyObject
  #jwk: z.infer<typeof publicKey>
  #thumbprint: string
  #request: Readonly<HostResourceRequest>
  #nonce = ''
  #cache: Cached | undefined
  #flight: Flight | undefined

  constructor(options: HostRestCredentialOptions) {
    try {
      this.origin = originFor(options.origin, options.allowLoopbackHttp === true)
      const expected = identity.parse(options.identity)
      this.#jwk = Object.freeze(publicKey.parse(options.publicJwk))
      this.#key = createPublicKey({ key: this.#jwk, format: 'jwk' })
      this.#thumbprint = createHash('sha256').update(JSON.stringify({ crv: this.#jwk.crv, kty: this.#jwk.kty, x: this.#jwk.x, y: this.#jwk.y })).digest('base64url')
      const scopes = z.array(text).min(1).max(32).parse(options.requiredScopes)
      if (new Set(scopes).size !== scopes.length || scopes.some(scope => /\s/.test(scope)) || !uuid.safeParse(options.installationId).success
        || typeof options.signer?.sign !== 'function' || typeof options.account?.acquire !== 'function' || !(options.account.signal instanceof AbortSignal)) throw error('invalid_config')
      this.#options = { origin: this.origin, installationId: options.installationId, identity: Object.freeze(expected), publicJwk: this.#jwk,
        signer: Object.freeze({ sign: options.signer.sign.bind(options.signer) }), account: Object.freeze({ signal: options.account.signal, acquire: options.account.acquire.bind(options.account) }), requiredScopes: Object.freeze(scopes) }
      this.#request = Object.freeze({ ...expected, origin: this.origin, proofKeyThumbprint: this.#thumbprint, requiredScopes: this.#options.requiredScopes })
      this.signal = AbortSignal.any([this.#closed.signal, options.account.signal])
      this.signal.addEventListener('abort', () => { this.#cache = undefined; this.#nonce = ''; this.#flight?.cancel.abort() }, { once: true })
      Object.freeze(this)
    } catch { throw error('invalid_config') }
  }

  toString(): string { return 'HostRestCredentialProvider' }
  toJSON(): string { return this.toString() }
  [inspect](): string { return this.toString() }
  close(): void { this.#closed.abort(); this.#cache = undefined; this.#nonce = '' }

  #current(signal: AbortSignal): void { if (signal.aborted || this.signal.aborted) throw error('cancelled') }

  async acquire(signal: AbortSignal): Promise<HostConnectionCredential> {
    this.#current(signal)
    if (this.#cache && this.#cache.remaining() > 30_000) return this.#cache.credential
    let flight = this.#flight
    if (!flight) {
      flight = { cancel: new AbortController(), waiters: 0, task: Promise.resolve(undefined as never) }
      this.#flight = flight
      const owned = flight
      const lifetime = AbortSignal.any([this.signal, owned.cancel.signal, AbortSignal.timeout(15_000)])
      owned.task = Promise.resolve().then(() => this.#mint(lifetime)).then(value => {
        this.#current(lifetime)
        if (this.#flight !== owned) throw error('cancelled')
        this.#cache = value
        return value.credential
      }).catch(cause => { throw cause instanceof HostCredentialError ? cause : error('unavailable') }).finally(() => {
        if (this.#flight === owned) this.#flight = undefined
      })
    }
    flight.waiters++
    try { return await abortable(flight.task, AbortSignal.any([signal, this.signal])) }
    finally {
      flight.waiters--
      if (flight.waiters === 0 && this.#flight === flight) { flight.cancel.abort(); this.#flight = undefined }
    }
  }

  async #sign(input: Uint8Array, signal: AbortSignal): Promise<Uint8Array> {
    signal = AbortSignal.any([signal, this.signal, AbortSignal.timeout(15_000)])
    this.#current(signal)
    const bytes = Buffer.from(input)
    if (bytes.length > 16 * 1024) throw error('proof_invalid')
    let signature: Uint8Array
    try { signature = Buffer.from(await abortable(Promise.resolve(this.#options.signer.sign(Uint8Array.from(bytes))), signal)) }
    catch (cause) { if (signal.aborted || this.signal.aborted) throw error('cancelled'); throw error('proof_invalid') }
    this.#current(signal)
    if (signature.byteLength !== 64 || !verify('sha256', bytes, { key: this.#key, dsaEncoding: 'ieee-p1363' }, signature)) throw error('proof_invalid')
    return signature
  }

  async #jws(header: object, claims: object, signal: AbortSignal): Promise<string> {
    const input = [header, claims].map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.')
    return `${input}.${Buffer.from(await this.#sign(Buffer.from(input), signal)).toString('base64url')}`
  }

  async #mint(signal: AbortSignal): Promise<Cached> {
    this.#current(signal)
    const session = access.parse(await abortable(this.#options.account.acquire(this.#request, signal), signal))
    this.#current(signal)
    if (Object.entries(this.#options.identity).some(([name, expected]) => session[name as keyof HostResourceIdentity] !== expected)
      || session.proofKeyThumbprint !== this.#thumbprint || !this.#options.requiredScopes.every(scope => session.scopes.includes(scope))) throw error('identity_changed')
    const resourceRemaining = session.expiresAt - Date.now()
    if (resourceRemaining < 1000 || resourceRemaining > 900_000) throw error('expired')
    const authorized = AbortSignal.any([signal, AbortSignal.timeout(resourceRemaining)])
    const response = challenge.parse(await this.#post('/v1/host-credentials/challenges', {}, session.token, authorized)).data
    if (response.installation_id !== this.#options.installationId) throw error('identity_changed')
    const remaining = deadline(response.expires_at, 90_000)
    if (remaining() <= 0) throw error('expired')
    const proof = await this.#jws({ alg: 'ES256', typ: 'dsh-host-credential-proof+jwt' }, {
      iss: response.installation_id, aud: audience, challenge_id: response.challenge_id, nonce: response.challenge, iat: Math.floor(Date.now() / 1000), jti: randomUUID(),
    }, authorized)
    if (remaining() <= 0) throw error('expired')
    const result = issued.parse(await this.#post('/v1/host-credentials', { challenge_id: response.challenge_id, proof }, session.token, authorized)).data
    this.#current(authorized)
    if (result.installation_id !== this.#options.installationId || result.key_thumbprint !== this.#thumbprint) throw error('identity_changed')
    const credentialRemaining = deadline(result.expires_at, 300_000)
    const current = () => { this.#current(this.signal); if (credentialRemaining() <= 0) throw error('expired') }
    const signer = Object.freeze({ sign: async (input: Uint8Array) => { current(); const signed = await this.#sign(input, this.signal); current(); return signed } })
    return { credential: Object.freeze(new BoundCredential(result.installation_id, signer, result.credential, current)), remaining: credentialRemaining }
  }

  async #post(path: string, body: object, token: string, signal: AbortSignal): Promise<unknown> {
    const url = this.origin + path
    for (let attempt = 0; attempt < 2; attempt++) {
      this.#current(signal)
      const dpop = await this.#jws({ alg: 'ES256', typ: 'dpop+jwt', jwk: this.#jwk }, {
        htm: 'POST', htu: url, ath: createHash('sha256').update(token).digest('base64url'), iat: Math.floor(Date.now() / 1000), jti: randomUUID(), ...(this.#nonce ? { nonce: this.#nonce } : {}),
      }, signal)
      this.#current(signal)
      let response: Response
      try { response = await fetch(url, { method: 'POST', body: JSON.stringify(body), headers: {
        authorization: `DPoP ${token}`, dpop, 'content-type': 'application/json', accept: 'application/json', 'accept-encoding': 'identity', 'cache-control': 'no-store',
      }, signal, credentials: 'omit', redirect: 'error', cache: 'no-store' }) }
      catch { this.#nonce = ''; this.#current(signal); throw error('unavailable') }
      const value = await this.#read(response, signal)
      this.#current(signal)
      const nonce = response.headers.get('dpop-nonce')
      if (nonce !== null && !secret.safeParse(nonce).success) throw error('response_invalid')
      if (response.status === 401 && attempt === 0 && /^DPoP error="use_dpop_nonce"$/i.test(response.headers.get('www-authenticate') ?? '')
        && nonce && failure.safeParse(value).success && failure.parse(value).error.code === 'auth.proof_invalid') {
        this.#nonce = nonce
        continue // This exact middleware challenge precedes the operation; all other POST outcomes are final/unknown.
      }
      if (response.status !== 201) { this.#nonce = ''; throw error(response.status === 401 || response.status === 403 ? 'denied' : 'unavailable') }
      if (!nonce) throw error('response_invalid')
      this.#nonce = nonce
      return value
    }
    throw error('denied')
  }

  async #read(response: Response, signal: AbortSignal): Promise<unknown> {
    const length = response.headers.get('content-length')
    if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('content-type') ?? '')
      || !(response.headers.get('cache-control') ?? '').toLowerCase().split(',').map(value => value.trim()).includes('no-store')
      || !['', 'identity'].includes(response.headers.get('content-encoding') ?? '')
      || length !== null && (!/^\d{1,8}$/.test(length) || Number(length) > maxBody) || !response.body) {
      void response.body?.cancel().catch(() => {})
      throw error('response_invalid')
    }
    const reader = response.body.getReader(), chunks: Uint8Array[] = []
    let size = 0
    try {
      for (;;) {
        const next = await abortable(reader.read(), signal)
        this.#current(signal)
        if (next.done) break
        size += next.value.byteLength
        if (size > maxBody) throw error('response_invalid')
        chunks.push(next.value)
      }
      return parseSigningObject(Buffer.concat(chunks, size))
    } catch (cause) { throw cause instanceof HostCredentialError ? cause : error('response_invalid') }
    finally { void reader.cancel().catch(() => {}); reader.releaseLock() }
  }
}
