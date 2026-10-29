import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto'
import { isIP } from 'node:net'
import { z } from 'zod'
import { parseSigningObject } from './canonical.js'
import type { HostResourceAccess, HostResourceAccessProvider, HostResourceIdentity, HostResourceRequest } from './host-credentials.js'

type Code = 'invalid_config' | 'cancelled' | 'busy' | 'unavailable' | 'invalid_token'
export class HostResourceJwtError extends Error {
  readonly code: `host.resource_jwt.${Code}`
  constructor(code: `host.resource_jwt.${Code}`) {
    const allowed: Code[] = ['invalid_config', 'cancelled', 'busy', 'unavailable', 'invalid_token']
    const safe = allowed.some(value => code === `host.resource_jwt.${value}`) ? code : 'host.resource_jwt.unavailable'
    super(safe); this.code = safe; this.name = 'HostResourceJwtError'
  }
}
const fail = (code: Code = 'invalid_token') => new HostResourceJwtError(`host.resource_jwt.${code}`)
const inspect = Symbol.for('nodejs.util.inspect.custom')
const text = z.string().min(1).max(2048).refine(value => value === value.trim() && !/[\x00-\x1f\x7f]/.test(value))
const scope = z.string().min(1).max(2048).regex(/^[\x21\x23-\x5b\x5d-\x7e]+$/)
const digest = z.string().regex(/^[A-Za-z0-9_-]{43}$/).refine(value => Buffer.from(value, 'base64url').toString('base64url') === value)
const identitySchema = z.strictObject({ issuer: text, subject: text, audience: text, clientId: text })
const publicKey = z.strictObject({ kty: z.literal('EC'), crv: z.literal('P-256'), x: digest, y: digest })
const requestSchema = identitySchema.extend({ origin: text, proofKeyThumbprint: digest, requiredScopes: z.array(scope).min(1).max(32) }).strict()
const tokenSourceValue = z.strictObject({ token: z.string().min(1).max(16 * 1024), tokenType: z.literal('DPoP') })
const MAX_JWKS = 128 * 1024

/** An existing login integration owns token acquisition, refresh and logout. */
export interface HostResourceTokenSource {
  readonly signal: AbortSignal
  acquire(signal: AbortSignal): Promise<{ token: string; tokenType: 'DPoP' }>
}
export interface HostResourceJwtOptions {
  origin: string
  identity: HostResourceIdentity
  publicJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string }
  requiredScopes: readonly string[]
  /** Explicit trusted issuer signing-key endpoint; token headers cannot select it. */
  jwksUrl: string
  source: HostResourceTokenSource
  /** Allows only literal loopback HTTP origins and key endpoints for local fixtures. */
  allowLoopbackHttp?: boolean
}

type Algorithm = 'ES256' | 'RS256'
type IssuerKey = { algorithm: Algorithm; key: KeyObject }
type KeyCache = { keys: Map<string, IssuerKey>; wall: number; monotonic: number; ttl: number }

function urlFor(value: string, loopback: boolean, origin: boolean): string {
  if (typeof value !== 'string' || value !== value.trim() || /[\x00-\x20\x7f]/.test(value)) throw fail('invalid_config')
  const url = new URL(value), host = url.hostname.replace(/^\[|\]$/g, '')
  const local = host === '::1' || isIP(host) === 4 && host.startsWith('127.')
  if (url.username || url.password || url.search || url.hash || (origin && url.pathname !== '/') ||
      url.protocol !== 'https:' && !(loopback && local && url.protocol === 'http:')) throw fail('invalid_config')
  return origin ? url.origin : url.href
}

function abortable<T>(task: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const cancelled = () => { signal.removeEventListener('abort', cancelled); reject(fail('cancelled')) }
    signal.addEventListener('abort', cancelled, { once: true })
    task.then(value => { signal.removeEventListener('abort', cancelled); resolve(value) }, cause => {
      signal.removeEventListener('abort', cancelled); reject(cause instanceof HostResourceJwtError ? new HostResourceJwtError(cause.code) : fail('unavailable'))
    })
    if (signal.aborted) cancelled()
  })
}

function bytes(value: unknown, minimum: number, maximum: number): Buffer {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw fail()
  const result = Buffer.from(value, 'base64url')
  if (result.length < minimum || result.length > maximum || result.toString('base64url') !== value) throw fail()
  return result
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw fail()
  return value as Record<string, unknown>
}

function issuerKey(value: unknown): { id: string; value: IssuerKey } | undefined {
  const row = object(value)
  for (const name of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'jku', 'x5u']) if (Object.hasOwn(row, name)) throw fail('unavailable')
  if (row.use !== undefined && row.use !== 'sig') throw fail('unavailable')
  if (row.key_ops !== undefined && (!Array.isArray(row.key_ops) || row.key_ops.length !== 1 || row.key_ops[0] !== 'verify')) throw fail('unavailable')
  if (row.kid === undefined || row.kid === '') return undefined
  if (typeof row.kid !== 'string' || row.kid.length > 256 || /[\x00-\x1f\x7f]/.test(row.kid)) throw fail('unavailable')
  let algorithm: Algorithm, key: KeyObject
  if (row.kty === 'EC' && row.crv === 'P-256') {
    bytes(row.x, 32, 32); bytes(row.y, 32, 32)
    algorithm = 'ES256'
    key = createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', x: row.x as string, y: row.y as string } })
  } else if (row.kty === 'RSA') {
    bytes(row.n, 256, 1024); const encodedExponent = bytes(row.e, 1, 4), exponent = encodedExponent.readUIntBE(0, encodedExponent.length)
    if (exponent < 3 || exponent % 2 === 0) throw fail('unavailable')
    algorithm = 'RS256'
    key = createPublicKey({ format: 'jwk', key: { kty: 'RSA', n: row.n as string, e: row.e as string } })
    if (!key.asymmetricKeyDetails?.modulusLength || key.asymmetricKeyDetails.modulusLength < 2048) throw fail('unavailable')
  } else throw fail('unavailable')
  if (row.alg !== undefined && row.alg !== algorithm) throw fail('unavailable')
  return { id: row.kid, value: { algorithm, key } }
}

function compact(value: string): { header: Record<string, unknown>; claims: Record<string, unknown>; input: Buffer; signature: Buffer } {
  const parts = value.split('.')
  if (parts.length !== 3) throw fail()
  const header = parseSigningObject(bytes(parts[0], 1, 16 * 1024))
  const claims = parseSigningObject(bytes(parts[1], 1, 16 * 1024))
  const signature = bytes(parts[2], 1, 1024)
  return { header, claims, input: Buffer.from(`${parts[0]}.${parts[1]}`), signature }
}

function numericDate(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || Math.abs(value) > 1e12) throw fail()
  const result = Math.floor(value * 1000)
  if (!Number.isSafeInteger(result)) throw fail()
  return result
}

class VerifiedAccess implements HostResourceAccess {
  #token: string
  #signal: AbortSignal
  #wall: number
  #monotonic: number
  readonly scopes: string[]
  constructor(readonly issuer: string, readonly subject: string, readonly audience: string, readonly clientId: string,
    readonly proofKeyThumbprint: string, readonly expiresAt: number, scopes: string[], token: string, signal: AbortSignal,
    wall: number, monotonic: number) {
    this.#token = token; this.#signal = signal; this.#wall = wall; this.#monotonic = monotonic
    this.scopes = Object.freeze([...scopes]) as string[]; Object.freeze(this)
  }
  readonly tokenType = 'DPoP' as const
  get token(): string {
    if (this.#signal.aborted || Date.now() < this.#wall || performance.now() < this.#monotonic ||
        Date.now() >= this.expiresAt || performance.now() - this.#monotonic >= this.expiresAt - this.#wall) throw fail('cancelled')
    return this.#token
  }
  toString(): string { return 'HostResourceAccess' }
  toJSON(): string { return this.toString() }
  [inspect](): string { return this.toString() }
}

/** Validate existing DPoP-bound resource JWTs against one explicitly trusted JWKS.
 * This is not an OAuth login, Discovery, token exchange or refresh implementation. */
export class HostResourceJwtProvider implements HostResourceAccessProvider {
  readonly signal: AbortSignal
  #closed = new AbortController()
  #origin: string
  #identity: HostResourceIdentity
  #thumbprint: string
  #scopes: readonly string[]
  #url: string
  #source: HostResourceTokenSource
  #cache: KeyCache | undefined
  #flight: Promise<KeyCache> | undefined
  #unknownAfter = 0
  #active = 0

  constructor(options: HostResourceJwtOptions) {
    try {
      const loopback = options.allowLoopbackHttp === true
      this.#origin = urlFor(options.origin, loopback, true)
      this.#identity = Object.freeze(identitySchema.parse(options.identity))
      urlFor(this.#identity.issuer, loopback, false)
      this.#url = urlFor(options.jwksUrl, loopback, false)
      const jwk = publicKey.parse(options.publicJwk)
      createPublicKey({ format: 'jwk', key: jwk })
      this.#thumbprint = createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest('base64url')
      const scopes = z.array(scope).min(1).max(32).parse(options.requiredScopes)
      if (new Set(scopes).size !== scopes.length || typeof options.source?.acquire !== 'function' || !(options.source.signal instanceof AbortSignal)) throw fail('invalid_config')
      this.#scopes = Object.freeze(scopes)
      this.#source = Object.freeze({ signal: options.source.signal, acquire: options.source.acquire.bind(options.source) })
      this.signal = AbortSignal.any([this.#closed.signal, this.#source.signal])
      this.signal.addEventListener('abort', () => { this.#cache = undefined }, { once: true })
      Object.freeze(this)
    } catch { throw fail('invalid_config') }
  }

  toString(): string { return 'HostResourceJwtProvider' }
  toJSON(): string { return this.toString() }
  [inspect](): string { return this.toString() }
  close(): void { this.#closed.abort(); this.#cache = undefined }

  async acquire(source: Readonly<HostResourceRequest>, caller: AbortSignal): Promise<HostResourceAccess> {
    if (!(caller instanceof AbortSignal)) throw fail('invalid_config')
    if (caller.aborted || this.signal.aborted) throw fail('cancelled')
    if (this.#active >= 8) throw fail('busy')
    this.#active++
    const lifetime = AbortSignal.any([caller, this.signal, AbortSignal.timeout(15_000)])
    try {
      const request = requestSchema.parse(source)
      if (request.origin !== this.#origin || request.proofKeyThumbprint !== this.#thumbprint ||
          Object.entries(this.#identity).some(([name, expected]) => request[name as keyof HostResourceIdentity] !== expected) ||
          request.requiredScopes.length !== this.#scopes.length || new Set(request.requiredScopes).size !== this.#scopes.length ||
          request.requiredScopes.some(item => !this.#scopes.includes(item))) throw fail('invalid_config')
      const sourceValue = tokenSourceValue.parse(await abortable(Promise.resolve().then(() => {
        if (lifetime.aborted) throw fail('cancelled')
        return this.#source.acquire(lifetime)
      }), lifetime))
      if (lifetime.aborted) throw fail('cancelled')
      const parsed = compact(sourceValue.token), { header, claims } = parsed
      if (typeof header.typ !== 'string' || !['at+jwt', 'application/at+jwt'].includes(header.typ.toLowerCase()) ||
          header.alg !== 'ES256' && header.alg !== 'RS256' || typeof header.kid !== 'string' || !header.kid || header.kid.length > 256 ||
          /[\x00-\x1f\x7f]/.test(header.kid) || ['jku', 'x5u', 'jwk', 'x5c', 'crit', 'b64'].some(name => Object.hasOwn(header, name))) throw fail()
      const now = Date.now(), monotonic = performance.now(), issued = numericDate(claims.iat), expires = numericDate(claims.exp)
      const audiences = typeof claims.aud === 'string' ? [claims.aud] : Array.isArray(claims.aud) ? claims.aud : []
      const cnf = object(claims.cnf)
      if (claims.iss !== this.#identity.issuer || claims.sub !== this.#identity.subject || claims.client_id !== this.#identity.clientId ||
          typeof claims.jti !== 'string' || !text.safeParse(claims.jti).success || !audiences.every(item => typeof item === 'string') ||
          !audiences.includes(this.#identity.audience) || cnf.jkt !== this.#thumbprint || issued > now + 30_000 ||
          expires <= now + 1_000 || expires > now + 900_000 || expires <= issued || expires - issued > 900_000 ||
          claims.nbf !== undefined && numericDate(claims.nbf) > now + 30_000) throw fail()
      if (typeof claims.scope !== 'string') throw fail()
      const scopes = claims.scope.split(' ')
      if (scopes.length > 64 || new Set(scopes).size !== scopes.length || scopes.some(item => !scope.safeParse(item).success) ||
          this.#scopes.some(item => !scopes.includes(item))) throw fail()
      const key = await this.#keyFor(header.kid, lifetime)
      if (lifetime.aborted) throw fail('cancelled')
      if (key.algorithm !== header.alg || header.alg === 'ES256' && parsed.signature.length !== 64 ||
          !verify('sha256', parsed.input, header.alg === 'ES256' ? { key: key.key, dsaEncoding: 'ieee-p1363' } : key.key, parsed.signature)) throw fail()
      // Fetching keys may have taken long enough for the token to expire.
      if (Date.now() < now || performance.now() < monotonic || expires <= Date.now() + 1_000 ||
          performance.now() - monotonic >= expires - now - 1_000) throw fail()
      return new VerifiedAccess(this.#identity.issuer, this.#identity.subject, this.#identity.audience, this.#identity.clientId,
        this.#thumbprint, expires, scopes, sourceValue.token, this.signal, now, monotonic)
    } catch (cause) {
      if (cause instanceof HostResourceJwtError) throw new HostResourceJwtError(cause.code)
      if (lifetime.aborted) throw fail('cancelled')
      throw fail()
    } finally { this.#active-- }
  }

  async #keyFor(id: string, signal: AbortSignal): Promise<IssuerKey> {
    const cache = this.#cache, now = Date.now(), monotonic = performance.now()
    const fresh = cache && now >= cache.wall && monotonic >= cache.monotonic && now - cache.wall < cache.ttl && monotonic - cache.monotonic < cache.ttl
    if (!fresh && (!cache || !cache.keys.has(id)) && monotonic < this.#unknownAfter) throw fail()
    let current = fresh ? cache : await this.#refresh(signal)
    let key = current.keys.get(id)
    if (!key && fresh && monotonic >= this.#unknownAfter) {
      this.#unknownAfter = monotonic + 5_000
      current = await this.#refresh(signal); key = current.keys.get(id)
    }
    if (!key) { if (!fresh) this.#unknownAfter = performance.now() + 5_000; throw fail() }
    return key
  }

  async #refresh(signal: AbortSignal): Promise<KeyCache> {
    if (!this.#flight) {
      const task = this.#fetchKeys().then(value => {
        if (this.signal.aborted) throw fail('cancelled')
        this.#cache = value.ttl > 0 ? value : undefined
        return value
      }).finally(() => { if (this.#flight === task) this.#flight = undefined })
      this.#flight = task
    }
    return await abortable(this.#flight, signal)
  }

  async #fetchKeys(): Promise<KeyCache> {
    const signal = AbortSignal.any([this.signal, AbortSignal.timeout(5_000)])
    let response: Response | undefined
    try {
      response = await fetch(this.#url, { method: 'GET', headers: { accept: 'application/json', 'accept-encoding': 'identity' },
        redirect: 'error', credentials: 'omit', cache: 'no-store', signal })
      const kind = response.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase()
      const encoding = response.headers.get('content-encoding')?.trim().toLowerCase()
      const length = response.headers.get('content-length')
      if (response.status !== 200 || !['application/json', 'application/jwk-set+json'].includes(kind ?? '') ||
          encoding && encoding !== 'identity' || length && (!/^\d+$/.test(length) || Number(length) > MAX_JWKS) || !response.body) throw fail('unavailable')
      const reader = response.body.getReader(), chunks: Uint8Array[] = []
      let total = 0
      try {
        for (;;) {
          const part = await reader.read()
          if (part.done) break
          total += part.value.length
          if (total > MAX_JWKS) throw fail('unavailable')
          chunks.push(part.value)
        }
      } finally { void reader.cancel().catch(() => {}); reader.releaseLock() }
      if (signal.aborted) throw fail('cancelled')
      const document = parseSigningObject(Buffer.concat(chunks)), keys = new Map<string, IssuerKey>()
      if (!Array.isArray(document.keys) || document.keys.length < 1 || document.keys.length > 32) throw fail('unavailable')
      for (const raw of document.keys) {
        const item = issuerKey(raw)
        if (!item) continue
        if (keys.has(item.id)) throw fail('unavailable')
        keys.set(item.id, item.value)
      }
      if (!keys.size) throw fail('unavailable')
      const control = response.headers.get('cache-control') ?? ''
      const maxAge = /(?:^|,)\s*max-age\s*=\s*(\d+)\s*(?:,|$)/i.exec(control)
      const ttl = /(?:^|,)\s*(?:no-cache|no-store)\s*(?:,|$)/i.test(control) ? 0 : Math.min(60_000, maxAge ? Number(maxAge[1]) * 1000 : 60_000)
      return { keys, wall: Date.now(), monotonic: performance.now(), ttl }
    } catch (cause) {
      if (this.signal.aborted) throw fail('cancelled')
      if (cause instanceof HostResourceJwtError && cause.code === 'host.resource_jwt.cancelled') throw fail('unavailable')
      throw fail('unavailable')
    } finally { void response?.body?.cancel().catch(() => {}) }
  }
}
