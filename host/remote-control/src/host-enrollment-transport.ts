import { createHash, createPublicKey, randomUUID, verify, type KeyObject } from 'node:crypto'
import { isIP } from 'node:net'
import { z } from 'zod'
import { parseSigningObject } from './canonical.js'
import { hostEnrollmentOwnerBinding, type HostResourceAccessProvider, type HostResourceIdentity, type HostResourceRequest } from './host-credentials.js'
import type { HostHandshakeSigner } from './relay-client.js'

type Code = 'invalid_config' | 'cancelled' | 'identity_changed' | 'expired' | 'proof_invalid' | 'denied' | 'conflict' | 'unavailable' | 'response_invalid' | 'review_required' | 'declined' | 'outcome_unknown' | 'busy'
export class HostEnrollmentError extends Error {
  readonly code: `host.enrollment.${Code}`
  constructor(code: `host.enrollment.${Code}`) {
    const allowed: Code[] = ['invalid_config', 'cancelled', 'identity_changed', 'expired', 'proof_invalid', 'denied', 'conflict', 'unavailable', 'response_invalid', 'review_required', 'declined', 'outcome_unknown', 'busy']
    const safe = allowed.some(value => code === `host.enrollment.${value}`) ? code : 'host.enrollment.unavailable'
    super(safe); this.code = safe; this.name = 'HostEnrollmentError'
  }
}
export const enrollmentError = (code: Code) => new HostEnrollmentError(`host.enrollment.${code}`)

const secret = z.string().regex(/^[A-Za-z0-9_-]{43}$/).refine(value => Buffer.from(value, 'base64url').toString('base64url') === value)
const text = z.string().min(1).max(2048).refine(value => value === value.trim() && !/[\x00-\x1f\x7f]/.test(value))
const identity = z.strictObject({ issuer: text, subject: text, audience: text, clientId: text })
const publicKey = z.strictObject({ kty: z.literal('EC'), crv: z.literal('P-256'), x: secret, y: secret })
const access = identity.extend({ token: z.string().min(1).max(16 * 1024).regex(/^[A-Za-z0-9._~+/-]+={0,2}$/),
  tokenType: z.literal('DPoP'), proofKeyThumbprint: secret, expiresAt: z.number().safe(), scopes: z.array(text).min(1).max(64) }).strict()
const failure = z.strictObject({ ok: z.literal(false), error: z.strictObject({ code: text }) })
const uuid = '[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'
const reviewPath = new RegExp(`^/v1/enrollments/${uuid}/host-review$`)
const confirmPath = new RegExp(`^/v1/enrollments/${uuid}/host-confirm$`)
const inspect = Symbol.for('nodejs.util.inspect.custom')

export interface HostEnrollmentTransportOptions {
  origin: string
  identity: HostResourceIdentity
  publicJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string }
  signer: HostHandshakeSigner
  account: HostResourceAccessProvider
  requiredScopes: readonly string[]
  allowLoopbackHttp?: boolean
}

export function enrollmentAbortable<T>(task: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const cancelled = () => { signal.removeEventListener('abort', cancelled); reject(enrollmentError('cancelled')) }
    signal.addEventListener('abort', cancelled, { once: true })
    task.then(value => { signal.removeEventListener('abort', cancelled); resolve(value) }, cause => {
      signal.removeEventListener('abort', cancelled); reject(cause instanceof HostEnrollmentError ? new HostEnrollmentError(cause.code) : enrollmentError('unavailable'))
    })
    if (signal.aborted) cancelled()
  })
}

function originFor(value: string, loopback: boolean): string {
  const url = new URL(value)
  const host = url.hostname.replace(/^\[|\]$/g, '')
  const local = host === '::1' || isIP(host) === 4 && host.startsWith('127.')
  if (value !== value.trim() || /[\x00-\x20\x7f]/.test(value) || url.username || url.password || url.search || url.hash ||
      url.pathname !== '/' || url.protocol !== 'https:' && !(loopback && local && url.protocol === 'http:')) throw enrollmentError('invalid_config')
  return url.origin
}

/** Internal transport for the three enrollment routes, never an arbitrary RPC. */
export class HostEnrollmentTransport {
  readonly origin: string
  readonly signal: AbortSignal
  readonly thumbprint: string
  readonly binding: string
  readonly publicJwk: z.infer<typeof publicKey>
  readonly identity: HostResourceIdentity
  #closed = new AbortController()
  #key: KeyObject
  #signer: HostHandshakeSigner
  #account: HostResourceAccessProvider
  #request: Readonly<HostResourceRequest>
  #scopes: readonly string[]
  #active = 0

  constructor(options: HostEnrollmentTransportOptions) {
    try {
      this.origin = originFor(options.origin, options.allowLoopbackHttp === true)
      this.identity = Object.freeze(identity.parse(options.identity))
      this.publicJwk = Object.freeze(publicKey.parse(options.publicJwk))
      this.#key = createPublicKey({ key: this.publicJwk, format: 'jwk' })
      this.thumbprint = createHash('sha256').update(JSON.stringify({ crv: this.publicJwk.crv, kty: this.publicJwk.kty, x: this.publicJwk.x, y: this.publicJwk.y })).digest('base64url')
      const scopes = z.array(text).min(1).max(32).parse(options.requiredScopes)
      if (new Set(scopes).size !== scopes.length || scopes.some(scope => /\s/.test(scope)) ||
          typeof options.signer?.sign !== 'function' || typeof options.account?.acquire !== 'function' || !(options.account.signal instanceof AbortSignal)) throw enrollmentError('invalid_config')
      this.#scopes = Object.freeze(scopes)
      this.binding = hostEnrollmentOwnerBinding(this.origin, this.identity, this.thumbprint, this.#scopes)
      this.#signer = Object.freeze({ sign: options.signer.sign.bind(options.signer) })
      this.#account = Object.freeze({ signal: options.account.signal, acquire: options.account.acquire.bind(options.account) })
      this.#request = Object.freeze({ ...this.identity, origin: this.origin, proofKeyThumbprint: this.thumbprint, requiredScopes: this.#scopes })
      this.signal = AbortSignal.any([this.#closed.signal, this.#account.signal])
      Object.freeze(this)
    } catch { throw enrollmentError('invalid_config') }
  }

  toString(): string { return 'HostEnrollmentTransport' }
  toJSON(): string { return this.toString() }
  [inspect](): string { return this.toString() }
  close(): void { this.#closed.abort() }
  current(signal: AbortSignal): void { if (signal.aborted || this.signal.aborted) throw enrollmentError('cancelled') }

  async request(method: 'GET' | 'POST', path: string, body: object | undefined, expectedStatus: 200 | 201, caller: AbortSignal): Promise<unknown> {
    if (!(caller instanceof AbortSignal) || !(method === 'POST' && (path === '/v1/enrollments' || confirmPath.test(path)) || method === 'GET' && reviewPath.test(path)) ||
        (method === 'GET' ? body !== undefined || expectedStatus !== 200 : !body || expectedStatus !== (path === '/v1/enrollments' ? 201 : 200))) throw enrollmentError('invalid_config')
    if (this.#active >= 8) throw enrollmentError('unavailable')
    let encodedBody: string | undefined
    try { encodedBody = body === undefined ? undefined : JSON.stringify(body) }
    catch { throw enrollmentError('invalid_config') }
    if (body !== undefined && (typeof encodedBody !== 'string' || Buffer.byteLength(encodedBody) > 16 * 1024)) throw enrollmentError('invalid_config')
    this.#active++
    try {
      const lifetime = AbortSignal.any([caller, this.signal, AbortSignal.timeout(15_000)])
      this.current(lifetime)
      let session: z.infer<typeof access>
      try { session = access.parse(await enrollmentAbortable(this.#account.acquire(this.#request, lifetime), lifetime)) }
      catch (cause) { if (cause instanceof HostEnrollmentError) throw new HostEnrollmentError(cause.code); throw enrollmentError('identity_changed') }
      this.current(lifetime)
      if (Object.entries(this.identity).some(([name, expected]) => session[name as keyof HostResourceIdentity] !== expected) ||
          session.proofKeyThumbprint !== this.thumbprint || !this.#scopes.every(scope => session.scopes.includes(scope))) throw enrollmentError('identity_changed')
      const remaining = session.expiresAt - Date.now()
      if (remaining < 1000 || remaining > 900_000) throw enrollmentError('expired')
      const signal = AbortSignal.any([lifetime, AbortSignal.timeout(remaining)])
      const url = this.origin + path
      let nonce = ''
      // Each operation owns its nonce, so concurrent review and confirmation do
      // not race over one mutable one-use proof. Only a pre-handler challenge is retried.
      for (let attempt = 0; attempt < 2; attempt++) {
        this.current(signal)
        const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: this.publicJwk }
        const claims = { htm: method, htu: url, ath: createHash('sha256').update(session.token).digest('base64url'),
          iat: Math.floor(Date.now() / 1000), jti: randomUUID(), ...(nonce ? { nonce } : {}) }
        const input = [header, claims].map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.')
        let signed: Uint8Array
        try { signed = Buffer.from(await enrollmentAbortable(Promise.resolve(this.#signer.sign(Buffer.from(input))), signal)) }
        catch (cause) { if (signal.aborted || this.signal.aborted) throw enrollmentError('cancelled'); throw enrollmentError('proof_invalid') }
        this.current(signal)
        if (signed.length !== 64 || !verify('sha256', Buffer.from(input), { key: this.#key, dsaEncoding: 'ieee-p1363' }, signed)) throw enrollmentError('proof_invalid')
        let response: Response
        try {
          response = await fetch(url, { method, ...(encodedBody === undefined ? {} : { body: encodedBody }), headers: {
            authorization: `DPoP ${session.token}`, dpop: `${input}.${Buffer.from(signed).toString('base64url')}`,
            ...(body === undefined ? {} : { 'content-type': 'application/json' }), accept: 'application/json', 'accept-encoding': 'identity', 'cache-control': 'no-store',
          }, signal, credentials: 'omit', redirect: 'error', cache: 'no-store' })
        } catch {
          if (method === 'POST') throw enrollmentError('outcome_unknown')
          this.current(signal); throw enrollmentError('unavailable')
        }
        let value: unknown
        try { value = await this.#read(response, signal); this.current(signal) }
        catch (cause) { if (method === 'POST') throw enrollmentError('outcome_unknown'); throw cause }
        const next = response.headers.get('dpop-nonce')
        if (next !== null && !secret.safeParse(next).success) throw enrollmentError(method === 'POST' ? 'outcome_unknown' : 'response_invalid')
        if (response.status === 401 && attempt === 0 && /^DPoP error="use_dpop_nonce"$/i.test(response.headers.get('www-authenticate') ?? '') &&
            next && failure.safeParse(value).success && failure.parse(value).error.code === 'auth.proof_invalid') { nonce = next; continue }
        if (response.status !== expectedStatus) throw enrollmentError(response.status === 401 || response.status === 403 ? 'denied' : response.status === 409 ? 'conflict' : method === 'POST' && response.status >= 500 ? 'outcome_unknown' : 'unavailable')
        if (!next) throw enrollmentError(method === 'POST' ? 'outcome_unknown' : 'response_invalid')
        return value
      }
      throw enrollmentError('denied')
    } finally { this.#active-- }
  }

  async #read(response: Response, signal: AbortSignal): Promise<unknown> {
    const length = response.headers.get('content-length')
    if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('content-type') ?? '') ||
        !(response.headers.get('cache-control') ?? '').toLowerCase().split(',').map(value => value.trim()).includes('no-store') ||
        !['', 'identity'].includes(response.headers.get('content-encoding') ?? '') ||
        length !== null && (!/^\d{1,8}$/.test(length) || Number(length) > 16 * 1024) || !response.body) {
      void response.body?.cancel().catch(() => {})
      throw enrollmentError('response_invalid')
    }
    const reader = response.body.getReader(), chunks: Uint8Array[] = []
    let size = 0
    try {
      for (;;) {
        const next = await enrollmentAbortable(reader.read(), signal)
        this.current(signal)
        if (next.done) break
        size += next.value.byteLength
        if (size > 16 * 1024) throw enrollmentError('response_invalid')
        chunks.push(next.value)
      }
      return parseSigningObject(Buffer.concat(chunks, size))
    } catch (cause) { throw cause instanceof HostEnrollmentError ? cause : enrollmentError('response_invalid') }
    finally { void reader.cancel().catch(() => {}); reader.releaseLock() }
  }
}
