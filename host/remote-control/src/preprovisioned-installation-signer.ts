import { createPrivateKey, createPublicKey, sign, timingSafeEqual } from 'node:crypto'
import { inspect } from 'node:util'
import type { HostHandshakeSigner } from './relay-client.js'
import { decodeSecretBase64 } from './linux-secret-service.js'

export interface InstallationPublicJwk { kty: 'EC'; crv: 'P-256'; x: string; y: string }

const unavailable = () => new Error('installation public key unavailable')
const COORDINATE = /^[A-Za-z0-9_-]{43}$/

function publicKey(value: InstallationPublicJwk): InstallationPublicJwk {
  if (!value || Object.keys(value).sort().join(',') !== 'crv,kty,x,y') throw unavailable()
  const { kty, crv, x: encodedX, y: encodedY } = value
  if (kty !== 'EC' || crv !== 'P-256' || typeof encodedX !== 'string' || !COORDINATE.test(encodedX) ||
      typeof encodedY !== 'string' || !COORDINATE.test(encodedY)) throw unavailable()
  const x = Buffer.from(encodedX, 'base64url'), y = Buffer.from(encodedY, 'base64url')
  if (x.length !== 32 || y.length !== 32 || x.toString('base64url') !== encodedX || y.toString('base64url') !== encodedY) throw unavailable()
  const result = Object.freeze({ kty: 'EC' as const, crv: 'P-256' as const, x: encodedX, y: encodedY })
  createPublicKey({ key: result, format: 'jwk' })
  return result
}

/** Signs with a preprovisioned PKCS#8 P-256 key, looked up for each operation.
 * It never creates, replaces, persists or returns the installation private key. */
export class PreprovisionedInstallationSigner implements HostHandshakeSigner {
  #lookup: { lookup(maxOutput: number, signal: AbortSignal): Promise<Buffer> }
  #publicJwk: InstallationPublicJwk
  #ownerSignal: AbortSignal
  #closed = new AbortController()
  #active = 0

  #typeName: string
  #reason: string
  constructor(options: { lookup: { lookup(maxOutput: number, signal: AbortSignal): Promise<Buffer> };
    publicJwk: InstallationPublicJwk; ownerSignal: AbortSignal; typeName: string; reason: string }) {
    this.#typeName = options.typeName; this.#reason = options.reason
    try {
      this.#lookup = options.lookup
      this.#publicJwk = publicKey(options.publicJwk)
      if (!(options.ownerSignal instanceof AbortSignal)) throw unavailable()
      this.#ownerSignal = options.ownerSignal
      Object.freeze(this)
    } catch { throw this.#unavailable() }
  }
  #unavailable(): Error { return new Error(this.#reason) }

  toString(): string { return this.#typeName }
  toJSON(): string { return this.toString() }
  [inspect.custom](): string { return this.toString() }
  close(): void { this.#closed.abort() }

  async sign(signingInput: Uint8Array): Promise<Uint8Array> {
    if (!(signingInput instanceof Uint8Array) || signingInput.length < 1 || signingInput.length > 16 * 1024 ||
        this.#closed.signal.aborted || this.#ownerSignal.aborted || this.#active >= 8) throw this.#unavailable()
    const input = Buffer.from(signingInput)
    const signal = AbortSignal.any([this.#closed.signal, this.#ownerSignal, AbortSignal.timeout(5_000)])
    let encoded: Buffer | undefined, der: Buffer | undefined, canonical: Buffer | undefined
    this.#active++
    try {
      encoded = await this.#lookup.lookup(2048, signal)
      if (signal.aborted) throw this.#unavailable()
      der = decodeSecretBase64(encoded, 1024)
      const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
      if (privateKey.asymmetricKeyType !== 'ec' || privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw this.#unavailable()
      canonical = privateKey.export({ format: 'der', type: 'pkcs8' })
      if (canonical.length !== der.length || !timingSafeEqual(canonical, der)) throw this.#unavailable()
      const actual = createPublicKey(privateKey).export({ format: 'jwk' })
      if (actual.kty !== this.#publicJwk.kty || actual.crv !== this.#publicJwk.crv || actual.x !== this.#publicJwk.x || actual.y !== this.#publicJwk.y) throw this.#unavailable()
      const signature = sign('sha256', input, { key: privateKey, dsaEncoding: 'ieee-p1363' })
      if (signal.aborted) { signature.fill(0); throw this.#unavailable() }
      return signature
    } catch { throw this.#unavailable() }
    finally { input.fill(0); encoded?.fill(0); der?.fill(0); canonical?.fill(0); this.#active-- }
  }
}
