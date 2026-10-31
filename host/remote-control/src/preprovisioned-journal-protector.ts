import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto'
import { inspect } from 'node:util'
import type { JournalKeyProtector } from './journal-key-protection.js'
import { decodeSecretBase64 } from './linux-secret-service.js'

function subkey(master: Buffer, salt: Uint8Array, domain: string): Buffer {
  return createHmac('sha256', master).update(domain).update(salt).digest()
}

/** Internal envelope; platform factories supply only validated read-only references. */
export class PreprovisionedJournalProtector implements JournalKeyProtector {
  readonly id: string
  #lookup: { lookup(maxOutput: number, signal: AbortSignal): Promise<Buffer> }
  #magic: Buffer
  #domain: string
  #typeName: string
  #reason: string
  constructor(options: { id: string; magic: string; domain: string; typeName: string; reason: string;
    lookup: { lookup(maxOutput: number, signal: AbortSignal): Promise<Buffer> } }) {
    this.id = options.id; this.#magic = Buffer.from(options.magic); this.#domain = options.domain
    this.#typeName = options.typeName; this.#reason = options.reason; this.#lookup = options.lookup
  }
  #unavailable(): Error { return new Error(this.#reason) }

  async #master(signal: AbortSignal): Promise<Buffer> {
    const encoded = await this.#lookup.lookup(128, signal)
    try {
      const master = decodeSecretBase64(encoded, 32)
      if (master.length !== 32) { master.fill(0); throw this.#unavailable() }
      return master
    } finally { encoded.fill(0) }
  }

  toString(): string { return this.#typeName }
  [inspect.custom](): string { return this.toString() }
  toJSON(): object { return { type: this.#typeName, id: this.id } }

  async wrap(key: Uint8Array, context: Uint8Array, signal: AbortSignal): Promise<Uint8Array> {
    if (!(key instanceof Uint8Array) || key.length !== 32 || !(context instanceof Uint8Array) || context.length === 0 || context.length > 16 * 1024 || !(signal instanceof AbortSignal)) throw this.#unavailable()
    const keyCopy = Buffer.from(key), contextCopy = Buffer.from(context)
    let master: Buffer | undefined, derived: Buffer | undefined, aad: Buffer | undefined
    try {
      master = await this.#master(signal)
      if (signal.aborted) throw this.#unavailable()
      const salt = randomBytes(32), nonce = randomBytes(12)
      const header = Buffer.concat([this.#magic, salt, nonce])
      derived = subkey(master, salt, this.#domain)
      aad = Buffer.concat([contextCopy, header])
      const cipher = createCipheriv('aes-256-gcm', derived, nonce)
      cipher.setAAD(aad)
      const ciphertext = Buffer.concat([cipher.update(keyCopy), cipher.final()])
      return Buffer.concat([header, ciphertext, cipher.getAuthTag()])
    } catch { throw this.#unavailable() }
    finally { keyCopy.fill(0); contextCopy.fill(0); master?.fill(0); derived?.fill(0); aad?.fill(0) }
  }

  async unwrap(wrapped: Uint8Array, context: Uint8Array, signal: AbortSignal): Promise<Uint8Array> {
    if (!(wrapped instanceof Uint8Array) || wrapped.length !== 100 || !(context instanceof Uint8Array) || context.length === 0 || context.length > 16 * 1024 || !(signal instanceof AbortSignal)) throw this.#unavailable()
    const raw = Buffer.from(wrapped), contextCopy = Buffer.from(context)
    let master: Buffer | undefined, derived: Buffer | undefined, aad: Buffer | undefined
    let partial: Buffer | undefined, final: Buffer | undefined
    try {
      if (!raw.subarray(0, 8).equals(this.#magic)) throw this.#unavailable()
      master = await this.#master(signal)
      if (signal.aborted) throw this.#unavailable()
      derived = subkey(master, raw.subarray(8, 40), this.#domain)
      aad = Buffer.concat([contextCopy, raw.subarray(0, 52)])
      const decipher = createDecipheriv('aes-256-gcm', derived, raw.subarray(40, 52))
      decipher.setAAD(aad)
      decipher.setAuthTag(raw.subarray(84, 100))
      // GCM update emits plaintext before final verifies the authentication
      // tag. Clear it on both success and failure, including a bad tag.
      partial = decipher.update(raw.subarray(52, 84))
      final = decipher.final()
      const key = Buffer.concat([partial, final])
      if (key.length !== 32 || signal.aborted) { key.fill(0); throw this.#unavailable() }
      return key
    } catch { throw this.#unavailable() }
    finally { raw.fill(0); contextCopy.fill(0); master?.fill(0); derived?.fill(0); aad?.fill(0); partial?.fill(0); final?.fill(0) }
  }
}
