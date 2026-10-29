import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto'
import { inspect } from 'node:util'
import type { JournalKeyProtector } from './journal-key-protection.js'
import { decodeSecretBase64, LinuxSecretServiceLookup, type LinuxSecretServiceReference } from './linux-secret-service.js'

export interface LinuxSecretServiceJournalOptions extends LinuxSecretServiceReference {
  /** Trusted absolute path to the system secret-tool executable. */
  executable: string
  /** Stable, non-secret lookup attributes for a preprovisioned 32-byte key. */
  service: string
  account: string
}

const MAGIC = Buffer.from('DSHSSK01')
const unavailable = () => new Error('journal Secret Service protection unavailable')

function subkey(master: Buffer, salt: Uint8Array): Buffer {
  return createHmac('sha256', master).update('dsh-secret-service-journal-wrap-v1\0').update(salt).digest()
}

/** Linux Secret Service adapter. It reads but never creates or replaces the
 * preprovisioned key, and passes no key material in command-line arguments. */
export class LinuxSecretServiceJournalProtector implements JournalKeyProtector {
  readonly id: string
  #lookup: LinuxSecretServiceLookup

  constructor(options: LinuxSecretServiceJournalOptions) {
    try {
      const reference = { executable: options.executable, service: options.service, account: options.account }
      this.#lookup = new LinuxSecretServiceLookup(reference)
      const digest = createHash('sha256').update('dsh-secret-service-reference-v1\0').update(reference.service).update('\0').update(reference.account).digest('hex')
      this.id = `secret-service-${digest.slice(0, 32)}`
    } catch { throw unavailable() }
  }

  async #master(signal: AbortSignal): Promise<Buffer> {
    const encoded = await this.#lookup.lookup(128, signal)
    try {
      const master = decodeSecretBase64(encoded, 32)
      if (master.length !== 32) { master.fill(0); throw unavailable() }
      return master
    } finally { encoded.fill(0) }
  }

  toString(): string { return 'LinuxSecretServiceJournalProtector' }
  [inspect.custom](): string { return this.toString() }
  toJSON(): object { return { type: 'LinuxSecretServiceJournalProtector', id: this.id } }

  async wrap(key: Uint8Array, context: Uint8Array, signal: AbortSignal): Promise<Uint8Array> {
    if (!(key instanceof Uint8Array) || key.length !== 32 || !(context instanceof Uint8Array) || context.length === 0 || context.length > 16 * 1024 || !(signal instanceof AbortSignal)) throw unavailable()
    const keyCopy = Buffer.from(key), contextCopy = Buffer.from(context)
    let master: Buffer | undefined, derived: Buffer | undefined, aad: Buffer | undefined
    try {
      master = await this.#master(signal)
      if (signal.aborted) throw unavailable()
      const salt = randomBytes(32), nonce = randomBytes(12)
      const header = Buffer.concat([MAGIC, salt, nonce])
      derived = subkey(master, salt)
      aad = Buffer.concat([contextCopy, header])
      const cipher = createCipheriv('aes-256-gcm', derived, nonce)
      cipher.setAAD(aad)
      const ciphertext = Buffer.concat([cipher.update(keyCopy), cipher.final()])
      return Buffer.concat([header, ciphertext, cipher.getAuthTag()])
    } catch { throw unavailable() }
    finally { keyCopy.fill(0); contextCopy.fill(0); master?.fill(0); derived?.fill(0); aad?.fill(0) }
  }

  async unwrap(wrapped: Uint8Array, context: Uint8Array, signal: AbortSignal): Promise<Uint8Array> {
    if (!(wrapped instanceof Uint8Array) || wrapped.length !== 100 || !(context instanceof Uint8Array) || context.length === 0 || context.length > 16 * 1024 || !(signal instanceof AbortSignal)) throw unavailable()
    const raw = Buffer.from(wrapped), contextCopy = Buffer.from(context)
    let master: Buffer | undefined, derived: Buffer | undefined, aad: Buffer | undefined
    let partial: Buffer | undefined, final: Buffer | undefined
    try {
      if (!raw.subarray(0, 8).equals(MAGIC)) throw unavailable()
      master = await this.#master(signal)
      if (signal.aborted) throw unavailable()
      derived = subkey(master, raw.subarray(8, 40))
      aad = Buffer.concat([contextCopy, raw.subarray(0, 52)])
      const decipher = createDecipheriv('aes-256-gcm', derived, raw.subarray(40, 52))
      decipher.setAAD(aad)
      decipher.setAuthTag(raw.subarray(84, 100))
      // GCM update emits plaintext before final verifies the authentication
      // tag. Clear it on both success and failure, including a bad tag.
      partial = decipher.update(raw.subarray(52, 84))
      final = decipher.final()
      const key = Buffer.concat([partial, final])
      if (key.length !== 32 || signal.aborted) { key.fill(0); throw unavailable() }
      return key
    } catch { throw unavailable() }
    finally { raw.fill(0); contextCopy.fill(0); master?.fill(0); derived?.fill(0); aad?.fill(0); partial?.fill(0); final?.fill(0) }
  }
}
