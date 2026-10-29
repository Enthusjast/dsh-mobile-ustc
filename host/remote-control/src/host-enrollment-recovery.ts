import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from 'node:crypto'
import { basename, dirname, isAbsolute, resolve } from 'node:path'
import { inspect } from 'node:util'
import { invoke, protectorFrom, type JournalKeyProtector, type Protector } from './journal-key-protection.js'
import { enrollmentRecoveryBinding, enrollmentRecoveryMatchesBinding, requireEnrollmentBindingOwner, type HostEnrollmentApprovalReview, type HostEnrollmentBinding, type HostEnrollmentClient, type HostEnrollmentConfirmation, type HostEnrollmentIntent, type HostEnrollmentReceipt } from './host-enrollment.js'
import type { HostEnrollmentBindingStore } from './host-enrollment-binding.js'
import { guards } from './host-process-guards.js'
import { assertLinuxPrivateDirectory, openLinuxPrivateDirectory, publishLinuxPrivateFile, readLinuxPrivateFile, unlinkLinuxPrivateFile, type LinuxPrivateDirectory, type LinuxPrivateFile } from './linux-private-files.js'

type Code = 'unavailable' | 'cancelled' | 'conflict' | 'busy'
export class HostEnrollmentRecoveryError extends Error {
  readonly code: `host.enrollment_recovery.${Code}`
  constructor(code: `host.enrollment_recovery.${Code}`) {
    const allowed: Code[] = ['unavailable', 'cancelled', 'conflict', 'busy']
    const safe = allowed.some(value => code === `host.enrollment_recovery.${value}`) ? code : 'host.enrollment_recovery.unavailable'
    super(safe); this.code = safe; this.name = 'HostEnrollmentRecoveryError'
  }
}
const failure = (code: Code = 'unavailable') => new HostEnrollmentRecoveryError(`host.enrollment_recovery.${code}`)
const MAGIC = Buffer.from('DSHENR01')
const MAX_WRAPPED = 16 * 1024
export const MAX_PLAINTEXT = 16 * 1024
export const MAX_FILE = 8 + 1 + 64 + 4 + MAX_WRAPPED + 12 + 4 + MAX_PLAINTEXT + 16
const busyPaths = guards.recoveryPaths

export interface HostEnrollmentRecoveryOptions {
  /** Absolute path under a dedicated, current-user-owned 0700 directory. */
  path: string
  /** The same resource account and installation key used for enrollment. */
  client: HostEnrollmentClient
  /** A trusted platform protector; no unprotected file-key fallback exists. */
  protector: JournalKeyProtector
}

function header(id: string, wrapped: Buffer, nonce: Buffer, size: number, magic: Buffer): Buffer {
  const name = Buffer.from(id, 'ascii')
  const output = Buffer.alloc(8 + 1 + name.length + 4 + wrapped.length + 12 + 4)
  magic.copy(output); output[8] = name.length; name.copy(output, 9)
  let offset = 9 + name.length
  output.writeUInt32BE(wrapped.length, offset); offset += 4
  wrapped.copy(output, offset); offset += wrapped.length
  nonce.copy(output, offset); offset += 12
  output.writeUInt32BE(size, offset)
  return output
}

/** @internal Shared authenticated envelope; callers must clear sensitive buffers. */
export async function seal(value: Buffer, protector: Protector, context: Buffer, signal: AbortSignal, magic = MAGIC): Promise<Buffer> {
  const key = randomBytes(32)
  let wrapped: Buffer | undefined, verified: Buffer | undefined, aad: Buffer | undefined
  try {
    wrapped = await invoke(protector, 'wrap', key, context, signal)
    verified = await invoke(protector, 'unwrap', wrapped, context, signal)
    if (!timingSafeEqual(key, verified) || signal.aborted) throw failure()
    const nonce = randomBytes(12), encoded = header(protector.id, wrapped, nonce, value.length, magic)
    aad = Buffer.concat([context, encoded])
    const cipher = createCipheriv('aes-256-gcm', key, nonce)
    cipher.setAAD(aad)
    const ciphertext = Buffer.concat([cipher.update(value), cipher.final()])
    return Buffer.concat([encoded, ciphertext, cipher.getAuthTag()])
  } finally { key.fill(0); wrapped?.fill(0); verified?.fill(0); aad?.fill(0) }
}

/** @internal Shared authenticated envelope; callers must clear returned buffers. */
export async function unseal(raw: Buffer, protector: Protector, context: Buffer, signal: AbortSignal, magic = MAGIC): Promise<Buffer> {
  if (raw.length < 8 + 1 + 1 + 4 + 48 + 12 + 4 + 1 + 16 || raw.length > MAX_FILE || !raw.subarray(0, 8).equals(magic)) throw failure()
  const nameLength = raw[8]!
  let offset = 9 + nameLength
  if (nameLength < 1 || nameLength > 64 || offset + 4 > raw.length || !raw.subarray(9, offset).equals(Buffer.from(protector.id, 'ascii'))) throw failure()
  const wrappedLength = raw.readUInt32BE(offset); offset += 4
  if (wrappedLength < 48 || wrappedLength > MAX_WRAPPED || offset + wrappedLength + 12 + 4 + 16 > raw.length) throw failure()
  const wrapped = raw.subarray(offset, offset + wrappedLength); offset += wrappedLength
  const nonce = raw.subarray(offset, offset + 12); offset += 12
  const size = raw.readUInt32BE(offset); offset += 4
  if (size < 1 || size > MAX_PLAINTEXT || offset + size + 16 !== raw.length) throw failure()
  let key: Buffer | undefined, aad: Buffer | undefined, partial: Buffer | undefined, final: Buffer | undefined
  try {
    key = await invoke(protector, 'unwrap', wrapped, context, signal)
    if (signal.aborted) throw failure('cancelled')
    aad = Buffer.concat([context, raw.subarray(0, offset)])
    const decipher = createDecipheriv('aes-256-gcm', key, nonce)
    decipher.setAAD(aad); decipher.setAuthTag(raw.subarray(offset + size))
    partial = decipher.update(raw.subarray(offset, offset + size)); final = decipher.final()
    const value = Buffer.concat([partial, final])
    if (value.length !== size || signal.aborted) { value.fill(0); throw failure('cancelled') }
    return value
  } finally { key?.fill(0); aad?.fill(0); partial?.fill(0); final?.fill(0) }
}

/** Linux authenticated, non-overwriting recovery storage for one pending attempt. */
export class HostEnrollmentRecoveryStore {
  readonly signal: AbortSignal
  #closed = new AbortController()
  #client: HostEnrollmentClient
  #protector: Protector
  #path: string
  #name: string
  #context: Buffer

  constructor(options: HostEnrollmentRecoveryOptions) {
    try {
      if (process.platform !== 'linux' || !options || typeof options.path !== 'string' || !isAbsolute(options.path) || options.path.includes('\0')) throw failure()
      this.#path = resolve(options.path)
      if (Buffer.byteLength(this.#path) > 8192 || basename(this.#path) === '' || this.#path === dirname(this.#path)) throw failure()
      this.#name = basename(this.#path)
      this.#client = options.client
      this.#protector = protectorFrom(options.protector)
      const binding = enrollmentRecoveryBinding(options.client)
      this.#context = Buffer.from(`dsh-host-enrollment-recovery-v1\0${this.#path}\0${binding}\0${this.#protector.id}`, 'utf8')
      this.signal = AbortSignal.any([this.#closed.signal, options.client.signal])
      Object.freeze(this)
    } catch { throw failure() }
  }

  toString(): string { return 'HostEnrollmentRecoveryStore' }
  toJSON(): string { return this.toString() }
  [inspect.custom](): string { return this.toString() }
  close(): void { this.#closed.abort() }

  async #run<T>(caller: AbortSignal, action: (directory: LinuxPrivateDirectory, signal: AbortSignal) => Promise<T>, permit?: symbol): Promise<T> {
    if (!(caller instanceof AbortSignal)) throw failure()
    if (caller.aborted || this.signal.aborted) throw failure('cancelled')
    const owner = busyPaths.get(this.#path)
    if (owner !== undefined && owner !== permit) throw failure('busy')
    const token = permit ?? Symbol('enrollment-recovery-operation'), acquired = owner === undefined
    if (acquired) busyPaths.set(this.#path, token)
    const signal = AbortSignal.any([caller, this.signal, AbortSignal.timeout(15_000)])
    let directory: LinuxPrivateDirectory | undefined
    try {
      directory = await openLinuxPrivateDirectory(dirname(this.#path))
      if (signal.aborted) throw failure('cancelled')
      return await action(directory, signal)
    } catch (cause) {
      if (cause instanceof HostEnrollmentRecoveryError) throw new HostEnrollmentRecoveryError(cause.code)
      if (signal.aborted) throw failure('cancelled')
      throw failure()
    } finally {
      try { await directory?.file.close() } catch { throw failure() }
      finally { if (acquired && busyPaths.get(this.#path) === token) busyPaths.delete(this.#path) }
    }
  }

  async save(attempt: HostEnrollmentIntent, signal: AbortSignal): Promise<void> {
    return await this.#save(attempt, signal)
  }

  async #save(attempt: HostEnrollmentIntent, signal: AbortSignal, permit?: symbol): Promise<void> {
    return await this.#run(signal, async (directory, lifetime) => {
      let plaintext: Buffer | undefined, existing: LinuxPrivateFile | undefined, prior: Buffer | undefined, sealed: Buffer | undefined
      try {
        const exported: unknown = attempt.exportRecovery()
        if (!(exported instanceof Uint8Array)) throw failure()
        plaintext = Buffer.isBuffer(exported) ? exported : Buffer.from(exported)
        if (plaintext !== exported) exported.fill(0)
        if (plaintext.length < 1 || plaintext.length > MAX_PLAINTEXT) throw failure()
        const checked = this.#client.restore(plaintext)
        try { if (checked.requestId !== attempt.requestId || checked.code !== attempt.code) throw failure() }
        finally { checked.destroy() }
        existing = await readLinuxPrivateFile(directory, this.#name, MAX_FILE, lifetime)
        if (existing) {
          prior = await unseal(existing.bytes, this.#protector, this.#context, lifetime)
          if (prior.length !== plaintext.length || !timingSafeEqual(prior, plaintext)) throw failure('conflict')
          await directory.file.sync(); await assertLinuxPrivateDirectory(directory)
          if (lifetime.aborted) throw failure('cancelled')
          return
        }
        sealed = await seal(plaintext, this.#protector, this.#context, lifetime)
        if (lifetime.aborted) throw failure('cancelled')
        await publishLinuxPrivateFile(directory, this.#name, sealed, MAX_FILE, lifetime)
        existing = await readLinuxPrivateFile(directory, this.#name, MAX_FILE, lifetime)
        if (!existing) throw failure()
        prior = await unseal(existing.bytes, this.#protector, this.#context, lifetime)
        if (prior.length !== plaintext.length || !timingSafeEqual(prior, plaintext)) throw failure('conflict')
        await directory.file.sync(); await assertLinuxPrivateDirectory(directory)
        if (lifetime.aborted) throw failure('cancelled')
      } finally {
        plaintext?.fill(0); existing?.bytes.fill(0); prior?.fill(0); sealed?.fill(0)
      }
    }, permit)
  }

  async load(signal: AbortSignal): Promise<HostEnrollmentIntent | undefined> {
    return await this.#run(signal, async (directory, lifetime) => {
      const stored = await readLinuxPrivateFile(directory, this.#name, MAX_FILE, lifetime)
      if (!stored) return undefined
      let plaintext: Buffer | undefined
      try {
        plaintext = await unseal(stored.bytes, this.#protector, this.#context, lifetime)
        if (lifetime.aborted) throw failure('cancelled')
        return this.#client.restore(plaintext)
      } finally { stored.bytes.fill(0); plaintext?.fill(0) }
    })
  }

  /** Persist the attempt before making the explicitly requested create call. */
  async create(attempt: HostEnrollmentIntent, signal: AbortSignal): Promise<HostEnrollmentReceipt> {
    return await this.#hold(signal, async (permit, lifetime) => {
      await this.#save(attempt, lifetime, permit)
      if (lifetime.aborted) throw failure('cancelled')
      return await this.#client.create(attempt, lifetime)
    })
  }

  /** Retain the matching recovery record through local review and confirmation. */
  async confirm(attempt: HostEnrollmentIntent, receipt: HostEnrollmentReceipt,
    approve: (review: HostEnrollmentApprovalReview, signal: AbortSignal) => boolean | Promise<boolean>, signal: AbortSignal): Promise<HostEnrollmentConfirmation> {
    return await this.#hold(signal, async (permit, lifetime) => {
      await this.#save(attempt, lifetime, permit)
      if (lifetime.aborted) throw failure('cancelled')
      return await this.#client.confirm(attempt, receipt, approve, lifetime)
    })
  }

  async #hold<T>(signal: AbortSignal, action: (permit: symbol, lifetime: AbortSignal) => Promise<T>): Promise<T> {
    if (!(signal instanceof AbortSignal)) throw failure()
    if (signal.aborted || this.signal.aborted) throw failure('cancelled')
    if (busyPaths.has(this.#path)) throw failure('busy')
    const permit = Symbol('enrollment-recovery-operation')
    busyPaths.set(this.#path, permit)
    try { return await action(permit, AbortSignal.any([signal, this.signal])) }
    finally { if (busyPaths.get(this.#path) === permit) busyPaths.delete(this.#path) }
  }

  /** Remove only an authenticated record matching the supplied attempt. */
  async remove(attempt: HostEnrollmentIntent, signal: AbortSignal): Promise<boolean> {
    return await this.#remove(attempt, signal)
  }

  /** Recheck an approved binding online, then remove only its matching recovery record. */
  async removeApproved(binding: HostEnrollmentBindingStore, signal: AbortSignal): Promise<boolean> {
    if (!(signal instanceof AbortSignal) || !binding || !(binding.signal instanceof AbortSignal) || typeof binding.open !== 'function') throw failure()
    return await this.#hold(AbortSignal.any([signal, binding.signal]), async (permit, lifetime) => {
      const approved = await binding.open(lifetime)
      if (lifetime.aborted) throw failure('cancelled')
      if (!approved) throw failure('conflict')
      requireEnrollmentBindingOwner(this.#client, approved)
      return await this.#remove(undefined, lifetime, permit, approved)
    })
  }

  /** Explicitly discard an authenticated record, including an expired one. */
  async discard(signal: AbortSignal): Promise<boolean> {
    return await this.#remove(undefined, signal)
  }

  async #remove(attempt: HostEnrollmentIntent | undefined, signal: AbortSignal, permit?: symbol, approved?: HostEnrollmentBinding): Promise<boolean> {
    return await this.#run(signal, async (directory, lifetime) => {
      const stored = await readLinuxPrivateFile(directory, this.#name, MAX_FILE, lifetime)
      if (!stored) return false
      let plaintext: Buffer | undefined, expected: Buffer | undefined
      try {
        plaintext = await unseal(stored.bytes, this.#protector, this.#context, lifetime)
        if (attempt) {
          const exported: unknown = attempt.exportRecovery()
          if (!(exported instanceof Uint8Array)) throw failure()
          expected = Buffer.isBuffer(exported) ? exported : Buffer.from(exported)
          if (expected !== exported) exported.fill(0)
          if (expected.length !== plaintext.length || !timingSafeEqual(expected, plaintext)) throw failure('conflict')
        }
        if (approved && !enrollmentRecoveryMatchesBinding(this.#client, plaintext, approved)) throw failure('conflict')
        await unlinkLinuxPrivateFile(directory, this.#name, stored, MAX_FILE, lifetime)
        return true
      } finally { stored.bytes.fill(0); plaintext?.fill(0); expected?.fill(0) }
    }, permit)
  }
}
