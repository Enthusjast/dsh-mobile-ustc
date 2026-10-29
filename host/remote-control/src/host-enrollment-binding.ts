import { timingSafeEqual } from 'node:crypto'
import { basename, dirname, isAbsolute, resolve } from 'node:path'
import { inspect } from 'node:util'
import { canonicalObject, parseSigningObject } from './canonical.js'
import { captureEnrollmentBinding, enrollmentRecoveryBinding, hostEnrollmentBindingRecord, verifyEnrollmentBinding,
  type HostEnrollmentApprovalReview, type HostEnrollmentBinding, type HostEnrollmentBindingRecord, type HostEnrollmentClient,
  type HostEnrollmentIntent, type HostEnrollmentReceipt } from './host-enrollment.js'
import { enrollmentError, HostEnrollmentError } from './host-enrollment-transport.js'
import { MAX_FILE, MAX_PLAINTEXT, seal, unseal, type HostEnrollmentRecoveryStore } from './host-enrollment-recovery.js'
import { protectorFrom, type JournalKeyProtector, type Protector } from './journal-key-protection.js'
import { assertLinuxPrivateDirectory, openLinuxPrivateDirectory, publishLinuxPrivateFile, readLinuxPrivateFile, unlinkLinuxPrivateFile, type LinuxPrivateDirectory, type LinuxPrivateFile } from './linux-private-files.js'
import { guards } from './host-process-guards.js'

type Code = 'unavailable' | 'cancelled' | 'conflict' | 'busy'
export class HostEnrollmentBindingError extends Error {
  readonly code: `host.enrollment_binding.${Code}`
  constructor(code: `host.enrollment_binding.${Code}`) {
    const allowed: Code[] = ['unavailable', 'cancelled', 'conflict', 'busy']
    const safe = allowed.some(value => code === `host.enrollment_binding.${value}`) ? code : 'host.enrollment_binding.unavailable'
    super(safe); this.code = safe; this.name = 'HostEnrollmentBindingError'
  }
}
const failure = (code: Code = 'unavailable') => new HostEnrollmentBindingError(`host.enrollment_binding.${code}`)
const busyPaths = guards.recoveryPaths
const BINDING_MAGIC = Buffer.from('DSHENB01')

export interface HostEnrollmentBindingOptions {
  /** Absolute path under a dedicated, current-user-owned 0700 directory. */
  path: string
  /** Resource identity and installation key that own this binding. */
  client: HostEnrollmentClient
  /** Trusted platform protector; no unprotected file-key fallback exists. */
  protector: JournalKeyProtector
}

/** Durable inert binding metadata. Opening it always rechecks server history;
 * it is not a connection credential or a substitute for current authorization. */
export class HostEnrollmentBindingStore {
  readonly signal: AbortSignal
  #closed = new AbortController()
  #client: HostEnrollmentClient
  #protector: Protector
  #path: string
  #name: string
  #context: Buffer

  constructor(options: HostEnrollmentBindingOptions) {
    try {
      if (process.platform !== 'linux' || !options || typeof options.path !== 'string' || !isAbsolute(options.path) || options.path.includes('\0')) throw failure()
      this.#path = resolve(options.path)
      if (Buffer.byteLength(this.#path) > 8192 || basename(this.#path) === '' || this.#path === dirname(this.#path)) throw failure()
      this.#name = basename(this.#path); this.#client = options.client; this.#protector = protectorFrom(options.protector)
      const binding = enrollmentRecoveryBinding(options.client)
      this.#context = Buffer.from(`dsh-host-enrollment-binding-store-v1\0${this.#path}\0${binding}\0${this.#protector.id}`, 'utf8')
      this.signal = AbortSignal.any([this.#closed.signal, options.client.signal])
      Object.freeze(this)
    } catch { throw failure() }
  }

  toString(): string { return 'HostEnrollmentBindingStore' }
  toJSON(): string { return this.toString() }
  [inspect.custom](): string { return this.toString() }
  close(): void { this.#closed.abort() }

  async #run<T>(caller: AbortSignal, action: (directory: LinuxPrivateDirectory, signal: AbortSignal) => Promise<T>, permit?: symbol): Promise<T> {
    if (!(caller instanceof AbortSignal)) throw failure()
    if (caller.aborted || this.signal.aborted) throw failure('cancelled')
    const owner = busyPaths.get(this.#path)
    if (owner !== undefined && owner !== permit) throw failure('busy')
    const token = permit ?? Symbol('enrollment-binding-operation'), acquired = owner === undefined
    if (acquired) busyPaths.set(this.#path, token)
    const signal = AbortSignal.any([caller, this.signal, AbortSignal.timeout(15_000)])
    let directory: LinuxPrivateDirectory | undefined
    try {
      directory = await openLinuxPrivateDirectory(dirname(this.#path))
      if (signal.aborted) throw failure('cancelled')
      return await action(directory, signal)
    } catch (cause) {
      if (cause instanceof HostEnrollmentBindingError) throw new HostEnrollmentBindingError(cause.code)
      if (cause instanceof HostEnrollmentError) throw new HostEnrollmentError(cause.code)
      if (signal.aborted) throw failure('cancelled')
      throw failure()
    } finally {
      try { await directory?.file.close() } catch { throw failure() }
      finally { if (acquired && busyPaths.get(this.#path) === token) busyPaths.delete(this.#path) }
    }
  }

  async #reserve(record: HostEnrollmentBindingRecord, signal: AbortSignal, permit?: symbol): Promise<void> {
    return await this.#run(signal, async (directory, lifetime) => {
      let plaintext: Buffer | undefined, prior: Buffer | undefined, sealed: Buffer | undefined, stored: LinuxPrivateFile | undefined
      try {
        plaintext = Buffer.from(canonicalObject(hostEnrollmentBindingRecord.parse(record)))
        if (plaintext.length < 1 || plaintext.length > MAX_PLAINTEXT) throw failure()
        stored = await readLinuxPrivateFile(directory, this.#name, MAX_FILE, lifetime)
        if (stored) {
          prior = await unseal(stored.bytes, this.#protector, this.#context, lifetime, BINDING_MAGIC)
          if (prior.length !== plaintext.length || !timingSafeEqual(prior, plaintext)) throw failure('conflict')
          await directory.file.sync(); await assertLinuxPrivateDirectory(directory)
          if (lifetime.aborted) throw failure('cancelled')
          return
        }
        sealed = await seal(plaintext, this.#protector, this.#context, lifetime, BINDING_MAGIC)
        if (lifetime.aborted) throw failure('cancelled')
        await publishLinuxPrivateFile(directory, this.#name, sealed, MAX_FILE, lifetime)
        stored = await readLinuxPrivateFile(directory, this.#name, MAX_FILE, lifetime)
        if (!stored) throw failure()
        prior = await unseal(stored.bytes, this.#protector, this.#context, lifetime, BINDING_MAGIC)
        if (prior.length !== plaintext.length || !timingSafeEqual(prior, plaintext)) throw failure('conflict')
        await directory.file.sync(); await assertLinuxPrivateDirectory(directory)
        if (lifetime.aborted) throw failure('cancelled')
      } finally { plaintext?.fill(0); prior?.fill(0); sealed?.fill(0); stored?.bytes.fill(0) }
    }, permit)
  }

  /** Reserve the verified create receipt before any host confirmation. */
  async reserve(attempt: HostEnrollmentIntent, receipt: HostEnrollmentReceipt, signal: AbortSignal): Promise<void> {
    let record: HostEnrollmentBindingRecord
    try { record = captureEnrollmentBinding(this.#client, attempt, receipt) }
    catch (cause) { if (cause instanceof HostEnrollmentError) throw new HostEnrollmentError(cause.code); throw failure() }
    return await this.#reserve(record, signal)
  }

  /** Confirm only after the binding pointer and recovery attempt are durable. */
  async confirm(recovery: HostEnrollmentRecoveryStore, attempt: HostEnrollmentIntent, receipt: HostEnrollmentReceipt,
    approve: (review: HostEnrollmentApprovalReview, signal: AbortSignal) => boolean | Promise<boolean>, signal: AbortSignal): Promise<HostEnrollmentBinding> {
    if (!(signal instanceof AbortSignal) || !recovery || typeof recovery.confirm !== 'function' || typeof approve !== 'function') throw failure()
    if (signal.aborted || this.signal.aborted) throw failure('cancelled')
    if (busyPaths.has(this.#path)) throw failure('busy')
    const permit = Symbol('enrollment-binding-confirm')
    busyPaths.set(this.#path, permit)
    const lifetime = AbortSignal.any([signal, this.signal])
    try {
      const record = captureEnrollmentBinding(this.#client, attempt, receipt)
      await this.#reserve(record, lifetime, permit)
      if (lifetime.aborted) throw failure('cancelled')
      await recovery.confirm(attempt, receipt, approve, lifetime)
      try {
        if (lifetime.aborted) throw failure('cancelled')
        await this.#reserve(record, lifetime, permit)
        const result = await verifyEnrollmentBinding(this.#client, record, lifetime)
        await this.#reserve(record, lifetime, permit)
        return result
      } catch { throw enrollmentError('outcome_unknown') }
    } finally { if (busyPaths.get(this.#path) === permit) busyPaths.delete(this.#path) }
  }

  /** Return binding metadata only after a fresh approved server review. */
  async open(signal: AbortSignal): Promise<HostEnrollmentBinding | undefined> {
    return await this.#run(signal, async (directory, lifetime) => {
      const stored = await readLinuxPrivateFile(directory, this.#name, MAX_FILE, lifetime)
      if (!stored) return undefined
      let plaintext: Buffer | undefined
      try {
        plaintext = await unseal(stored.bytes, this.#protector, this.#context, lifetime, BINDING_MAGIC)
        const record = hostEnrollmentBindingRecord.parse(parseSigningObject(plaintext))
        const result = await verifyEnrollmentBinding(this.#client, record, lifetime)
        const current = await readLinuxPrivateFile(directory, this.#name, MAX_FILE, lifetime)
        if (!current) throw failure()
        try { if (current.dev !== stored.dev || current.ino !== stored.ino || !current.bytes.equals(stored.bytes)) throw failure() }
        finally { current.bytes.fill(0) }
        return result
      } finally { stored.bytes.fill(0); plaintext?.fill(0) }
    })
  }

  /** Explicitly discard an authenticated binding pointer; never called automatically. */
  async discard(signal: AbortSignal): Promise<boolean> {
    return await this.#run(signal, async (directory, lifetime) => {
      const stored = await readLinuxPrivateFile(directory, this.#name, MAX_FILE, lifetime)
      if (!stored) return false
      let plaintext: Buffer | undefined
      try {
        plaintext = await unseal(stored.bytes, this.#protector, this.#context, lifetime, BINDING_MAGIC)
        hostEnrollmentBindingRecord.parse(parseSigningObject(plaintext))
        await unlinkLinuxPrivateFile(directory, this.#name, stored, MAX_FILE, lifetime)
        return true
      } finally { stored.bytes.fill(0); plaintext?.fill(0) }
    })
  }
}
