import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from 'node:crypto'
import { constants, type Stats } from 'node:fs'
import { link, lstat, mkdir, open, opendir, realpath, unlink, type FileHandle } from 'node:fs/promises'
import { basename, dirname, isAbsolute, resolve } from 'node:path'
import { inspect } from 'node:util'
import { invoke, protectorFrom, type JournalKeyProtector, type Protector } from './journal-key-protection.js'
import { enrollmentRecoveryBinding, type HostEnrollmentApprovalReview, type HostEnrollmentClient, type HostEnrollmentConfirmation, type HostEnrollmentIntent, type HostEnrollmentReceipt } from './host-enrollment.js'
import { guards } from './host-process-guards.js'

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
const MAX_PLAINTEXT = 16 * 1024
const MAX_FILE = 8 + 1 + 64 + 4 + MAX_WRAPPED + 12 + 4 + MAX_PLAINTEXT + 16
const busyPaths = guards.recoveryPaths

export interface HostEnrollmentRecoveryOptions {
  /** Absolute path under a dedicated, current-user-owned 0700 directory. */
  path: string
  /** The same resource account and installation key used for enrollment. */
  client: HostEnrollmentClient
  /** A trusted platform protector; no unprotected file-key fallback exists. */
  protector: JournalKeyProtector
}

type Directory = { file: FileHandle; path: string; proc: string; dev: number; ino: number }
type StoredFile = { bytes: Buffer; dev: number; ino: number }

async function assertDirectory(directory: Directory): Promise<void> {
  const entry = await lstat(directory.path)
  if (!entry.isDirectory() || entry.isSymbolicLink() || entry.uid !== process.getuid?.() || (entry.mode & 0o7777) !== 0o700 ||
      entry.dev !== directory.dev || entry.ino !== directory.ino || await realpath(directory.path) !== directory.path) throw failure()
}

async function openDirectory(path: string): Promise<Directory> {
  if (process.platform !== 'linux' || typeof constants.O_NOFOLLOW !== 'number' || typeof constants.O_DIRECTORY !== 'number' || process.getuid?.() === undefined) throw failure()
  await mkdir(path, { recursive: true, mode: 0o700 })
  if (await realpath(path) !== path) throw failure()
  const uid = process.getuid!()
  let ancestor = path, immediate = true
  for (;;) {
    const entry = await lstat(ancestor)
    if (!entry.isDirectory() || entry.isSymbolicLink() || (entry.uid !== 0 && entry.uid !== uid) ||
        (immediate && (entry.uid !== uid || (entry.mode & 0o7777) !== 0o700)) ||
        (!immediate && (entry.mode & 0o022) !== 0 && (entry.mode & 0o1000) === 0)) throw failure()
    const parent = dirname(ancestor)
    if (parent === ancestor) break
    ancestor = parent; immediate = false
  }
  const before = await lstat(path)
  const file = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)
  try {
    const actual = await file.stat()
    if (!actual.isDirectory() || actual.dev !== before.dev || actual.ino !== before.ino || actual.uid !== uid || (actual.mode & 0o7777) !== 0o700) throw failure()
    const directory = { file, path, proc: `/proc/self/fd/${file.fd}`, dev: actual.dev, ino: actual.ino }
    await assertDirectory(directory)
    return directory
  } catch (error) { await file.close(); throw error }
}

function privateFile(info: Stats): boolean {
  return info.isFile() && info.uid === process.getuid?.() && (info.mode & 0o7777) === 0o600 && info.size <= MAX_FILE
}

// An interrupted link-based publication can leave its own temporary hard link.
// Remove only matching temporary names for this exact inode, never other aliases.
async function cleanPublicationLinks(directory: Directory, name: string, file: FileHandle): Promise<void> {
  const initial = await file.stat()
  if (initial.nlink === 1) return
  if (initial.nlink < 1 || initial.nlink > 16) throw failure()
  const prefix = `.${name}.`, entries = await opendir(directory.proc)
  let count = 0, removed = false
  try {
    for await (const entry of entries) {
      if (++count > 4096) throw failure()
      if (!entry.name.startsWith(prefix) || !/^[0-9a-f]{32}\.tmp$/.test(entry.name.slice(prefix.length))) continue
      const path = `${directory.proc}/${entry.name}`
      let candidate
      try { candidate = await lstat(path) } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue; throw error }
      if (!privateFile(candidate) || candidate.dev !== initial.dev || candidate.ino !== initial.ino) continue
      try { await unlink(path); removed = true } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
    }
  } finally { await entries.close().catch(() => {}) }
  if (removed) await directory.file.sync()
  const after = await file.stat()
  if (!privateFile(after) || after.dev !== initial.dev || after.ino !== initial.ino || after.nlink !== 1) throw failure()
}

async function readStored(directory: Directory, name: string, signal: AbortSignal): Promise<StoredFile | undefined> {
  if (signal.aborted) throw failure('cancelled')
  const path = `${directory.proc}/${name}`
  let before
  try { before = await lstat(path) } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw error }
  if (!privateFile(before) || before.isSymbolicLink() || before.size < 1) throw failure()
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    const actual = await file.stat()
    if (!privateFile(actual) || actual.dev !== before.dev || actual.ino !== before.ino || actual.size !== before.size) throw failure()
    await cleanPublicationLinks(directory, name, file)
    const buffer = Buffer.alloc(MAX_FILE + 1)
    try {
      let length = 0
      while (length < buffer.length) {
        if (signal.aborted) throw failure('cancelled')
        const { bytesRead } = await file.read(buffer, length, buffer.length - length, null)
        if (bytesRead === 0) break
        length += bytesRead
      }
      const after = await file.stat()
      if (!privateFile(after) || after.dev !== actual.dev || after.ino !== actual.ino || after.size !== actual.size || after.nlink !== 1 || length !== actual.size || length > MAX_FILE) throw failure()
      await assertDirectory(directory)
      if (signal.aborted) throw failure('cancelled')
      await file.sync()
      const current = await lstat(path)
      if (!privateFile(current) || current.nlink !== 1 || current.dev !== actual.dev || current.ino !== actual.ino || current.size !== actual.size) throw failure()
      return { bytes: Buffer.from(buffer.subarray(0, length)), dev: actual.dev, ino: actual.ino }
    } finally { buffer.fill(0) }
  } finally { await file.close() }
}

function header(id: string, wrapped: Buffer, nonce: Buffer, size: number): Buffer {
  const name = Buffer.from(id, 'ascii')
  const output = Buffer.alloc(8 + 1 + name.length + 4 + wrapped.length + 12 + 4)
  MAGIC.copy(output); output[8] = name.length; name.copy(output, 9)
  let offset = 9 + name.length
  output.writeUInt32BE(wrapped.length, offset); offset += 4
  wrapped.copy(output, offset); offset += wrapped.length
  nonce.copy(output, offset); offset += 12
  output.writeUInt32BE(size, offset)
  return output
}

async function seal(value: Buffer, protector: Protector, context: Buffer, signal: AbortSignal): Promise<Buffer> {
  const key = randomBytes(32)
  let wrapped: Buffer | undefined, verified: Buffer | undefined, aad: Buffer | undefined
  try {
    wrapped = await invoke(protector, 'wrap', key, context, signal)
    verified = await invoke(protector, 'unwrap', wrapped, context, signal)
    if (!timingSafeEqual(key, verified) || signal.aborted) throw failure()
    const nonce = randomBytes(12), encoded = header(protector.id, wrapped, nonce, value.length)
    aad = Buffer.concat([context, encoded])
    const cipher = createCipheriv('aes-256-gcm', key, nonce)
    cipher.setAAD(aad)
    const ciphertext = Buffer.concat([cipher.update(value), cipher.final()])
    return Buffer.concat([encoded, ciphertext, cipher.getAuthTag()])
  } finally { key.fill(0); wrapped?.fill(0); verified?.fill(0); aad?.fill(0) }
}

async function unseal(raw: Buffer, protector: Protector, context: Buffer, signal: AbortSignal): Promise<Buffer> {
  if (raw.length < 8 + 1 + 1 + 4 + 48 + 12 + 4 + 1 + 16 || raw.length > MAX_FILE || !raw.subarray(0, 8).equals(MAGIC)) throw failure()
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

  async #run<T>(caller: AbortSignal, action: (directory: Directory, signal: AbortSignal) => Promise<T>, permit?: symbol): Promise<T> {
    if (!(caller instanceof AbortSignal)) throw failure()
    if (caller.aborted || this.signal.aborted) throw failure('cancelled')
    const owner = busyPaths.get(this.#path)
    if (owner !== undefined && owner !== permit) throw failure('busy')
    const token = permit ?? Symbol('enrollment-recovery-operation'), acquired = owner === undefined
    if (acquired) busyPaths.set(this.#path, token)
    const signal = AbortSignal.any([caller, this.signal, AbortSignal.timeout(15_000)])
    let directory: Directory | undefined
    try {
      directory = await openDirectory(dirname(this.#path))
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
      let plaintext: Buffer | undefined, existing: StoredFile | undefined, prior: Buffer | undefined, sealed: Buffer | undefined
      let temporary: string | undefined, temporaryIdentity: { dev: number; ino: number } | undefined
      try {
        const exported: unknown = attempt.exportRecovery()
        if (!(exported instanceof Uint8Array)) throw failure()
        plaintext = Buffer.isBuffer(exported) ? exported : Buffer.from(exported)
        if (plaintext !== exported) exported.fill(0)
        if (plaintext.length < 1 || plaintext.length > MAX_PLAINTEXT) throw failure()
        const checked = this.#client.restore(plaintext)
        try { if (checked.requestId !== attempt.requestId || checked.code !== attempt.code) throw failure() }
        finally { checked.destroy() }
        existing = await readStored(directory, this.#name, lifetime)
        if (existing) {
          prior = await unseal(existing.bytes, this.#protector, this.#context, lifetime)
          if (prior.length !== plaintext.length || !timingSafeEqual(prior, plaintext)) throw failure('conflict')
          await directory.file.sync(); await assertDirectory(directory)
          if (lifetime.aborted) throw failure('cancelled')
          return
        }
        sealed = await seal(plaintext, this.#protector, this.#context, lifetime)
        if (lifetime.aborted) throw failure('cancelled')
        temporary = `${directory.proc}/.${this.#name}.${randomBytes(16).toString('hex')}.tmp`
        const file = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
        try {
          const info = await file.stat(); temporaryIdentity = { dev: info.dev, ino: info.ino }
          if (!privateFile(info) || info.nlink !== 1) throw failure()
          await file.writeFile(sealed); await file.sync()
        } finally { await file.close() }
        if (lifetime.aborted) throw failure('cancelled')
        try { await link(temporary, `${directory.proc}/${this.#name}`) }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error }
        try {
          const current = await lstat(temporary)
          if (!temporaryIdentity || current.dev !== temporaryIdentity.dev || current.ino !== temporaryIdentity.ino) throw failure()
          await unlink(temporary); temporary = undefined
        } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
        await directory.file.sync(); await assertDirectory(directory)
        if (lifetime.aborted) throw failure('cancelled')
        existing = await readStored(directory, this.#name, lifetime)
        if (!existing) throw failure()
        prior = await unseal(existing.bytes, this.#protector, this.#context, lifetime)
        if (prior.length !== plaintext.length || !timingSafeEqual(prior, plaintext)) throw failure('conflict')
        await directory.file.sync(); await assertDirectory(directory)
        if (lifetime.aborted) throw failure('cancelled')
      } finally {
        plaintext?.fill(0); existing?.bytes.fill(0); prior?.fill(0); sealed?.fill(0)
        if (temporary && temporaryIdentity) {
          try {
            const current = await lstat(temporary)
            if (current.dev === temporaryIdentity.dev && current.ino === temporaryIdentity.ino) { await unlink(temporary); await directory.file.sync() }
          } catch { /* An absent or replaced temporary entry is not removed. */ }
        }
      }
    }, permit)
  }

  async load(signal: AbortSignal): Promise<HostEnrollmentIntent | undefined> {
    return await this.#run(signal, async (directory, lifetime) => {
      const stored = await readStored(directory, this.#name, lifetime)
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

  /** Explicitly discard an authenticated record, including an expired one. */
  async discard(signal: AbortSignal): Promise<boolean> {
    return await this.#remove(undefined, signal)
  }

  async #remove(attempt: HostEnrollmentIntent | undefined, signal: AbortSignal): Promise<boolean> {
    return await this.#run(signal, async (directory, lifetime) => {
      const stored = await readStored(directory, this.#name, lifetime)
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
        const path = `${directory.proc}/${this.#name}`, current = await lstat(path)
        if (!privateFile(current) || current.nlink !== 1 || current.dev !== stored.dev || current.ino !== stored.ino) throw failure()
        await assertDirectory(directory)
        if (lifetime.aborted) throw failure('cancelled')
        await unlink(path); await directory.file.sync(); await assertDirectory(directory)
        if (lifetime.aborted) throw failure('cancelled')
        return true
      } finally { stored.bytes.fill(0); plaintext?.fill(0); expected?.fill(0) }
    })
  }
}
