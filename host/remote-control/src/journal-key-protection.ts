import { constants } from 'node:fs'
import { link, lstat, open, unlink } from 'node:fs/promises'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import { basename, dirname, join, resolve } from 'node:path'

/** A trusted platform adapter wraps a 32-byte journal key using the supplied
 * context. Returned byte arrays are transferred to the caller and cleared. */
export interface JournalKeyProtector {
  readonly id: string
  wrap(key: Uint8Array, context: Uint8Array, signal: AbortSignal): Promise<Uint8Array>
  unwrap(wrapped: Uint8Array, context: Uint8Array, signal: AbortSignal): Promise<Uint8Array>
}

export interface JournalKeyOptions {
  protector?: JournalKeyProtector
  signal?: AbortSignal
}

const MAGIC = Buffer.from('DSHJKEY1')
const MAX_WRAPPED = 16 * 1024
const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/
const failure = () => new Error('command journal key protection unavailable')

type Protector = { id: string; wrap: JournalKeyProtector['wrap']; unwrap: JournalKeyProtector['unwrap'] }
export type ProtectedKey = { key: Buffer; needsWrap: boolean; protector: Protector; context: Buffer }

function protectorFrom(value: JournalKeyProtector): Protector {
  try {
    if (!value) throw failure()
    const id = value.id, wrap = value.wrap, unwrap = value.unwrap
    if (typeof id !== 'string' || !ID.test(id) || typeof wrap !== 'function' || typeof unwrap !== 'function') throw failure()
    return { id, wrap: wrap.bind(value), unwrap: unwrap.bind(value) }
  } catch { throw failure() }
}

function binding(runtimeId: string, path: string, id: string): Buffer {
  const absolute = resolve(path)
  if (absolute.includes('\0') || Buffer.byteLength(absolute) > 8192) throw failure()
  return Buffer.from(`dsh-remote-journal-wrap-v1\0${runtimeId}\0${absolute}\0${id}`, 'utf8')
}

function clearBytes(value: unknown): void {
  try { if (value instanceof Uint8Array) value.fill(0) } catch { /* Detached buffers cannot retain usable bytes. */ }
}

async function invoke(protector: Protector, operation: 'wrap' | 'unwrap', input: Uint8Array, context: Uint8Array, signal?: AbortSignal): Promise<Buffer> {
  const deadline = new AbortController()
  const timer = setTimeout(() => deadline.abort(), 5_000)
  const combined = signal ? AbortSignal.any([signal, deadline.signal]) : deadline.signal
  const inputCopy = Uint8Array.from(input), contextCopy = Uint8Array.from(context)
  let stopped = false
  let removeAbort = () => {}
  try {
    if (combined.aborted) throw failure()
    const task = Promise.resolve().then(() => protector[operation](inputCopy, contextCopy, combined))
    task.then(value => { if (stopped) clearBytes(value) }, () => {})
    const cancelled = new Promise<never>((_, reject) => {
      const abort = () => reject(failure())
      removeAbort = () => combined.removeEventListener('abort', abort)
      combined.addEventListener('abort', abort, { once: true })
      if (combined.aborted) abort()
    })
    const value: unknown = await Promise.race([task, cancelled])
    if (!(value instanceof Uint8Array)) throw failure()
    if (combined.aborted) { clearBytes(value); throw failure() }
    if (operation === 'wrap' ? value.byteLength < 48 || value.byteLength > MAX_WRAPPED : value.byteLength !== 32) {
      clearBytes(value)
      throw failure()
    }
    const result = Buffer.from(value)
    clearBytes(value)
    return result
  } catch { throw failure() }
  finally {
    stopped = true
    removeAbort()
    clearTimeout(timer)
    inputCopy.fill(0)
    contextCopy.fill(0)
  }
}

function encode(id: string, wrapped: Buffer): Buffer {
  const name = Buffer.from(id, 'ascii')
  const header = Buffer.alloc(MAGIC.length + 1 + name.length + 4)
  MAGIC.copy(header)
  header[MAGIC.length] = name.length
  name.copy(header, MAGIC.length + 1)
  header.writeUInt32BE(wrapped.length, MAGIC.length + 1 + name.length)
  return Buffer.concat([header, wrapped])
}

function decode(raw: Buffer, expectedID: string): Buffer {
  if (raw.length < MAGIC.length + 1 + 4 + 48 || raw.length > MAGIC.length + 1 + 64 + 4 + MAX_WRAPPED || !raw.subarray(0, MAGIC.length).equals(MAGIC)) throw failure()
  const nameLength = raw[MAGIC.length]!
  const offset = MAGIC.length + 1 + nameLength
  if (nameLength < 1 || nameLength > 64 || offset + 4 > raw.length) throw failure()
  const name = raw.subarray(MAGIC.length + 1, offset)
  const size = raw.readUInt32BE(offset)
  if (!ID.test(expectedID) || !name.equals(Buffer.from(expectedID, 'ascii')) || size < 48 || size > MAX_WRAPPED || offset + 4 + size !== raw.length) throw failure()
  return Buffer.from(raw.subarray(offset + 4))
}

async function privateRead(path: string, max: number, singleLink = false, synchronize = false): Promise<Buffer> {
  if (typeof constants.O_NOFOLLOW !== 'number' || constants.O_NOFOLLOW <= 0) throw failure()
  const before = await lstat(path)
  if (!before.isFile() || before.isSymbolicLink() || (before.mode & 0o777) !== 0o600 || before.uid !== process.getuid?.() || before.size > max || (singleLink && before.nlink !== 1)) throw failure()
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  try {
    const actual = await file.stat()
    if (!actual.isFile() || actual.dev !== before.dev || actual.ino !== before.ino || actual.size !== before.size || actual.size > max ||
        (actual.mode & 0o777) !== 0o600 || actual.uid !== process.getuid?.() || (singleLink && actual.nlink !== 1)) throw failure()
    const buffer = Buffer.alloc(max + 1)
    try {
      let length = 0
      while (length < buffer.length) {
        const { bytesRead } = await file.read(buffer, length, buffer.length - length, null)
        if (bytesRead === 0) break
        length += bytesRead
      }
      const after = await file.stat()
      if (length !== actual.size || length > max || after.size !== actual.size || (after.mode & 0o777) !== 0o600 || after.uid !== process.getuid?.() || (singleLink && after.nlink !== 1)) throw failure()
      if (synchronize) await file.sync()
      return Buffer.from(buffer.subarray(0, length))
    } finally { buffer.fill(0) }
  } finally { await file.close() }
}

async function optionalPrivateRead(path: string, max: number, singleLink = false, synchronize = false): Promise<Buffer | undefined> {
  try { return await privateRead(path, max, singleLink, synchronize) }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw failure() }
}

async function syncDirectory(path: string): Promise<void> {
  const directory = await open(path, constants.O_RDONLY)
  try { await directory.sync() } finally { await directory.close() }
}

async function openWrapped(path: string, protector: Protector, context: Buffer, signal?: AbortSignal, synchronize = false): Promise<Buffer | undefined> {
  const raw = await optionalPrivateRead(path, MAGIC.length + 1 + 64 + 4 + MAX_WRAPPED, false, synchronize)
  if (raw === undefined) return undefined
  let wrapped: Buffer | undefined
  try {
    wrapped = decode(raw, protector.id)
    return await invoke(protector, 'unwrap', wrapped, context, signal)
  } finally { raw.fill(0); wrapped?.fill(0) }
}

async function publishWrapped(path: string, protector: Protector, context: Buffer, key: Buffer, allowDifferent: boolean, signal?: AbortSignal): Promise<Buffer> {
  let wrapped: Buffer | undefined, check: Buffer | undefined, encoded: Buffer | undefined
  let temporaryIdentity: { dev: number; ino: number } | undefined
  const temporary = join(dirname(path), `.${basename(path)}.${randomBytes(16).toString('hex')}.tmp`)
  try {
    wrapped = await invoke(protector, 'wrap', key, context, signal)
    check = await invoke(protector, 'unwrap', wrapped, context, signal)
    if (!timingSafeEqual(check, key)) throw failure()
    if (signal?.aborted) throw failure()
    encoded = encode(protector.id, wrapped)
    const file = await open(temporary, 'wx', 0o600)
    try {
      const info = await file.stat()
      temporaryIdentity = { dev: info.dev, ino: info.ino }
      await file.writeFile(encoded)
      await file.sync()
    } finally { await file.close() }
    if (signal?.aborted) throw failure()
    try { await link(temporary, path) }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error }
    await syncDirectory(dirname(path))
    const published = await openWrapped(path, protector, context, signal)
    if (published === undefined || (!allowDifferent && !timingSafeEqual(published, key))) {
      published?.fill(0)
      throw failure()
    }
    return published
  } catch { throw failure() }
  finally {
    wrapped?.fill(0); check?.fill(0); encoded?.fill(0)
    if (temporaryIdentity) {
      try {
        const current = await lstat(temporary)
        if (current.dev === temporaryIdentity.dev && current.ino === temporaryIdentity.ino) {
          await unlink(temporary)
          await syncDirectory(dirname(path))
        }
      } catch { /* An absent or replaced temporary file is not removed. */ }
    }
  }
}

export async function hasProtectedKey(path: string): Promise<boolean> {
  try { await lstat(`${path}.wrapped-key`); return true }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw failure() }
}

export async function loadProtectedKey(path: string, runtimeId: string, databaseExists: boolean, source: JournalKeyProtector, signal?: AbortSignal): Promise<ProtectedKey> {
  if (process.platform === 'win32' || signal?.aborted) throw failure()
  const protector = protectorFrom(source), context = binding(runtimeId, path, protector.id)
  let wrapped: Buffer | undefined, legacy: Buffer | undefined, generated: Buffer | undefined
  try {
    wrapped = await openWrapped(`${path}.wrapped-key`, protector, context, signal)
    legacy = await optionalPrivateRead(`${path}.key`, 32, true)
    if (legacy !== undefined && legacy.length !== 32) throw failure()
    if (wrapped !== undefined) {
      if (legacy !== undefined && !timingSafeEqual(wrapped, legacy)) throw failure()
      const key = wrapped
      wrapped = undefined
      return { key, needsWrap: false, protector, context }
    }
    if (legacy !== undefined) {
      const key = legacy
      legacy = undefined
      return { key, needsWrap: true, protector, context }
    }
    if (databaseExists) throw failure()
    generated = randomBytes(32)
    const key = await publishWrapped(`${path}.wrapped-key`, protector, context, generated, true, signal)
    return { key, needsWrap: false, protector, context }
  } catch { context.fill(0); throw failure() }
  finally { wrapped?.fill(0); legacy?.fill(0); generated?.fill(0) }
}

// Called only after the existing database has authenticated this key.
export async function finalizeProtectedKey(path: string, state: ProtectedKey, signal?: AbortSignal): Promise<void> {
  try {
    if (signal?.aborted) throw failure()
    if (state.needsWrap) {
      const published = await publishWrapped(`${path}.wrapped-key`, state.protector, state.context, state.key, false, signal)
      published.fill(0)
    }
    if (signal?.aborted) throw failure()
    // A prior process may have linked the envelope but failed before syncing
    // its directory. Make the envelope durable before removing any legacy key.
    const confirmed = await openWrapped(`${path}.wrapped-key`, state.protector, state.context, signal, true)
    if (confirmed === undefined || !timingSafeEqual(confirmed, state.key)) { confirmed?.fill(0); throw failure() }
    confirmed.fill(0)
    await syncDirectory(dirname(path))
    if (signal?.aborted) throw failure()
    // Recheck even for a newly created envelope: another opener may have
    // created a legacy key while this operation was initializing.
    const before = await lstat(`${path}.key`).catch(error => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
      throw error
    })
    if (before !== undefined) {
      const legacy = await privateRead(`${path}.key`, 32, true)
      try {
        if (legacy.length !== 32 || !timingSafeEqual(legacy, state.key)) throw failure()
        const current = await lstat(`${path}.key`)
        if (current.dev !== before.dev || current.ino !== before.ino || current.nlink !== 1 || (current.mode & 0o777) !== 0o600 || current.uid !== process.getuid?.()) throw failure()
        if (signal?.aborted) throw failure()
        try { await unlink(`${path}.key`) }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
        await syncDirectory(dirname(path))
      } finally { legacy.fill(0) }
    }
    if (signal?.aborted) throw failure()
  } catch { throw failure() }
  finally { state.context.fill(0) }
}
