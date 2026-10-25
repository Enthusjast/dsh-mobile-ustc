import { createHash } from 'node:crypto'
import { constants, type BigIntStats } from 'node:fs'
import { open, statfs, type FileHandle } from 'node:fs/promises'
import { isAbsolute, normalize } from 'node:path'
import { fileManifest, type FileManifest } from './file-admission.js'
import { ProbeError } from './protocol.js'

export const MAX_EXPORT_FILE_BYTES = 2_000_000_000
const CHUNK_BYTES = 64 * 1024

export interface ExportSourceSpec {
  /** Host policy, never a phone-supplied path. Every component is opened without following links. */
  root: string
  parts: readonly string[]
  /** Present only for an authoritative native attachment; its immutable aliases can be hard links. */
  attachment?: FileManifest
}

function validPart(value: string): boolean { return fileManifest.shape.name.safeParse(value).success }
function same(left: BigIntStats, right: BigIntStats): boolean {
  return right.isFile() && left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.mode === right.mode
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs && left.nlink === right.nlink
}
function failure(error: unknown, signal: AbortSignal): never {
  signal.throwIfAborted()
  if (error instanceof ProbeError) throw error
  throw new ProbeError('file.export_unavailable')
}

/**
 * One bounded, version-pinned source. A digest is computed before publication;
 * the later one-use stream rechecks the same descriptor, version and digest.
 * This Linux adapter uses kernel fd-relative traversal. Other hosts must supply
 * an equally strong adapter; realpath-then-open is not a fallback.
 */
export class PinnedExportSource {
  readonly name: string
  readonly sizeBytes: number
  #file: FileHandle
  #version: BigIntStats
  #expected: FileManifest | undefined
  #current: () => void
  #signal: AbortSignal
  #onAbort = () => { void this.close() }
  #timer: NodeJS.Timeout
  #closed = false
  #closing: Promise<void> | undefined
  #busy = false
  #manifest: FileManifest | undefined

  private constructor(file: FileHandle, version: BigIntStats, name: string, expected: FileManifest | undefined, signal: AbortSignal, current: () => void) {
    this.#file = file; this.#version = version; this.name = name; this.sizeBytes = Number(version.size)
    this.#expected = expected; this.#current = current; this.#signal = signal
    this.#signal.addEventListener('abort', this.#onAbort, { once: true })
    this.#timer = setTimeout(() => { void this.close() }, 5 * 60_000)
    this.#timer.unref()
    if (this.#signal.aborted) void this.close()
  }

  static async supported(): Promise<boolean> {
    return process.platform === 'linux' && await statfs('/proc/self/fd').then(info => info.type === 0x9fa0, () => false)
  }

  static async open(spec: ExportSourceSpec, signal: AbortSignal, current: () => void): Promise<PinnedExportSource> {
    signal.throwIfAborted(); current()
    const root = spec.root, selected = [...spec.parts], attachment = spec.attachment ? { ...spec.attachment } : undefined
    const rootParts = root === '/' ? [] : root.split('/').slice(1)
    if (!isAbsolute(root) || normalize(root) !== root || selected.length === 0 || selected.length > 32
      || !selected.every(validPart) || rootParts.some(part => !validPart(part))) throw new ProbeError('file.export_invalid')
    if (attachment && !fileManifest.safeParse(attachment).success) throw new ProbeError('file.export_invalid')
    if (!await this.supported()) throw new ProbeError('file.export_unsupported')
    const flags = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
    let directory: FileHandle | undefined
    let file: FileHandle | undefined
    try {
      directory = await open('/', flags | constants.O_DIRECTORY)
      // Opening through each live directory descriptor pins its identity even
      // if a repository process swaps a lexical ancestor during traversal.
      const parts = [...rootParts, ...selected]
      for (let index = 0; index < parts.length; index++) {
        signal.throwIfAborted(); current()
        if (!directory) throw new ProbeError('file.export_unavailable')
        const next = await open(`/proc/self/fd/${directory.fd}/${parts[index]!}`, flags | (index + 1 === parts.length ? 0 : constants.O_DIRECTORY))
        const previous = directory; directory = undefined
        if (index + 1 === parts.length) file = next
        else directory = next
        await previous.close()
      }
      signal.throwIfAborted(); current()
      signal.throwIfAborted()
      const info = await file!.stat({ bigint: true })
      if (!info.isFile() || info.size < 0 || info.nlink < 1 || !attachment && info.nlink !== 1n) throw new ProbeError('file.export_unavailable')
      if (info.size > BigInt(MAX_EXPORT_FILE_BYTES)) throw new ProbeError('file.too_large')
      if (attachment && Number(info.size) !== attachment.size_bytes) throw new ProbeError('file.export_changed')
      signal.throwIfAborted(); current()
      const source = new PinnedExportSource(file!, info, attachment?.name ?? selected.at(-1)!, attachment, signal, current)
      file = undefined
      return source
    } catch (error) { return failure(error, signal) }
    finally { await directory?.close().catch(() => {}); await file?.close().catch(() => {}) }
  }

  async #check(signal: AbortSignal): Promise<void> {
    signal.throwIfAborted(); this.#current()
    if (this.#closed) throw new ProbeError('file.export_changed')
    const info = await this.#file.stat({ bigint: true })
    if (!same(this.#version, info)) throw new ProbeError('file.export_changed')
    signal.throwIfAborted(); this.#current()
    if (this.#closed) throw new ProbeError('file.export_changed')
  }

  async *#chunks(signal: AbortSignal): AsyncGenerator<Buffer> {
    const buffer = Buffer.alloc(CHUNK_BYTES)
    let position = 0
    while (position < this.sizeBytes) {
      await this.#check(signal)
      const { bytesRead } = await this.#file.read(buffer, 0, Math.min(buffer.length, this.sizeBytes - position), position)
      await this.#check(signal)
      if (bytesRead <= 0) throw new ProbeError('file.export_changed')
      position += bytesRead
      yield Buffer.from(buffer.subarray(0, bytesRead))
    }
    await this.#check(signal)
    const tail = await this.#file.read(buffer, 0, 1, position)
    await this.#check(signal)
    if (tail.bytesRead !== 0) throw new ProbeError('file.export_changed')
  }

  async prepare(signal: AbortSignal): Promise<FileManifest> {
    if (this.#busy) throw new ProbeError('file.export_busy')
    this.#busy = true
    const lifetime = AbortSignal.any([signal, this.#signal])
    const cancel = () => { void this.close() }
    lifetime.addEventListener('abort', cancel, { once: true })
    try {
      await this.#check(lifetime)
      if (this.#manifest) return { ...this.#manifest }
      const hash = createHash('sha256')
      for await (const chunk of this.#chunks(lifetime)) hash.update(chunk)
      const manifest = { name: this.name, size_bytes: this.sizeBytes, sha256: hash.digest('hex') }
      if (this.#expected && manifest.sha256 !== this.#expected.sha256) throw new ProbeError('file.export_changed')
      this.#manifest = manifest
      return { ...manifest }
    } catch (error) { await this.close(); return failure(error, lifetime) }
    finally { this.#busy = false; lifetime.removeEventListener('abort', cancel) }
  }

  async *read(signal: AbortSignal): AsyncGenerator<Uint8Array> {
    if (!this.#manifest) throw new ProbeError('file.export_not_prepared')
    if (this.#busy) throw new ProbeError('file.export_busy')
    this.#busy = true
    const lifetime = AbortSignal.any([signal, this.#signal])
    const cancel = () => { void this.close() }
    lifetime.addEventListener('abort', cancel, { once: true })
    try {
      await this.#check(lifetime)
      const hash = createHash('sha256')
      let last: Buffer | undefined
      for await (const chunk of this.#chunks(lifetime)) {
        hash.update(chunk)
        if (last) yield last
        last = chunk
      }
      if (hash.digest('hex') !== this.#manifest.sha256) throw new ProbeError('file.export_changed')
      await this.#check(lifetime)
      if (last) yield last
    } catch (error) { failure(error, lifetime) }
    finally { this.#busy = false; lifetime.removeEventListener('abort', cancel); await this.close() }
  }

  async close(): Promise<void> {
    if (this.#closing) return this.#closing
    this.#closed = true; clearTimeout(this.#timer)
    this.#signal.removeEventListener('abort', this.#onAbort)
    // Do not abort the caller's lifetime or replace the original read failure.
    this.#closing = this.#file.close().catch(() => {})
    return this.#closing
  }
  toJSON() { return {} }
  toString() { return 'PinnedExportSource' }
  [Symbol.for('nodejs.util.inspect.custom')]() { return this.toString() }
}
