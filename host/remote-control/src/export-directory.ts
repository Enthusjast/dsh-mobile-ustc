import { constants, type Dir } from 'node:fs'
import { open, opendir, type FileHandle } from 'node:fs/promises'
import { exportPart, exportVersion, openExportHandle } from './export-fs.js'
import { ProbeError } from './protocol.js'

export interface ExportDirectoryItem { name: string; kind: 'file' | 'directory'; size?: number; version?: string }

/** Bounded metadata cursor over one pinned directory. Actor authority is fresh on every page. */
export class ExportDirectory {
  #file: FileHandle
  #directory: Dir
  #closed = false
  #busy = false
  #location: string
  #idle: Promise<void> = Promise.resolve()
  #closing: Promise<void> | undefined
  private constructor(file: FileHandle, directory: Dir, location: string) { this.#file = file; this.#directory = directory; this.#location = location }
  static async open(root: string, parts: readonly string[], signal: AbortSignal, current: () => void): Promise<ExportDirectory> {
    const file = await openExportHandle(root, parts, true, signal, current)
    try {
      const directory = await opendir(`/proc/self/fd/${file.fd}`, { bufferSize: 16 })
      return new ExportDirectory(file, directory, JSON.stringify([root, parts]))
    } catch { await file.close(); throw new ProbeError('file.export_unavailable') }
  }
  matches(root: string, parts: readonly string[]) { return this.#location === JSON.stringify([root, parts]) }
  async page(signal: AbortSignal, current: () => void): Promise<{ items: ExportDirectoryItem[]; done: boolean }> {
    if (this.#closed || this.#busy) throw new ProbeError('file.export_unavailable')
    this.#busy = true
    let finished!: () => void
    this.#idle = new Promise<void>(resolve => { finished = resolve })
    let ended = false
    try {
      const items: ExportDirectoryItem[] = []
      for (let inspected = 0; inspected < 256 && items.length < 16; inspected++) {
        signal.throwIfAborted(); current()
        const entry = await this.#directory.read()
        if (!entry) { ended = true; return { items, done: true } }
        if (!exportPart(entry.name) || entry.isSymbolicLink()) continue
        let child: FileHandle | undefined
        try {
          child = await open(`/proc/self/fd/${this.#file.fd}/${entry.name}`, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
          const info = await child.stat({ bigint: true })
          signal.throwIfAborted(); current()
          if (info.isDirectory()) items.push({ name: entry.name, kind: 'directory' })
          else if (info.isFile() && info.nlink === 1n && info.size >= 0 && info.size <= BigInt(Number.MAX_SAFE_INTEGER)) items.push({ name: entry.name, kind: 'file', size: Number(info.size), version: exportVersion(info) })
        } catch (error) { signal.throwIfAborted(); current(); if (error instanceof ProbeError) throw error }
        finally { await child?.close().catch(() => {}) }
      }
      return { items, done: false }
    } finally { this.#busy = false; finished(); if (ended) await this.close() }
  }
  async close() {
    if (this.#closing) return this.#closing
    this.#closed = true
    this.#closing = this.#idle.then(async () => { await this.#directory.close().catch(() => {}); await this.#file.close().catch(() => {}) })
    return this.#closing
  }
  toJSON() { return {} }
  [Symbol.for('nodejs.util.inspect.custom')]() { return 'ExportDirectory' }
}
