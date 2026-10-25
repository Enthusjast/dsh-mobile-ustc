import { randomUUID } from 'node:crypto'
import type { CommandOwner } from './command-journal.js'
import type { DshClient } from './dsh-client.js'
import type { PinnedExportSource } from './file-export-source.js'
import type { FileManifest } from './file-admission.js'
import { ProbeError } from './protocol.js'

export interface ExportAuthority {
  owner: CommandOwner
  /** Current caller/connection lifetime plus a synchronous, fail-closed authorization lease check. */
  signal: AbortSignal
  current(): void
}
export interface ExportEntry extends FileManifest {
  export_id: string
  origin: 'workspace_artifact' | 'session_attachment'
  expires_at: string
}
interface Entry {
  session: string; owner: CommandOwner; authority: ExportAuthority; source: PinnedExportSource; value: ExportEntry
  started: bigint; wall: number; used: boolean
}
type Sources = Pick<DshClient, 'workspaceExportSource' | 'attachmentExportSource'>
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const TTL_MS = 5 * 60_000

/** Runtime-local source identities. Paths and native attachment IDs never become a selectable public identity. */
export class FileExportRegistry {
  #entries = new Map<string, Entry>()
  #preparing = 0
  #pending = new Set<Promise<void>>()
  #lifetime = new AbortController()
  #timer: NodeJS.Timeout
  #closed = false
  #closing: Promise<void> | undefined
  constructor(private readonly sources: Sources) {
    this.#timer = setInterval(() => this.#prune(), 1000)
    this.#timer.unref()
  }
  #valid(session: string, authority: ExportAuthority): void {
    if (this.#closed || !UUID.test(session) || !UUID.test(authority.owner.userId) || !UUID.test(authority.owner.deviceId)) throw new ProbeError('access.denied')
    authority.signal.throwIfAborted(); authority.current()
  }
  #alive(entry: Pick<Entry, 'wall' | 'started' | 'authority'>): boolean {
    return !entry.authority.signal.aborted && Date.now() >= entry.wall && Date.now() < entry.wall + TTL_MS
      && process.hrtime.bigint() - entry.started < BigInt(TTL_MS) * 1_000_000n
  }
  #prune(): void {
    for (const [id, entry] of this.#entries) {
      let active = this.#alive(entry) && entry.owner.userId === entry.authority.owner.userId && entry.owner.deviceId === entry.authority.owner.deviceId
      if (active) { try { entry.authority.current() } catch { active = false } }
      if (!active) { this.#entries.delete(id); void entry.source.close() }
    }
  }

  /** Called by a trusted Host artifact selector under a configured root, never with a phone-supplied path. */
  registerWorkspaceArtifact(session: string, root: string, parts: readonly string[], authority: ExportAuthority): Promise<ExportEntry> {
    const selected = [...parts]
    return this.#register(session, 'workspace_artifact', authority, (signal, current) => this.sources.workspaceExportSource(session, root, selected, signal, current))
  }
  registerSessionAttachment(session: string, seq: number, index: number, authority: ExportAuthority): Promise<ExportEntry> {
    return this.#register(session, 'session_attachment', authority, (signal, current) => this.sources.attachmentExportSource(session, seq, index, signal, current))
  }
  async #register(session: string, origin: ExportEntry['origin'], authority: ExportAuthority, create: (signal: AbortSignal, current: () => void) => Promise<PinnedExportSource>): Promise<ExportEntry> {
    this.#valid(session, authority); this.#prune()
    if (this.#entries.size + this.#preparing >= 32 || this.#preparing >= 2) throw new ProbeError('rate.limited')
    this.#preparing++
    let finish!: () => void
    const done = new Promise<void>(resolve => { finish = resolve }); this.#pending.add(done)
    const wall = Date.now(), started = process.hrtime.bigint(), owner = { ...authority.owner }
    const lifetime = AbortSignal.any([authority.signal, this.#lifetime.signal])
    const guard = () => {
      this.#valid(session, authority)
      if (!this.#alive({ wall, started, authority }) || authority.owner.userId !== owner.userId || authority.owner.deviceId !== owner.deviceId) throw new ProbeError('access.denied')
    }
    let source: PinnedExportSource | undefined
    try {
      source = await create(lifetime, guard)
      const manifest = await source.prepare(lifetime)
      guard()
      const value = Object.freeze({ ...manifest, export_id: randomUUID(), origin, expires_at: new Date(wall + TTL_MS).toISOString() })
      this.#entries.set(value.export_id, { session, owner, authority, source, value, wall, started, used: false })
      source = undefined
      return { ...value }
    } finally {
      await source?.close(); this.#preparing--; this.#pending.delete(done); finish()
    }
  }
  #find(id: string, session: string, authority: ExportAuthority): Entry {
    this.#valid(session, authority); this.#prune()
    const entry = this.#entries.get(id)
    if (!entry || entry.used || entry.session !== session || entry.owner.userId !== authority.owner.userId || entry.owner.deviceId !== authority.owner.deviceId) throw new ProbeError('file.export_unavailable')
    entry.authority.current()
    return entry
  }
  describe(id: string, session: string, authority: ExportAuthority): ExportEntry { return { ...this.#find(id, session, authority).value } }
  async *read(id: string, session: string, authority: ExportAuthority): AsyncGenerator<Uint8Array> {
    const entry = this.#find(id, session, authority)
    entry.used = true
    try {
      for await (const chunk of entry.source.read(AbortSignal.any([authority.signal, this.#lifetime.signal]))) {
        this.#valid(session, authority)
        if (entry.owner.userId !== authority.owner.userId || entry.owner.deviceId !== authority.owner.deviceId) throw new ProbeError('access.denied')
        yield chunk
      }
    } finally { this.#entries.delete(id); await entry.source.close() }
  }
  async release(id: string, session: string, authority: ExportAuthority): Promise<void> {
    this.#valid(session, authority)
    const entry = this.#entries.get(id)
    if (!entry || entry.session !== session || entry.owner.userId !== authority.owner.userId || entry.owner.deviceId !== authority.owner.deviceId) return
    this.#entries.delete(id); await entry.source.close()
  }
  async close(): Promise<void> {
    if (this.#closing) return this.#closing
    this.#closed = true; clearInterval(this.#timer); this.#lifetime.abort()
    this.#closing = Promise.all([...this.#entries.values()].map(entry => entry.source.close()).concat([...this.#pending])).then(() => { this.#entries.clear() })
    return this.#closing
  }
  toJSON() { return {} }
  toString() { return 'FileExportRegistry' }
  [Symbol.for('nodejs.util.inspect.custom')]() { return this.toString() }
}
