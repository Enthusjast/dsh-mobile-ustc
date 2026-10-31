import { spawn } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { constants } from 'node:fs'
import { access, open, realpath, stat } from 'node:fs/promises'
import { isAbsolute } from 'node:path'
import { ProbeError } from './protocol.js'

export interface WorkspaceChangesContext { root: string; guard: () => void }
interface Binding { runtimeId: string; runtimeEpoch: string; sessionId: string; subscriptionId: string; syncId: string }
interface ReadRequest { sync_id: string; limit: number; cursor?: string | undefined }
interface PatchRequest { sync_id: string; snapshot_id: string; file_id: string; cursor?: string | undefined }
type Kind = 'text' | 'binary' | 'symlink' | 'gitlink'
interface PathValue { bytes_base64: string; display: string }
interface FileValue {
  file_id: string; status: 'added' | 'modified' | 'deleted' | 'renamed' | 'type_changed'
  old_path: PathValue | null; new_path: PathValue | null; old_mode: string; new_mode: string
  kind: Kind; patch_bytes: number; complete: boolean; copyable: boolean
}
interface Line { kind: 'context' | 'add' | 'delete' | 'no_final_newline'; bytes_base64: string; text: string | null; old_line: number | null; new_line: number | null }
interface Hunk { old_start: number; old_count: number; new_start: number; new_count: number; lines: Line[] }
interface PatchPage {
  v: 1; sync_id: string; snapshot_id: string; file_id: string; version: string; kind: Kind
  complete: boolean; copyable: boolean; partial: boolean; patch_base64: string; patch_utf8: string | null
  hunks: Hunk[]; next_cursor: string | null
}
interface FileEntry { value: FileValue; patch: Buffer; pages: Array<{ start: number; end: number }> }
interface Capture { head: string; raw: Buffer; patch: Buffer; version: string }
interface Snapshot {
  id: string; owner: string; subscription: string; root: string; created: number; started: number; expires: number
  head: string; version: string; manifest: string; files: FileEntry[]; bytes: number; pages: number
  cursors: Map<string, { kind: 'manifest' | 'patch'; index: number; file?: string }>; timer: NodeJS.Timeout
}
const PATCH_BYTES = 1024 * 1024
const RAW_BYTES = 256 * 1024
const MAX_LINES = 20_000
const MAX_FILES = 128
const MANIFEST_BYTES = 32 * 1024
const PAGE_BYTES = 16 * 1024
const TOTAL_BYTES = 8 * 1024 * 1024
const TTL = 30_000
const TOKEN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
const gitOptions = [
  '--no-pager', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
  '-c', 'core.pager=cat', '-c', 'core.quotePath=true', '-c', 'core.attributesFile=/dev/null',
  '-c', 'diff.external=', '-c', 'diff.trustExitCode=false', '-c', 'diff.suppressBlankEmpty=false', '-c', 'submodule.recurse=false',
  '-c', 'protocol.allow=never', '-c', 'core.preloadIndex=false', '-c', 'core.untrackedCache=false',
]
const diffOptions = [
  'diff', '--no-ext-diff', '--no-textconv', '--no-color', '--no-abbrev', '--relative', '--ignore-submodules=dirty',
  '--find-renames=50%', '-l128', '--diff-algorithm=myers', '--no-indent-heuristic', '--full-index', '--submodule=short',
]
const patchFormatOptions = [
  '--src-prefix=a/', '--dst-prefix=b/', '--unified=3', '--inter-hunk-context=0', '--word-diff=none',
  '--output-indicator-new=+', '--output-indicator-old=-', '--output-indicator-context= ',
]
function error(code: string): never { throw new ProbeError(code) }
function utf8(bytes: Uint8Array): string | null { try { return decoder.decode(bytes) } catch { return null } }
function wireBytes(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, char => '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0')))
}
function owner(binding: Binding): string {
  for (const value of Object.values(binding)) if (typeof value !== 'string' || !TOKEN.test(value)) error('protocol.invalid')
  return JSON.stringify([binding.runtimeId, binding.runtimeEpoch, binding.sessionId, binding.subscriptionId, binding.syncId])
}
function requestKeys(request: object, keys: string[]): void {
  if (!request || typeof request !== 'object' || Array.isArray(request) || Object.keys(request).some(key => !keys.includes(key))) error('protocol.invalid')
}
function pathValue(path: Buffer): PathValue {
  if (!path.length || path.length > 8192 || path[0] === 47 || path.includes(0)) error('changes.limit')
  let display = ''
  for (const byte of path) display += byte >= 32 && byte <= 126 && byte !== 92 ? String.fromCharCode(byte) : '\\x' + byte.toString(16).padStart(2, '0')
  return { bytes_base64: path.toString('base64'), display }
}
function digest(capture: Omit<Capture, 'version'>): string {
  const hash = createHash('sha256')
  for (const part of [Buffer.from(capture.head), capture.raw, capture.patch]) hash.update(String(part.length) + ':').update(part)
  return hash.digest('hex')
}
function splitFiles(raw: Buffer, patch: Buffer): FileEntry[] {
  const fields: Buffer[] = []
  let offset = 0
  while (offset < raw.length) {
    const end = raw.indexOf(0, offset)
    if (end < 0) error('changes.unavailable')
    fields.push(raw.subarray(offset, end)); offset = end + 1
    if (fields.length > MAX_FILES * 3) error('changes.limit')
  }
  const values: FileValue[] = []
  for (let index = 0; index < fields.length;) {
    const header = fields[index++]!.toString('ascii').match(/^:([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}|[0-9a-f]{64}) ([0-9a-f]{40}|[0-9a-f]{64}) ([AMDRT])(?:[0-9]{1,3})?$/)
    if (!header || !fields[index]) error('changes.unavailable')
    const status = header[5]!, first = pathValue(fields[index++]!)
    const second = status === 'R' ? pathValue(fields[index++] ?? error('changes.unavailable')) : first
    values.push({ file_id: randomUUID(), status: ({ A: 'added', M: 'modified', D: 'deleted', R: 'renamed', T: 'type_changed' } as const)[status as 'A'],
      old_path: status === 'A' ? null : first, new_path: status === 'D' ? null : second, old_mode: header[1]!, new_mode: header[2]!,
      kind: header[1] === '160000' || header[2] === '160000' ? 'gitlink' : header[1] === '120000' || header[2] === '120000' ? 'symlink' : 'text',
      patch_bytes: 0, complete: true, copyable: false })
    if (values.length > MAX_FILES) error('changes.limit')
  }
  const starts: number[] = [], prefix = Buffer.from('diff --git ')
  let lines = 0
  for (let start = 0; start < patch.length;) {
    if (++lines > MAX_LINES) error('changes.limit')
    const newline = patch.indexOf(10, start), end = newline < 0 ? patch.length : newline + 1
    if (patch.subarray(start, Math.min(start + prefix.length, end)).equals(prefix)) starts.push(start)
    start = end
  }
  if (patch.length > 0 && starts[0] !== 0) error('changes.unavailable')
  const entries: FileEntry[] = []
  let section = 0
  for (const value of values) {
    const start = starts[section++]
    if (start === undefined) error('changes.unavailable')
    // Git can represent a type transition as adjacent deletion/addition sections for the same path.
    if (value.status === 'type_changed' && starts[section] !== undefined) {
      const next = starts[section]!, firstEnd = patch.indexOf(10, start), nextEnd = patch.indexOf(10, next)
      if (firstEnd >= 0 && nextEnd >= 0 && patch.subarray(start, firstEnd).equals(patch.subarray(next, nextEnd))) section++
    }
    const bytes = patch.subarray(start, starts[section] ?? patch.length)
    // A Git binary marker describes a change but is not a complete replacement patch.
    if (/\nBinary files [^\n]* differ\n/.test(bytes.toString('latin1'))) {
      if (value.kind === 'text') value.kind = 'binary'
      value.complete = false
    }
    value.patch_bytes = bytes.length
    entries.push({ value, patch: bytes, pages: [] })
  }
  if (section !== starts.length) error('changes.unavailable')
  return entries
}
function patchPage(snapshot: Pick<Snapshot, 'id' | 'version'>, sync: string, file: FileEntry, start: number, end: number, next: string | null): PatchPage {
  const bytes = file.patch.subarray(start, end), text = utf8(bytes)
  const complete = start === 0 && end === file.patch.length && file.value.complete
  const hunks: Hunk[] = []
  let hunk: Hunk | undefined, oldLine = 0, newLine = 0, oldRemaining = 0, newRemaining = 0
  for (let offset = 0; offset < end;) {
    const newline = file.patch.indexOf(10, offset), lineEnd = newline < 0 ? file.patch.length : newline + 1
    const bodyEnd = newline < 0 ? lineEnd : newline
    const body = file.patch.subarray(offset, bodyEnd)
    if (body[0] === 64) {
      const match = body.toString('latin1').match(/^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@/)
      if (!match || oldRemaining || newRemaining) error('changes.unavailable')
      hunk = { old_start: Number(match[1]), old_count: match[2] === undefined ? 1 : Number(match[2]), new_start: Number(match[3]), new_count: match[4] === undefined ? 1 : Number(match[4]), lines: [] }
      if (![hunk.old_start, hunk.old_count, hunk.new_start, hunk.new_count].every(Number.isSafeInteger)) error('changes.limit')
      oldLine = hunk.old_start; newLine = hunk.new_start; oldRemaining = hunk.old_count; newRemaining = hunk.new_count
      if (offset >= start) hunks.push(hunk)
    } else if (hunk && (oldRemaining || newRemaining || body[0] === 92)) {
      const prefix = body[0]
      if (prefix !== 32 && prefix !== 43 && prefix !== 45 && prefix !== 92) error('changes.unavailable')
      const marker = prefix === 92
      if (marker && body.toString('ascii') !== '\\ No newline at end of file') error('changes.unavailable')
      const old = !marker && prefix !== 43 ? oldLine++ : null, current = !marker && prefix !== 45 ? newLine++ : null
      if (old !== null && --oldRemaining < 0 || current !== null && --newRemaining < 0) error('changes.unavailable')
      if (offset >= start) {
        if (!hunks.includes(hunk)) { hunk = { ...hunk, lines: [] }; hunks.push(hunk) }
        const content = marker ? body : body.subarray(1)
        hunk.lines.push({ kind: marker ? 'no_final_newline' : prefix === 32 ? 'context' : prefix === 43 ? 'add' : 'delete', bytes_base64: content.toString('base64'), text: utf8(content), old_line: old, new_line: current })
      }
    }
    offset = lineEnd
  }
  if (end === file.patch.length && (oldRemaining || newRemaining)) error('changes.unavailable')
  return { v: 1, sync_id: sync, snapshot_id: snapshot.id, file_id: file.value.file_id, version: snapshot.version, kind: file.value.kind,
    complete, copyable: complete && text !== null, partial: !complete, patch_base64: bytes.toString('base64'), patch_utf8: text, hunks, next_cursor: next }
}
function preparePages(snapshot: Pick<Snapshot, 'id' | 'version'>, sync: string, file: FileEntry, current: () => void): void {
  const ends: number[] = []
  for (let offset = 0; offset < file.patch.length;) {
    const newline = file.patch.indexOf(10, offset)
    offset = newline < 0 ? file.patch.length : newline + 1; ends.push(offset)
  }
  let first = 0, start = 0
  while (first < ends.length) {
    current()
    let upper = first
    while (upper < ends.length && ends[upper]! - start <= 12_288) upper++
    if (upper === first || file.pages.length >= 64) error('changes.limit')
    let low = first, high = upper - 1, last = first - 1
    while (low <= high) {
      current()
      const middle = (low + high) >>> 1
      if (wireBytes(patchPage(snapshot, sync, file, start, ends[middle]!, '00000000-0000-0000-0000-000000000000')) <= PAGE_BYTES) {
        last = middle; low = middle + 1
      } else high = middle - 1
    }
    if (last < first) error('changes.limit')
    const end = ends[last]!
    file.pages.push({ start, end }); start = end; first = last + 1
  }
  file.value.copyable = file.pages.length === 1 && file.value.complete && utf8(file.patch) !== null
}

/** Read-only configured-workspace snapshots. Opaque handles locate bytes, never confer authority. */
export class WorkspaceChanges {
  #snapshots = new Map<string, Snapshot>()
  #readers = new Map<string, string>()
  #active: { subscription: string; abort: AbortController; until: number } | undefined
  #closed = false
  constructor(private readonly now: () => number = Date.now) {}

  static async supported(): Promise<boolean> {
    try { return await WorkspaceChanges.#runtimeSupported() } catch { return false }
  }

  static async #runtimeSupported(current?: () => void): Promise<boolean> {
    current?.()
    if (process.platform !== 'linux' || !process.getuid || !process.geteuid || process.getuid() === 0 || process.geteuid() === 0) return false
    let handle
    try {
      // RLIMIT_NPROC must not be bypassable: Git cannot launch filters or any other helper.
      handle = await open('/proc/self/status', 'r'); current?.()
      const buffer = Buffer.alloc(8192)
      const result = await handle.read(buffer, 0, buffer.length, 0); current?.()
      const status = buffer.subarray(0, result.bytesRead).toString('ascii'), forbidden = (1n << 21n) | (1n << 24n)
      for (const name of ['CapEff', 'CapAmb']) {
        const capabilities = status.match(new RegExp('^' + name + ':\\s*([0-9a-f]+)$', 'm'))
        if (!capabilities || (BigInt('0x' + capabilities[1]!) & forbidden) !== 0n) return false
      }
      for (const binary of ['/usr/bin/prlimit', '/usr/bin/git']) {
        current?.()
        const info = await stat(binary); current?.()
        if (!info.isFile() || info.uid !== 0 || (info.mode & 0o6022) !== 0) return false
        await access(binary, constants.X_OK); current?.()
      }
      return true
    } catch { return false }
    finally {
      try { if (handle) await handle.close() } finally { current?.() }
    }
  }

  #current(context: WorkspaceChangesContext, signal: AbortSignal): void {
    if (this.#closed || signal.aborted) error('access.denied')
    if (this.#active && performance.now() >= this.#active.until) error('changes.limit')
    try { context.guard() } catch { error('access.denied') }
  }
  #drop(snapshot: Snapshot): void {
    clearTimeout(snapshot.timer); snapshot.cursors.clear(); this.#snapshots.delete(snapshot.id)
    if (this.#readers.get(snapshot.subscription) === snapshot.id) this.#readers.delete(snapshot.subscription)
  }
  #alive(snapshot: Snapshot): boolean {
    return this.now() >= snapshot.created && this.now() < snapshot.expires && performance.now() - snapshot.started < TTL
  }
  #prune(): void { for (const snapshot of this.#snapshots.values()) if (!this.#alive(snapshot)) this.#drop(snapshot) }
  #find(context: WorkspaceChangesContext, binding: Binding, id: string): Snapshot {
    const snapshot = this.#snapshots.get(id)
    if (!snapshot || !this.#alive(snapshot) || snapshot.owner !== owner(binding) || snapshot.root !== context.root) {
      if (snapshot && snapshot.subscription === binding.subscriptionId) this.#drop(snapshot)
      return error('changes.stale')
    }
    return snapshot
  }
  async #supported(context: WorkspaceChangesContext, signal: AbortSignal): Promise<void> {
    this.#current(context, signal)
    if (!isAbsolute(context.root) || context.root.includes('\0')) error('changes.unavailable')
    const supported = await WorkspaceChanges.#runtimeSupported(() => this.#current(context, signal))
    this.#current(context, signal)
    if (!supported) error('changes.unavailable')
  }
  async #git(context: WorkspaceChangesContext, args: string[], cap: number, signal: AbortSignal): Promise<{ code: number; bytes: Buffer }> {
    this.#current(context, signal)
    const result = await new Promise<{ code: number; bytes: Buffer }>((resolve, reject) => {
      const stdout = Buffer.alloc(cap), stderr = Buffer.alloc(16 * 1024)
      let out = 0, err = 0, failure: ProbeError | undefined
      const child = spawn('/usr/bin/prlimit', ['--as=268435456', '--cpu=3', '--nofile=64', '--fsize=0', '--nproc=0', '--', '/usr/bin/git', ...gitOptions, ...args], {
        cwd: context.root, shell: false, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
        env: { PATH: '/usr/bin:/bin', LC_ALL: 'C', LANG: 'C', TZ: 'UTC', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_SYSTEM: '/dev/null', GIT_CONFIG_GLOBAL: '/dev/null',
          GIT_OPTIONAL_LOCKS: '0', GIT_NO_LAZY_FETCH: '1', GIT_TERMINAL_PROMPT: '0', GIT_PAGER: 'cat', GIT_ATTR_NOSYSTEM: '1' },
      })
      const stop = (code: string) => { failure ??= new ProbeError(code); child.kill('SIGKILL') }
      const abort = () => stop('access.denied')
      const timer = setTimeout(() => stop('changes.limit'), 3500); timer.unref()
      signal.addEventListener('abort', abort, { once: true })
      child.stdout.on('data', (chunk: Buffer) => {
        if (failure) return
        if (chunk.length > cap - out) { stop('changes.limit'); return }
        chunk.copy(stdout, out); out += chunk.length
      })
      child.stderr.on('data', (chunk: Buffer) => {
        if (failure) return
        if (chunk.length > stderr.length - err) { stop('changes.limit'); return }
        chunk.copy(stderr, err); err += chunk.length
      })
      child.on('error', () => { failure ??= new ProbeError('changes.unavailable') })
      child.on('close', code => {
        clearTimeout(timer); signal.removeEventListener('abort', abort)
        if (failure) reject(failure)
        else if (code === null) reject(new ProbeError('changes.limit'))
        else if (code === 0 && err > 0) reject(new ProbeError('changes.unavailable'))
        else resolve({ code, bytes: Buffer.from(stdout.subarray(0, out)) })
      })
      if (signal.aborted) abort()
    }).finally(() => this.#current(context, signal))
    return result
  }
  async #capture(context: WorkspaceChangesContext, signal: AbortSignal): Promise<Capture> {
    const inside = await this.#git(context, ['rev-parse', '--is-inside-work-tree'], 128, signal)
    if (inside.code || inside.bytes.toString('ascii') !== 'true\n') error('changes.not_git')
    this.#current(context, signal)
    const configuredRoot = await realpath(context.root); this.#current(context, signal)
    const top = await this.#git(context, ['rev-parse', '--show-toplevel'], 8192, signal)
    const topPath = top.bytes.length && top.bytes[top.bytes.length - 1] === 10 ? utf8(top.bytes.subarray(0, -1)) : null
    if (top.code || !topPath) error('changes.unavailable')
    const actualRoot = await realpath(topPath); this.#current(context, signal)
    // Nested configured directories and core.worktree redirection are deliberately unsupported.
    if (actualRoot !== configuredRoot) error('changes.unavailable')
    const before = await this.#git(context, ['rev-parse', '--verify', 'HEAD^{commit}'], 128, signal)
    const head = before.bytes.toString('ascii').trim()
    if (before.code || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(head)) error('changes.unavailable')
    const raw = await this.#git(context, [...diffOptions, '--raw', '-z', head, '--', '.'], RAW_BYTES, signal)
    if (raw.code) error('changes.unavailable')
    const patch = await this.#git(context, [...diffOptions, ...patchFormatOptions, '--patch', head, '--', '.'], PATCH_BYTES, signal)
    if (patch.code) error('changes.unavailable')
    const after = await this.#git(context, ['rev-parse', '--verify', 'HEAD^{commit}'], 128, signal)
    if (after.code || after.bytes.toString('ascii').trim() !== head) error('changes.stale')
    const topAfter = await this.#git(context, ['rev-parse', '--show-toplevel'], 8192, signal)
    if (topAfter.code || !topAfter.bytes.equals(top.bytes)) error('changes.stale')
    const rootAfter = await realpath(context.root); this.#current(context, signal)
    if (rootAfter !== configuredRoot) error('changes.stale')
    const capture = { head, raw: raw.bytes, patch: patch.bytes }
    return { ...capture, version: digest(capture) }
  }
  async #stable(context: WorkspaceChangesContext, signal: AbortSignal, version?: string): Promise<Capture> {
    const before = await this.#capture(context, signal)
    if (version && before.version !== version) error('changes.stale')
    const after = await this.#capture(context, signal)
    if (after.version !== before.version) error('changes.stale')
    return after
  }
  async #run<T>(context: WorkspaceChangesContext, binding: Binding, signal: AbortSignal, task: (signal: AbortSignal) => Promise<T>): Promise<T> {
    try { this.#current(context, signal); owner(binding); this.#prune() }
    catch (failure) { this.retire(binding.subscriptionId); throw failure }
    if (this.#active) error('changes.limit')
    const active = { subscription: binding.subscriptionId, abort: new AbortController(), until: performance.now() + 15_000 }; this.#active = active
    const timeout = AbortSignal.timeout(15_000), lifetime = AbortSignal.any([signal, active.abort.signal, timeout])
    try {
      await this.#supported(context, lifetime); this.#current(context, lifetime)
      const result = await task(lifetime); this.#current(context, lifetime)
      return result
    } catch (failure) {
      const id = this.#readers.get(binding.subscriptionId), snapshot = id ? this.#snapshots.get(id) : undefined
      if (snapshot) this.#drop(snapshot)
      if (timeout.aborted) error('changes.limit')
      if (signal.aborted || active.abort.signal.aborted || this.#closed) error('access.denied')
      if (failure instanceof ProbeError) throw failure
      return error('changes.unavailable')
    } finally { if (this.#active === active) this.#active = undefined }
  }
  #cursor(snapshot: Snapshot, value: { kind: 'manifest' | 'patch'; index: number; file?: string }): string {
    for (const [token, existing] of snapshot.cursors) if (existing.kind === value.kind && existing.index === value.index && existing.file === value.file) return token
    if (snapshot.cursors.size >= 64) error('changes.limit')
    const token = randomUUID(); snapshot.cursors.set(token, value); return token
  }
  #pageCount(snapshot: Snapshot): void { if (++snapshot.pages > 64) { this.#drop(snapshot); error('changes.limit') } }

  async read(context: WorkspaceChangesContext, binding: Binding, request: ReadRequest, signal: AbortSignal): Promise<unknown> {
    requestKeys(request, ['sync_id', 'limit', 'cursor'])
    if (!Number.isInteger(request.limit) || request.limit < 1 || request.limit > 20 || request.cursor !== undefined && !TOKEN.test(request.cursor)) error('protocol.invalid')
    if (request.sync_id !== binding.syncId) { this.retire(binding.subscriptionId); error('changes.stale') }
    return this.#run(context, binding, signal, async lifetime => {
      let snapshot: Snapshot, index = 0
      if (request.cursor) {
        const id = this.#readers.get(binding.subscriptionId)
        snapshot = this.#find(context, binding, id ?? '')
        const cursor = snapshot.cursors.get(request.cursor)
        if (!cursor || cursor.kind !== 'manifest') error('changes.stale')
        index = cursor.index
        await this.#stable(context, lifetime, snapshot.version); this.#current(context, lifetime)
      } else {
        const previousId = this.#readers.get(binding.subscriptionId), previous = previousId ? this.#snapshots.get(previousId) : undefined
        if (previous) this.#drop(previous)
        if (this.#snapshots.size >= 8) error('changes.limit')
        const captured = await this.#stable(context, lifetime); this.#current(context, lifetime)
        const files = splitFiles(captured.raw, captured.patch), id = randomUUID()
        for (const file of files) preparePages({ id, version: captured.version }, binding.syncId, file, () => this.#current(context, lifetime))
        for (const file of files) {
          if (file.value.old_path) Object.freeze(file.value.old_path)
          if (file.value.new_path) Object.freeze(file.value.new_path)
          Object.freeze(file.value)
        }
        const manifestBytes = JSON.stringify(files.map(file => file.value))
        const manifest = createHash('sha256').update(manifestBytes).digest('hex')
        // Conservative accounting includes objects, page offsets and the bounded cursor table, not just Git bytes.
        const created = this.now(), bytes = captured.raw.length + captured.patch.length + 2 * Buffer.byteLength(manifestBytes)
          + files.length * 1024 + files.reduce((total, file) => total + file.pages.length * 64, 0) + 64 * 1024
        if (bytes + [...this.#snapshots.values()].reduce((total, item) => total + item.bytes, 0) > TOTAL_BYTES) error('changes.limit')
        const timer = setTimeout(() => { const current = this.#snapshots.get(id); if (current) this.#drop(current) }, TTL); timer.unref()
        snapshot = { id, owner: owner(binding), subscription: binding.subscriptionId, root: context.root, created, started: performance.now(), expires: created + TTL,
          head: captured.head, version: captured.version, manifest, files, bytes, pages: 0, cursors: new Map(), timer }
        this.#snapshots.set(id, snapshot); this.#readers.set(binding.subscriptionId, id)
      }
      snapshot = this.#find(context, binding, snapshot.id); this.#pageCount(snapshot)
      const result = { v: 1, sync_id: binding.syncId, snapshot_id: snapshot.id, source: 'configured_workspace_git', base: { kind: 'git_head', oid: snapshot.head },
        version: snapshot.version, manifest_sha256: snapshot.manifest, expires_at: new Date(snapshot.expires).toISOString(), scope: 'tracked_head_to_index_worktree',
        excluded: ['untracked', 'ignored', 'submodule_contents'], complete: true, truncated: false, files: [] as FileValue[], next_cursor: null as string | null }
      for (; index < snapshot.files.length && result.files.length < request.limit; index++) {
        const file = snapshot.files[index]!.value
        const candidate = { ...result, files: [...result.files, file], next_cursor: '00000000-0000-0000-0000-000000000000' }
        if (wireBytes(candidate) > MANIFEST_BYTES) break
        result.files.push(file)
      }
      if (!result.files.length && index < snapshot.files.length) error('changes.limit')
      result.next_cursor = index < snapshot.files.length ? this.#cursor(snapshot, { kind: 'manifest', index }) : null
      return result
    })
  }
  async patch(context: WorkspaceChangesContext, binding: Binding, request: PatchRequest, signal: AbortSignal): Promise<unknown> {
    requestKeys(request, ['sync_id', 'snapshot_id', 'file_id', 'cursor'])
    if (!TOKEN.test(request.snapshot_id) || !TOKEN.test(request.file_id) || request.cursor !== undefined && !TOKEN.test(request.cursor)) error('protocol.invalid')
    if (request.sync_id !== binding.syncId) { this.retire(binding.subscriptionId); error('changes.stale') }
    return this.#run(context, binding, signal, async lifetime => {
      const snapshot = this.#find(context, binding, request.snapshot_id)
      const file = snapshot.files.find(entry => entry.value.file_id === request.file_id)
      if (!file) error('changes.stale')
      let index = 0
      if (request.cursor) {
        const cursor = snapshot.cursors.get(request.cursor)
        if (!cursor || cursor.kind !== 'patch' || cursor.file !== request.file_id) error('changes.stale')
        index = cursor.index
      }
      await this.#stable(context, lifetime, snapshot.version); this.#current(context, lifetime)
      this.#find(context, binding, snapshot.id); this.#pageCount(snapshot)
      const page = file.pages[index]
      if (!page) error('changes.stale')
      const next = index + 1 < file.pages.length ? this.#cursor(snapshot, { kind: 'patch', file: request.file_id, index: index + 1 }) : null
      const result = patchPage(snapshot, binding.syncId, file, page.start, page.end, next)
      if (wireBytes(result) > PAGE_BYTES) error('changes.limit')
      return result
    })
  }
  retire(subscriptionId: string): void {
    const id = this.#readers.get(subscriptionId), snapshot = id ? this.#snapshots.get(id) : undefined
    if (snapshot) this.#drop(snapshot)
    if (this.#active?.subscription === subscriptionId) this.#active.abort.abort()
  }
  close(): void {
    this.#closed = true; this.#active?.abort.abort()
    for (const snapshot of this.#snapshots.values()) this.#drop(snapshot)
  }
}
