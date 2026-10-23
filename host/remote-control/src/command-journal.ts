import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { lstat, mkdir, open as openFile, realpath, readFile } from 'node:fs/promises'
import { DatabaseSync } from 'node:sqlite'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { ProbeError, type Command } from './protocol.js'

export const MAX_JOURNAL_COMMANDS = 100_000
const MAX_PENDING_JOURNAL_COMMANDS = 4096
const MAX_COMMAND_BYTES = 64 * 1024
const SCHEMA_VERSION = 1
const RUNTIME_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

export type CommandState = 'host_accepted' | 'dispatching' | 'agent_queued' | 'settled' | 'rejected' | 'outcome_unknown'
export interface CommandOwner { userId: string; deviceId: string }
export interface JournalAdmission {
  inserted: boolean
  state: CommandState
  digest: string
  result?: unknown
  errorCode?: string
}

export interface CommandJournal {
  admit(command: Command, owner: CommandOwner): JournalAdmission
  start(requestId: string, owner: CommandOwner): void
  complete(requestId: string, owner: CommandOwner, state: 'agent_queued' | 'settled', result: unknown): void
  fail(requestId: string, owner: CommandOwner, state: 'rejected' | 'outcome_unknown', errorCode: string): void
  close(): void
}

type Ciphertext = { nonce: Buffer; ciphertext: Buffer; tag: Buffer }
type JournalRow = {
  user_id: string
  payload_sha256: string
  payload_nonce: Uint8Array | null
  payload_ciphertext: Uint8Array | null
  payload_tag: Uint8Array | null
  result_nonce: Uint8Array | null
  result_ciphertext: Uint8Array | null
  result_tag: Uint8Array | null
  state: CommandState
  error_code: string | null
}

const allowedTransitions: Record<CommandState, ReadonlySet<CommandState>> = {
  host_accepted: new Set(['dispatching', 'rejected', 'outcome_unknown']),
  dispatching: new Set(['agent_queued', 'settled', 'rejected', 'outcome_unknown']),
  agent_queued: new Set(['settled', 'outcome_unknown']),
  settled: new Set(),
  rejected: new Set(),
  outcome_unknown: new Set(),
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue)
  if (typeof value !== 'object' || value === null) return value
  const object = value as Record<string, unknown>
  return Object.fromEntries(Object.keys(object).sort().map(key => [key, canonicalValue(object[key])]))
}

/** Request epochs and IDs identify transport attempts; only the operation body is hashed. */
export function commandDigest(command: Command): string {
  const body = {
    type: command.type,
    ...('session_id' in command ? { session_id: command.session_id } : {}),
    payload: command.payload,
  }
  return createHash('sha256').update(JSON.stringify(canonicalValue(body))).digest('hex')
}

function isCommandState(value: unknown): value is CommandState {
  return typeof value === 'string' && Object.hasOwn(allowedTransitions, value)
}

function validateOwner(owner: CommandOwner): void {
  if (!owner.userId || owner.userId.length > 256 || !owner.deviceId || owner.deviceId.length > 256) {
    throw new ProbeError('access.denied')
  }
}
function aad(runtimeId: string, owner: CommandOwner, requestId: string, kind: 'command' | 'result', digest: string): Buffer {
  return Buffer.from(`dsh-remote-command-v1\0${runtimeId}\0${owner.userId}\0${owner.deviceId}\0${requestId}\0${kind}\0${digest}`)
}

export function defaultCommandJournalPath(runtimeId: string): string {
  if (!RUNTIME_ID.test(runtimeId)) throw new Error('command journal requires a runtime UUID')
  if (process.platform === 'win32') {
    const root = process.env.LOCALAPPDATA
    if (!root || !isAbsolute(root)) throw new Error('LOCALAPPDATA is required for the command journal')
    return join(root, 'dsh-mobile-ustc', runtimeId, 'commands.sqlite')
  }
  if (process.platform === 'darwin') return join(homedir(), 'Library', 'Application Support', 'dsh-mobile-ustc', runtimeId, 'commands.sqlite')
  const state = process.env.XDG_STATE_HOME
  const root = state && isAbsolute(state) ? state : join(homedir(), '.local', 'state')
  return join(root, 'dsh-mobile-ustc', runtimeId, 'commands.sqlite')
}

function encrypt(key: Buffer, runtimeId: string, owner: CommandOwner, requestId: string, kind: 'command' | 'result', digest: string, value: unknown): Ciphertext {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(aad(runtimeId, owner, requestId, kind, digest))
  const plaintext = Buffer.from(JSON.stringify(value) ?? 'null', 'utf8')
  let ciphertext: Buffer
  try { ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]) }
  finally { plaintext.fill(0) }
  return { nonce, ciphertext, tag: cipher.getAuthTag() }
}

function decrypt<T>(key: Buffer, runtimeId: string, owner: CommandOwner, requestId: string, kind: 'command' | 'result', digest: string, value: Ciphertext): T {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, value.nonce)
    decipher.setAAD(aad(runtimeId, owner, requestId, kind, digest))
    decipher.setAuthTag(value.tag)
    const cleartext = Buffer.concat([decipher.update(value.ciphertext), decipher.final()]).toString('utf8')
    return JSON.parse(cleartext) as T
  } catch {
    throw new ProbeError('journal.integrity_failed')
  }
}

function keyCheckAAD(runtimeId: string): Buffer {
  return Buffer.from(`dsh-remote-command-key-v1\0${runtimeId}`)
}

function encryptKeyCheck(key: Buffer, runtimeId: string): Ciphertext {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(keyCheckAAD(runtimeId))
  const plaintext = Buffer.from(`command-journal:${runtimeId}`)
  let ciphertext: Buffer | undefined
  try { ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]) }
  finally { plaintext.fill(0) }
  if (ciphertext === undefined) throw new ProbeError('journal.encryption_failed')
  return { nonce, ciphertext, tag: cipher.getAuthTag() }
}

function verifyKeyCheck(key: Buffer, runtimeId: string, value: Ciphertext): void {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, value.nonce)
    decipher.setAAD(keyCheckAAD(runtimeId))
    decipher.setAuthTag(value.tag)
    const actual = Buffer.concat([decipher.update(value.ciphertext), decipher.final()])
    const expected = Buffer.from(`command-journal:${runtimeId}`)
    try {
      if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error('key check mismatch')
    } finally { actual.fill(0) }
  } catch {
    throw new ProbeError('journal.integrity_failed')
  }
}

function securePathEqual(first: string, second: string): boolean {
  return process.platform === 'win32' ? first.toLowerCase() === second.toLowerCase() : first === second
}

async function ensurePrivateDirectory(path: string): Promise<void> {
  if (!isAbsolute(path)) throw new Error('command journal path must be absolute')
  await mkdir(path, { recursive: true, mode: 0o700 })
  const info = await lstat(path)
  if (!info.isDirectory() || info.isSymbolicLink() || !securePathEqual(await realpath(path), resolve(path))) {
    throw new Error('command journal directory must be a real directory without symlinks')
  }
  if (process.platform !== 'win32' && (info.uid !== process.getuid?.() || (info.mode & 0o777) !== 0o700)) {
    throw new Error('command journal directory must be owned by this user and mode 0700')
  }
}

async function assertPrivateFile(path: string): Promise<void> {
  const info = await lstat(path)
  if (!info.isFile() || info.isSymbolicLink()) throw new Error('command journal files must be regular files without symlinks')
  if (process.platform !== 'win32' && (info.uid !== process.getuid?.() || (info.mode & 0o777) !== 0o600)) {
    throw new Error('command journal files must be owned by this user and mode 0600')
  }
}

async function createPrivateFile(path: string, content?: Buffer): Promise<boolean> {
  let file
  try {
    file = await openFile(path, 'wx', 0o600)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') return false
    throw error
  }
  try {
    if (content !== undefined) await file.writeFile(content)
    await file.sync()
  } finally { await file.close() }
  return true
}

async function loadOrCreateKey(path: string, databaseExists: boolean): Promise<Buffer> {
  try {
    await assertPrivateFile(path)
    const key = await readFile(path)
    if (key.length !== 32) throw new Error('command journal key has invalid length')
    return key
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    if (databaseExists) throw new Error('command journal key is missing; refusing to replace it')
    const generated = randomBytes(32)
    const created = await createPrivateFile(path, generated)
    if (created) return generated
    generated.fill(0)
    return loadOrCreateKey(path, false)
  }
}

function rowCiphertext(row: JournalRow, kind: 'command' | 'result'): Ciphertext | undefined {
  const nonce = kind === 'command' ? row.payload_nonce : row.result_nonce
  const ciphertext = kind === 'command' ? row.payload_ciphertext : row.result_ciphertext
  const tag = kind === 'command' ? row.payload_tag : row.result_tag
  if (nonce === null || ciphertext === null || tag === null) return undefined
  return { nonce: Buffer.from(nonce), ciphertext: Buffer.from(ciphertext), tag: Buffer.from(tag) }
}

function transitionAllowed(from: CommandState, to: CommandState): boolean {
  return allowedTransitions[from].has(to)
}

/**
 * Profile-local SQLite WAL journal. Payload and result bodies use AES-256-GCM;
 * metadata retains the request hash and delivery state for idempotency.
 */
export class PersistentCommandJournal implements CommandJournal {
  private constructor(private readonly database: DatabaseSync, private readonly key: Buffer, private readonly runtimeId: string) {}

  static async open(path: string, runtimeId: string): Promise<PersistentCommandJournal> {
    if (!isAbsolute(path) || !RUNTIME_ID.test(runtimeId)) throw new Error('command journal requires an absolute path and runtime UUID')
    if (process.platform === 'win32') {
      const root = process.env.LOCALAPPDATA
      if (!root || !isAbsolute(root)) throw new Error('LOCALAPPDATA is required for the command journal')
      const relativePath = relative(resolve(root), resolve(path))
      if (!relativePath || relativePath === '..' || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
        throw new Error('Windows command journal must remain under the current user LOCALAPPDATA directory')
      }
    }
    const parent = dirname(path)
    await ensurePrivateDirectory(parent)
    let databaseExists = false
    try {
      await assertPrivateFile(path)
      databaseExists = true
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    }
    const key = await loadOrCreateKey(`${path}.key`, databaseExists)
    if (!databaseExists) {
      await createPrivateFile(path)
      await assertPrivateFile(path)
    }
    let database: DatabaseSync | undefined
    try {
      database = new DatabaseSync(path, { timeout: 5000, enableForeignKeyConstraints: true })
      database.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA secure_delete = ON; PRAGMA trusted_schema = OFF;')
      if (database.prepare('PRAGMA journal_mode').get()?.journal_mode !== 'wal'
        || database.prepare('PRAGMA synchronous').get()?.synchronous !== 2) {
        throw new Error('command journal requires SQLite WAL mode and FULL synchronization')
      }
      const version = database.prepare('PRAGMA user_version').get()?.user_version
      if (version === 0) {
        database.exec(`
          BEGIN IMMEDIATE;
          CREATE TABLE commands (
            runtime_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
            payload_nonce BLOB,
            payload_ciphertext BLOB,
            payload_tag BLOB,
            result_nonce BLOB,
            result_ciphertext BLOB,
            result_tag BLOB,
            state TEXT NOT NULL CHECK (state IN ('host_accepted','dispatching','agent_queued','settled','rejected','outcome_unknown')),
            error_code TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (runtime_id, device_id, request_id),
            CHECK ((payload_nonce IS NULL AND payload_ciphertext IS NULL AND payload_tag IS NULL) OR
                   (length(payload_nonce) = 12 AND payload_ciphertext IS NOT NULL AND length(payload_tag) = 16)),
            CHECK ((result_nonce IS NULL AND result_ciphertext IS NULL AND result_tag IS NULL) OR
                   (length(result_nonce) = 12 AND result_ciphertext IS NOT NULL AND length(result_tag) = 16))
          ) STRICT;
          CREATE INDEX commands_state_updated ON commands (runtime_id, state, updated_at);
          CREATE TABLE journal_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            nonce BLOB NOT NULL CHECK (length(nonce) = 12),
            ciphertext BLOB NOT NULL,
            tag BLOB NOT NULL CHECK (length(tag) = 16)
          ) STRICT;
          PRAGMA user_version = ${SCHEMA_VERSION};
          COMMIT;
        `)
      } else if (version !== SCHEMA_VERSION) {
        throw new Error(`unsupported command journal schema version: ${String(version)}`)
      }
      database.exec('BEGIN IMMEDIATE')
      try {
        const check = database.prepare('SELECT nonce, ciphertext, tag FROM journal_meta WHERE id = 1').get() as Ciphertext | undefined
        if (check === undefined) {
          const existingCommands = database.prepare('SELECT COUNT(*) AS count FROM commands').get()?.count
          if (typeof existingCommands !== 'number' || existingCommands !== 0) throw new ProbeError('journal.integrity_failed')
          const encrypted = encryptKeyCheck(key, runtimeId)
          database.prepare('INSERT INTO journal_meta (id, nonce, ciphertext, tag) VALUES (1, ?, ?, ?)')
            .run(encrypted.nonce, encrypted.ciphertext, encrypted.tag)
        } else {
          verifyKeyCheck(key, runtimeId, {
            nonce: Buffer.from(check.nonce), ciphertext: Buffer.from(check.ciphertext), tag: Buffer.from(check.tag),
          })
        }
        database.exec('COMMIT')
      } catch (error) {
        try { database.exec('ROLLBACK') } catch { /* Preserve the key validation error. */ }
        throw error
      }
      return new PersistentCommandJournal(database, key, runtimeId)
    } catch (error) {
      if (database?.isOpen) {
        if (database.isTransaction) {
          try { database.exec('ROLLBACK') } catch { /* Preserve the initialization error. */ }
        }
        database.close()
      }
      key.fill(0)
      throw error
    }
  }

  admit(command: Command, owner: CommandOwner): JournalAdmission {
    validateOwner(owner)
    if (Buffer.byteLength(JSON.stringify(canonicalValue(command))) > MAX_COMMAND_BYTES) throw new ProbeError('protocol.frame_too_large')
    const digest = commandDigest(command)
    let admission: JournalAdmission | undefined
    this.transaction(() => {
      const existing = this.database.prepare(`
        SELECT user_id, payload_sha256, payload_nonce, payload_ciphertext, payload_tag,
               result_nonce, result_ciphertext, result_tag, state, error_code
        FROM commands WHERE runtime_id = ? AND device_id = ? AND request_id = ?
      `).get(this.runtimeId, owner.deviceId, command.request_id) as JournalRow | undefined
      if (existing !== undefined) {
        if (existing.user_id !== owner.userId) throw new ProbeError('access.denied')
        if (existing.payload_sha256 !== digest) throw new ProbeError('command.request_conflict')
        if (!isCommandState(existing.state)) throw new ProbeError('journal.integrity_failed')
        const encryptedResult = rowCiphertext(existing, 'result')
        const result = encryptedResult === undefined ? undefined : decrypt<unknown>(this.key, this.runtimeId, owner, command.request_id, 'result', digest, encryptedResult)
        admission = {
          inserted: false, state: existing.state, digest, result,
          ...(existing.error_code === null ? {} : { errorCode: existing.error_code }),
        }
        return
      }
      const count = this.database.prepare('SELECT COUNT(*) AS count FROM commands WHERE runtime_id = ?').get(this.runtimeId)?.count
      if (typeof count !== 'number' || count >= MAX_JOURNAL_COMMANDS) throw new ProbeError('rate.limited')
      const pendingCount = this.database.prepare('SELECT COUNT(*) AS count FROM commands WHERE runtime_id = ? AND payload_ciphertext IS NOT NULL').get(this.runtimeId)?.count
      if (typeof pendingCount !== 'number' || pendingCount >= MAX_PENDING_JOURNAL_COMMANDS) throw new ProbeError('rate.limited')
      const encrypted = encrypt(this.key, this.runtimeId, owner, command.request_id, 'command', digest, command)
      const now = Date.now()
      this.database.prepare(`
        INSERT INTO commands (runtime_id, user_id, device_id, request_id, payload_sha256,
          payload_nonce, payload_ciphertext, payload_tag, state, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'host_accepted', ?, ?)
      `).run(this.runtimeId, owner.userId, owner.deviceId, command.request_id, digest,
        encrypted.nonce, encrypted.ciphertext, encrypted.tag, now, now)
      admission = { inserted: true, state: 'host_accepted', digest }
    })
    if (admission === undefined) throw new ProbeError('journal.integrity_failed')
    return admission
  }

  start(requestId: string, owner: CommandOwner): void {
    this.transition(requestId, owner, 'dispatching')
  }

  complete(requestId: string, owner: CommandOwner, state: 'agent_queued' | 'settled', result: unknown): void {
    const row = this.select(requestId, owner)
    if (!transitionAllowed(row.state, state)) {
      if (row.state === state) return
      throw new ProbeError('journal.invalid_transition')
    }
    const encrypted = encrypt(this.key, this.runtimeId, owner, requestId, 'result', row.digest, result)
    this.transaction(() => {
      this.database.prepare(`
        UPDATE commands SET state = ?, payload_nonce = NULL, payload_ciphertext = NULL, payload_tag = NULL,
          result_nonce = ?, result_ciphertext = ?, result_tag = ?, error_code = NULL, updated_at = ?
        WHERE runtime_id = ? AND user_id = ? AND device_id = ? AND request_id = ?
      `).run(state, encrypted.nonce, encrypted.ciphertext, encrypted.tag, Date.now(), this.runtimeId, owner.userId, owner.deviceId, requestId)
    })
  }

  fail(requestId: string, owner: CommandOwner, state: 'rejected' | 'outcome_unknown', errorCode: string): void {
    const row = this.select(requestId, owner)
    if (!transitionAllowed(row.state, state)) {
      if (row.state === state && row.errorCode === errorCode) return
      throw new ProbeError('journal.invalid_transition')
    }
    this.transaction(() => {
      this.database.prepare(`UPDATE commands SET state = ?,
        payload_nonce = CASE WHEN ? = 'rejected' THEN NULL ELSE payload_nonce END,
        payload_ciphertext = CASE WHEN ? = 'rejected' THEN NULL ELSE payload_ciphertext END,
        payload_tag = CASE WHEN ? = 'rejected' THEN NULL ELSE payload_tag END,
        error_code = ?, updated_at = ?
        WHERE runtime_id = ? AND user_id = ? AND device_id = ? AND request_id = ?`)
        .run(state, state, state, state, errorCode.slice(0, 128), Date.now(), this.runtimeId, owner.userId, owner.deviceId, requestId)
    })
  }

  get(requestId: string, owner: CommandOwner): { command?: Command; state: CommandState; result?: unknown; errorCode?: string } | undefined {
    const row = this.database.prepare(`
      SELECT user_id, payload_sha256, payload_nonce, payload_ciphertext, payload_tag,
             result_nonce, result_ciphertext, result_tag, state, error_code
      FROM commands WHERE runtime_id = ? AND device_id = ? AND request_id = ?
    `).get(this.runtimeId, owner.deviceId, requestId) as JournalRow | undefined
    if (row === undefined) return undefined
    if (row.user_id !== owner.userId) throw new ProbeError('access.denied')
    if (!isCommandState(row.state)) throw new ProbeError('journal.integrity_failed')
    const digest = row.payload_sha256
    const encryptedCommand = rowCiphertext(row, 'command')
    const command = encryptedCommand === undefined ? undefined : decrypt<Command>(this.key, this.runtimeId, owner, requestId, 'command', digest, encryptedCommand)
    const encryptedResult = rowCiphertext(row, 'result')
    const result = encryptedResult === undefined ? undefined : decrypt<unknown>(this.key, this.runtimeId, owner, requestId, 'result', digest, encryptedResult)
    return {
      ...(command === undefined ? {} : { command }), state: row.state, result,
      ...(row.error_code === null ? {} : { errorCode: row.error_code }),
    }
  }

  close(): void {
    if (!this.database.isOpen) return
    try { this.database.exec('PRAGMA wal_checkpoint(TRUNCATE)') }
    finally {
      this.database.close()
      this.key.fill(0)
    }
  }

  private transition(requestId: string, owner: CommandOwner, state: CommandState): void {
    const row = this.select(requestId, owner)
    if (!transitionAllowed(row.state, state)) {
      if (row.state === state) return
      throw new ProbeError('journal.invalid_transition')
    }
    this.transaction(() => {
      this.database.prepare('UPDATE commands SET state = ?, updated_at = ? WHERE runtime_id = ? AND user_id = ? AND device_id = ? AND request_id = ?')
        .run(state, Date.now(), this.runtimeId, owner.userId, owner.deviceId, requestId)
    })
  }

  private select(requestId: string, owner: CommandOwner): { digest: string; state: CommandState; errorCode: string | null } {
    const row = this.database.prepare('SELECT user_id, payload_sha256, state, error_code FROM commands WHERE runtime_id = ? AND device_id = ? AND request_id = ?')
      .get(this.runtimeId, owner.deviceId, requestId) as { user_id: string; payload_sha256: string; state: unknown; error_code: string | null } | undefined
    if (row === undefined || !isCommandState(row.state)) throw new ProbeError('journal.record_not_found')
    if (row.user_id !== owner.userId) throw new ProbeError('access.denied')
    return { digest: row.payload_sha256, state: row.state, errorCode: row.error_code }
  }

  private transaction(callback: () => void): void {
    this.database.exec('BEGIN IMMEDIATE')
    try {
      callback()
      this.database.exec('COMMIT')
    } catch (error) {
      try { this.database.exec('ROLLBACK') } catch { /* Preserve the original failure. */ }
      throw error
    }
  }
}

/** Test and short-lived local probes use this adapter; enabled desktop plugins use SQLite. */
export class MemoryCommandJournal implements CommandJournal {
  private readonly rows = new Map<string, { digest: string; state: CommandState; result?: unknown; errorCode?: string }>()
  constructor(private readonly runtimeId: string) {}

  admit(command: Command, owner: CommandOwner): JournalAdmission {
    validateOwner(owner)
    const digest = commandDigest(command)
    const key = `${this.runtimeId}\0${owner.userId}\0${owner.deviceId}\0${command.request_id}`
    const existing = this.rows.get(key)
    if (existing !== undefined) {
      if (existing.digest !== digest) throw new ProbeError('command.request_conflict')
      return { inserted: false, ...existing }
    }
    if (this.rows.size >= MAX_JOURNAL_COMMANDS) throw new ProbeError('rate.limited')
    this.rows.set(key, { digest, state: 'host_accepted' })
    return { inserted: true, digest, state: 'host_accepted' }
  }

  start(requestId: string, owner: CommandOwner): void { this.transition(requestId, owner, 'dispatching') }
  complete(requestId: string, owner: CommandOwner, state: 'agent_queued' | 'settled', result: unknown): void {
    const row = this.find(requestId, owner)
    if (!transitionAllowed(row.state, state)) {
      if (row.state === state) return
      throw new ProbeError('journal.invalid_transition')
    }
    Object.assign(row, { state, result, errorCode: undefined })
  }
  fail(requestId: string, owner: CommandOwner, state: 'rejected' | 'outcome_unknown', errorCode: string): void {
    const row = this.find(requestId, owner)
    if (!transitionAllowed(row.state, state)) {
      if (row.state === state && row.errorCode === errorCode) return
      throw new ProbeError('journal.invalid_transition')
    }
    Object.assign(row, { state, errorCode })
  }
  close(): void {}

  private transition(requestId: string, owner: CommandOwner, state: CommandState): void {
    const row = this.find(requestId, owner)
    if (!transitionAllowed(row.state, state)) {
      if (row.state === state) return
      throw new ProbeError('journal.invalid_transition')
    }
    row.state = state
  }
  private find(requestId: string, owner: CommandOwner) {
    const row = this.rows.get(`${this.runtimeId}\0${owner.userId}\0${owner.deviceId}\0${requestId}`)
    if (row === undefined) throw new ProbeError('journal.record_not_found')
    return row
  }
}
