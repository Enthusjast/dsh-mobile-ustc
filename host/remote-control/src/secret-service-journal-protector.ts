import { spawn } from 'node:child_process'
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto'
import { lstat, realpath } from 'node:fs/promises'
import { dirname, isAbsolute, resolve } from 'node:path'
import { inspect } from 'node:util'
import type { JournalKeyProtector } from './journal-key-protection.js'

export interface LinuxSecretServiceJournalOptions {
  /** Trusted absolute path to the system secret-tool executable. */
  executable: string
  /** Stable, non-secret lookup attributes for a preprovisioned 32-byte key. */
  service: string
  account: string
}

const MAGIC = Buffer.from('DSHSSK01')
const ATTRIBUTE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const MAX_OUTPUT = 128
const unavailable = () => new Error('journal Secret Service protection unavailable')

function digit(value: number): number {
  if (value >= 65 && value <= 90) return value - 65
  if (value >= 97 && value <= 122) return value - 97 + 26
  if (value >= 48 && value <= 57) return value - 48 + 52
  if (value === 43) return 62
  if (value === 47) return 63
  return -1
}

// Decode exactly one canonical base64-encoded 32-byte secret without creating
// an immutable JavaScript string containing the key.
function decodeMaster(raw: Buffer): Buffer {
  let end = raw.length
  if (end > 0 && raw[end - 1] === 10) {
    end--
    if (end > 0 && raw[end - 1] === 13) end--
  }
  if (end !== 44 || raw[43] !== 61) throw unavailable()
  const result = Buffer.alloc(32)
  let output = 0
  try {
    for (let index = 0; index < 40; index += 4) {
      const a = digit(raw[index]!), b = digit(raw[index + 1]!), c = digit(raw[index + 2]!), d = digit(raw[index + 3]!)
      if (a < 0 || b < 0 || c < 0 || d < 0) throw unavailable()
      result[output++] = (a << 2) | (b >> 4)
      result[output++] = (b << 4) | (c >> 2)
      result[output++] = (c << 6) | d
    }
    const a = digit(raw[40]!), b = digit(raw[41]!), c = digit(raw[42]!)
    if (a < 0 || b < 0 || c < 0 || (c & 3) !== 0) throw unavailable()
    result[output++] = (a << 2) | (b >> 4)
    result[output++] = (b << 4) | (c >> 2)
    if (output !== 32) throw unavailable()
    return result
  } catch { result.fill(0); throw unavailable() }
}

async function assertTrustedExecutable(path: string): Promise<void> {
  try {
    if (!isAbsolute(path) || path.includes('\0') || Buffer.byteLength(path) > 4096 || await realpath(path) !== resolve(path)) throw unavailable()
    const executable = await lstat(path), uid = process.getuid?.()
    if (uid === undefined || !executable.isFile() || executable.isSymbolicLink() ||
        (executable.uid !== 0 && executable.uid !== uid) ||
        (executable.mode & 0o7022) !== 0 || (executable.mode & 0o111) === 0) throw unavailable()
    // A protected immediate parent is insufficient if another user can
    // replace an ancestor. Sticky directories protect trusted-owned children.
    let directory = dirname(path), immediate = true
    for (;;) {
      const entry = await lstat(directory)
      if (!entry.isDirectory() || entry.isSymbolicLink() || (entry.uid !== 0 && entry.uid !== uid) ||
          ((entry.mode & 0o022) !== 0 && (immediate || (entry.mode & 0o1000) === 0))) throw unavailable()
      const parent = dirname(directory)
      if (parent === directory) break
      directory = parent
      immediate = false
    }
  } catch { throw unavailable() }
}

function sanitizedEnvironment(): NodeJS.ProcessEnv {
  const result = { ...process.env }
  for (const name of Object.keys(result)) if (name.startsWith('LD_') || name.startsWith('DYLD_') || name === 'NODE_OPTIONS' || name === 'PYTHONPATH' || name === 'PYTHONHOME') delete result[name]
  return result
}

async function lookup(executable: string, service: string, account: string, signal: AbortSignal): Promise<Buffer> {
  if (signal.aborted) throw unavailable()
  await assertTrustedExecutable(executable)
  if (signal.aborted) throw unavailable()
  return await new Promise<Buffer>((resolveResult, rejectResult) => {
    const child = spawn(executable, ['lookup', 'service', service, 'account', account], { shell: false, env: sanitizedEnvironment(), stdio: ['ignore', 'pipe', 'ignore'] })
    let settled = false, total = 0
    let killTimer: NodeJS.Timeout | undefined
    const parts: Buffer[] = []
    const clearParts = () => { for (const part of parts) part.fill(0); parts.length = 0 }
    const stop = () => {
      try { child.kill('SIGTERM') } catch { /* The child may have already exited. */ }
      killTimer = setTimeout(() => { if (child.exitCode === null && child.signalCode === null) { try { child.kill('SIGKILL') } catch { /* Already gone. */ } } }, 250)
      killTimer.unref()
    }
    const finish = (error?: Error, value?: Buffer) => {
      if (settled) { value?.fill(0); return }
      settled = true
      signal.removeEventListener('abort', abort)
      clearParts()
      if (error || !value) rejectResult(unavailable())
      else resolveResult(value)
    }
    const abort = () => { if (!settled) { stop(); finish(unavailable()) } }
    signal.addEventListener('abort', abort, { once: true })
    child.on('error', () => { if (!settled) { stop(); finish(unavailable()) } })
    child.stdout.on('error', () => { if (!settled) { stop(); finish(unavailable()) } })
    child.stdout.on('data', (chunk: Buffer) => {
      if (settled) { chunk.fill(0); return }
      const copy = Buffer.from(chunk)
      chunk.fill(0)
      total += copy.length
      if (total > MAX_OUTPUT) { copy.fill(0); stop(); finish(unavailable()); return }
      parts.push(copy)
    })
    child.on('close', code => {
      if (killTimer) clearTimeout(killTimer)
      if (settled) return
      if (code !== 0) { finish(unavailable()); return }
      const raw = Buffer.concat(parts)
      try { finish(undefined, decodeMaster(raw)) }
      catch { finish(unavailable()) }
      finally { raw.fill(0) }
    })
    if (signal.aborted) abort()
  })
}

function subkey(master: Buffer, salt: Uint8Array): Buffer {
  return createHmac('sha256', master).update('dsh-secret-service-journal-wrap-v1\0').update(salt).digest()
}

/** Linux Secret Service adapter. It reads but never creates or replaces the
 * preprovisioned key, and passes no key material in command-line arguments. */
export class LinuxSecretServiceJournalProtector implements JournalKeyProtector {
  readonly id: string
  #executable: string
  #service: string
  #account: string

  constructor(options: LinuxSecretServiceJournalOptions) {
    try {
      if (process.platform !== 'linux' || !options || typeof options.executable !== 'string' || !isAbsolute(options.executable) ||
          typeof options.service !== 'string' || !ATTRIBUTE.test(options.service) || typeof options.account !== 'string' || !ATTRIBUTE.test(options.account)) throw unavailable()
      // Execute the same normalized path whose components are checked.
      this.#executable = resolve(options.executable)
      this.#service = options.service
      this.#account = options.account
      const reference = createHash('sha256').update('dsh-secret-service-reference-v1\0').update(options.service).update('\0').update(options.account).digest('hex')
      this.id = `secret-service-${reference.slice(0, 32)}`
    } catch { throw unavailable() }
  }

  toString(): string { return 'LinuxSecretServiceJournalProtector' }
  [inspect.custom](): string { return this.toString() }
  toJSON(): object { return { type: 'LinuxSecretServiceJournalProtector', id: this.id } }

  async wrap(key: Uint8Array, context: Uint8Array, signal: AbortSignal): Promise<Uint8Array> {
    if (!(key instanceof Uint8Array) || key.length !== 32 || !(context instanceof Uint8Array) || context.length === 0 || context.length > 16 * 1024 || !(signal instanceof AbortSignal)) throw unavailable()
    const keyCopy = Buffer.from(key), contextCopy = Buffer.from(context)
    let master: Buffer | undefined, derived: Buffer | undefined, aad: Buffer | undefined
    try {
      master = await lookup(this.#executable, this.#service, this.#account, signal)
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
      master = await lookup(this.#executable, this.#service, this.#account, signal)
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
