import { spawn } from 'node:child_process'
import { isAbsolute, resolve } from 'node:path'
import { assertTrustedExecutable, sanitizedEnvironment, PrivateCommandLookup } from './private-command-lookup.js'

export interface LinuxSecretServiceReference {
  executable: string
  service: string
  account: string
}

const ATTRIBUTE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const unavailable = () => new Error('Secret Service unavailable')

/** Internal read-only lookup. Returned bytes belong to the caller and must be cleared. */
export class LinuxSecretServiceLookup {
  #lookup: PrivateCommandLookup
  constructor(options: LinuxSecretServiceReference) {
    if (process.platform !== 'linux' || !options) throw unavailable()
    const { executable, service, account } = options
    if (typeof executable !== 'string' || !isAbsolute(executable) || typeof service !== 'string' || !ATTRIBUTE.test(service)
      || typeof account !== 'string' || !ATTRIBUTE.test(account)) throw unavailable()
    try { this.#lookup = new PrivateCommandLookup(executable, ['lookup', 'service', service, 'account', account], 'linux') }
    catch { throw unavailable() }
  }
  async lookup(maxOutput: number, signal: AbortSignal): Promise<Buffer> {
    try { return await this.#lookup.lookup(maxOutput, signal) } catch { throw unavailable() }
  }
}

/** Internal writer for a newly generated, unguessable reference. No secret is
 * passed in arguments or logged; a failed/aborted store may have created an item. */
export class LinuxSecretServiceWriter {
  #reference: LinuxSecretServiceReference
  #pendingChecks = 0

  constructor(options: LinuxSecretServiceReference) {
    const reference = { executable: options.executable, service: options.service, account: options.account }
    new LinuxSecretServiceLookup(reference) // Reuse the same strict reference validation.
    this.#reference = { ...reference, executable: resolve(reference.executable) }
  }

  async store(secret: Uint8Array, signal: AbortSignal): Promise<void> {
    if (!(secret instanceof Uint8Array) || secret.length < 1 || secret.length > 2048 || !(signal instanceof AbortSignal) || signal.aborted || this.#pendingChecks >= 8) throw unavailable()
    const input = Buffer.from(secret)
    try {
      this.#pendingChecks++
      const check = assertTrustedExecutable(this.#reference.executable).finally(() => { this.#pendingChecks-- })
      let removeAbort = () => {}
      try {
        const cancelled = new Promise<never>((_, reject) => {
          const abort = () => reject(unavailable())
          removeAbort = () => signal.removeEventListener('abort', abort)
          signal.addEventListener('abort', abort, { once: true })
          if (signal.aborted) abort()
        })
        await Promise.race([check, cancelled])
      } finally { removeAbort() }
      if (signal.aborted) throw unavailable()
      await new Promise<void>((resolveResult, rejectResult) => {
        const child = spawn(this.#reference.executable, ['store', '--label=DSH remote installation key', 'service', this.#reference.service, 'account', this.#reference.account],
          { shell: false, env: sanitizedEnvironment(), stdio: ['pipe', 'ignore', 'ignore'] })
        let settled = false
        let killTimer: NodeJS.Timeout | undefined
        const stop = () => {
          try { child.kill('SIGTERM') } catch { /* Already exited. */ }
          killTimer = setTimeout(() => { if (child.exitCode === null && child.signalCode === null) { try { child.kill('SIGKILL') } catch { /* Already exited. */ } } }, 250)
          killTimer.unref()
        }
        const finish = (ok: boolean) => {
          if (settled) return
          settled = true; signal.removeEventListener('abort', abort)
          if (ok) resolveResult(); else rejectResult(unavailable())
        }
        const abort = () => { if (!settled) { stop(); finish(false) } }
        signal.addEventListener('abort', abort, { once: true })
        child.on('error', () => { if (!settled) { stop(); finish(false) } })
        child.stdin.on('error', () => { if (!settled) { stop(); finish(false) } })
        child.on('close', code => { if (killTimer) clearTimeout(killTimer); if (!settled) finish(code === 0) })
        child.stdin.end(input, (error?: Error | null) => {
          input.fill(0)
          if (error && !settled) { stop(); finish(false) }
        })
        if (signal.aborted) abort()
      })
    } catch { throw unavailable() } finally { input.fill(0) }
  }
}

function digit(value: number): number {
  if (value >= 65 && value <= 90) return value - 65
  if (value >= 97 && value <= 122) return value - 97 + 26
  if (value >= 48 && value <= 57) return value - 48 + 52
  if (value === 43) return 62
  if (value === 47) return 63
  return -1
}

/** Canonical RFC 4648 base64 without an immutable JavaScript secret string. */
export function encodeSecretBase64(input: Uint8Array): Buffer {
  const alphabet = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
  const result = Buffer.alloc(Math.ceil(input.length / 3) * 4, 61)
  for (let source = 0, target = 0; source < input.length; source += 3, target += 4) {
    const a = input[source]!, b = input[source + 1] ?? 0, c = input[source + 2] ?? 0
    result[target] = alphabet[a >> 2]!
    result[target + 1] = alphabet[((a & 3) << 4) | (b >> 4)]!
    if (source + 1 < input.length) result[target + 2] = alphabet[((b & 15) << 2) | (c >> 6)]!
    if (source + 2 < input.length) result[target + 3] = alphabet[c & 63]!
  }
  return result
}

/** Strict canonical RFC 4648 base64 without creating a JavaScript secret string. */
export function decodeSecretBase64(raw: Buffer, maximumBytes: number): Buffer {
  let end = raw.length
  if (end > 0 && raw[end - 1] === 10) {
    end--
    if (end > 0 && raw[end - 1] === 13) end--
  }
  if (end === 0 || end % 4 !== 0) throw unavailable()
  const padding = raw[end - 1] === 61 ? (raw[end - 2] === 61 ? 2 : 1) : 0
  const size = end / 4 * 3 - padding
  if (size < 1 || size > maximumBytes) throw unavailable()
  const result = Buffer.alloc(size)
  try {
    let output = 0
    for (let index = 0; index < end; index += 4) {
      const a = digit(raw[index]!), b = digit(raw[index + 1]!)
      const c = digit(raw[index + 2]!), d = digit(raw[index + 3]!)
      const last = index + 4 === end
      if (a < 0 || b < 0 || (!last && (c < 0 || d < 0))) throw unavailable()
      result[output++] = (a << 2) | (b >> 4)
      if (last && padding === 2) {
        if (c !== -1 || raw[index + 2] !== 61 || raw[index + 3] !== 61 || (b & 15) !== 0) throw unavailable()
        continue
      }
      if (c < 0) throw unavailable()
      result[output++] = (b << 4) | (c >> 2)
      if (last && padding === 1) {
        if (raw[index + 3] !== 61 || (c & 3) !== 0) throw unavailable()
        continue
      }
      if (d < 0) throw unavailable()
      result[output++] = (c << 6) | d
    }
    return result
  } catch { result.fill(0); throw unavailable() }
}
