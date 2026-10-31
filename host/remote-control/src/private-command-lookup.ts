import { spawn } from 'node:child_process'
import { lstat, realpath } from 'node:fs/promises'
import { dirname, isAbsolute, resolve } from 'node:path'

const unavailable = () => new Error('private key lookup unavailable')

export async function assertTrustedExecutable(path: string): Promise<void> {
  try {
    if (!isAbsolute(path) || path.includes('\0') || Buffer.byteLength(path) > 4096 || await realpath(path) !== resolve(path)) throw unavailable()
    const executable = await lstat(path), uid = process.getuid?.()
    if (uid === undefined || !executable.isFile() || executable.isSymbolicLink() ||
        (executable.uid !== 0 && executable.uid !== uid) ||
        (executable.mode & 0o7022) !== 0 || (executable.mode & 0o111) === 0) throw unavailable()
    await assertTrustedParentDirectories(path)
  } catch { throw unavailable() }
}

export async function assertTrustedParentDirectories(path: string): Promise<void> {
  try {
    const uid = process.getuid?.()
    if (uid === undefined) throw unavailable()
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

export function sanitizedEnvironment(): NodeJS.ProcessEnv {
  const result = { ...process.env }
  for (const name of Object.keys(result)) if (name.startsWith('LD_') || name.startsWith('DYLD_') || name === 'NODE_OPTIONS' || name === 'PYTHONPATH' || name === 'PYTHONHOME') delete result[name]
  return result
}

/** Internal read-only lookup. Returned bytes belong to the caller and must be cleared. */
export class PrivateCommandLookup {
  #executable: string
  #arguments: string[]
  #additionalCheck: (() => Promise<void>) | undefined
  #pendingChecks = 0
  #pendingChildren = 0

  constructor(executable: string, args: readonly string[], platform: 'linux' | 'darwin', additionalCheck?: () => Promise<void>) {
    if (process.platform !== platform || typeof executable !== 'string' || !isAbsolute(executable)
      || !Array.isArray(args) || args.length > 16 || args.some(value => typeof value !== 'string' || value.includes('\0') || Buffer.byteLength(value) > 4096)) throw unavailable()
    this.#executable = resolve(executable)
    this.#arguments = [...args]
    this.#additionalCheck = additionalCheck
  }

  async lookup(maxOutput: number, signal: AbortSignal): Promise<Buffer> {
    if (!(signal instanceof AbortSignal) || signal.aborted || !Number.isSafeInteger(maxOutput) || maxOutput < 1 || maxOutput > 4096) throw unavailable()
    // Filesystem metadata on an unavailable mount may not respond to abort.
    // Bound the caller's wait and keep its slot until that check actually ends.
    if (this.#pendingChecks >= 8) throw unavailable()
    this.#pendingChecks++
    const checks = [assertTrustedExecutable(this.#executable)]
    if (this.#additionalCheck) checks.push(Promise.resolve().then(this.#additionalCheck))
    const check = Promise.allSettled(checks).then(results => { if (results.some(result => result.status === 'rejected')) throw unavailable() }).finally(() => { this.#pendingChecks-- })
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
    return await new Promise<Buffer>((resolveResult, rejectResult) => {
      if (this.#pendingChildren >= 8) { rejectResult(unavailable()); return }
      this.#pendingChildren++
      const launch = () => spawn(this.#executable, this.#arguments, { shell: false, env: sanitizedEnvironment(), stdio: ['ignore', 'pipe', 'ignore'] })
      let child: ReturnType<typeof launch>
      try { child = launch() } catch { this.#pendingChildren--; rejectResult(unavailable()); return }
      child.once('close', () => { this.#pendingChildren-- })
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
        if (error || !value) { child.stdout.destroy(); rejectResult(unavailable()) }
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
        if (total > maxOutput) { copy.fill(0); stop(); finish(unavailable()); return }
        parts.push(copy)
      })
      child.on('close', code => {
        if (killTimer) clearTimeout(killTimer)
        if (settled) return
        if (code !== 0) { finish(unavailable()); return }
        finish(undefined, Buffer.concat(parts))
      })
      if (signal.aborted) abort()
    })
  }
}
