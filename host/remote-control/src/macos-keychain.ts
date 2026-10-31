import { lstat, realpath } from 'node:fs/promises'
import { isAbsolute, resolve } from 'node:path'
import { assertTrustedParentDirectories, PrivateCommandLookup } from './private-command-lookup.js'

export interface MacOSKeychainReference {
  /** Trusted absolute path to security, normally /usr/bin/security. */
  executable: string
  /** Explicit private current-user Keychain file; no search-list fallback. */
  keychainPath: string
  /** Exact non-secret lookup attributes for the preprovisioned item. */
  service: string
  account: string
}

const ATTRIBUTE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const unavailable = () => new Error('Keychain unavailable')

async function privateKeychain(path: string): Promise<void> {
  const metadata = await lstat(path), uid = process.getuid?.()
  if (uid === undefined || !metadata.isFile() || metadata.isSymbolicLink() || metadata.uid !== uid || metadata.nlink !== 1
    || (metadata.mode & 0o7777) !== 0o600 || await realpath(path) !== path) throw unavailable()
  await assertTrustedParentDirectories(path)
}

export function keychainReference(options: MacOSKeychainReference): Readonly<MacOSKeychainReference> {
  if (process.platform !== 'darwin' || !options) throw unavailable()
  const { executable, keychainPath: referencePath, service, account } = options
  if (typeof executable !== 'string' || !isAbsolute(executable) || typeof referencePath !== 'string' || !isAbsolute(referencePath)
    || referencePath.includes('\0') || Buffer.byteLength(referencePath) > 4096 || typeof service !== 'string' || !ATTRIBUTE.test(service)
    || typeof account !== 'string' || !ATTRIBUTE.test(account)) throw unavailable()
  return Object.freeze({ executable, keychainPath: resolve(referencePath), service, account })
}

/** Internal read-only Keychain lookup shared by distinct key purposes. */
export class MacOSKeychainLookup {
  #lookup: PrivateCommandLookup
  constructor(options: MacOSKeychainReference) {
    const reference = keychainReference(options)
    this.#lookup = new PrivateCommandLookup(reference.executable,
      ['find-generic-password', '-s', reference.service, '-a', reference.account, '-w', reference.keychainPath],
      'darwin', () => privateKeychain(reference.keychainPath))
  }
  async lookup(maxOutput: number, signal: AbortSignal): Promise<Buffer> {
    try { return await this.#lookup.lookup(maxOutput, signal) } catch { throw unavailable() }
  }
}
