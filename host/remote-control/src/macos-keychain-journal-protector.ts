import { createHash } from 'node:crypto'
import { lstat, realpath } from 'node:fs/promises'
import { isAbsolute, resolve } from 'node:path'
import { assertTrustedParentDirectories, PrivateCommandLookup } from './private-command-lookup.js'
import { PreprovisionedJournalProtector } from './preprovisioned-journal-protector.js'

export interface MacOSKeychainJournalOptions {
  /** Trusted absolute path to security, normally /usr/bin/security. */
  executable: string
  /** Explicit current-user Keychain file; no default search-list fallback. */
  keychainPath: string
  /** Exact non-secret attributes of a preprovisioned Base64 32-byte master key. */
  service: string
  account: string
}
const ATTRIBUTE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const unavailable = () => new Error('journal Keychain protection unavailable')

async function privateKeychain(path: string): Promise<void> {
  const metadata = await lstat(path), uid = process.getuid?.()
  if (uid === undefined || !metadata.isFile() || metadata.isSymbolicLink() || metadata.uid !== uid || metadata.nlink !== 1
    || (metadata.mode & 0o7777) !== 0o600 || await realpath(path) !== path) throw unavailable()
  await assertTrustedParentDirectories(path)
}

/** Optional macOS read-only adapter. It neither creates nor overwrites Keychain items.
 * Native Keychain UI/ACL behaviour still requires target-platform acceptance. */
export class MacOSKeychainJournalProtector extends PreprovisionedJournalProtector {
  constructor(options: MacOSKeychainJournalOptions) {
    try {
      if (process.platform !== 'darwin' || !options) throw unavailable()
      const { executable, keychainPath: referencePath, service, account } = options
      if (typeof executable !== 'string' || !isAbsolute(executable) || typeof referencePath !== 'string' || !isAbsolute(referencePath)
        || referencePath.includes('\0') || Buffer.byteLength(referencePath) > 4096 || typeof service !== 'string' || !ATTRIBUTE.test(service)
        || typeof account !== 'string' || !ATTRIBUTE.test(account)) throw unavailable()
      const keychainPath = resolve(referencePath)
      const lookup = new PrivateCommandLookup(executable, ['find-generic-password', '-s', service, '-a', account, '-w', keychainPath],
        'darwin', () => privateKeychain(keychainPath))
      const digest = createHash('sha256').update('dsh-keychain-reference-v1\0').update(keychainPath).update('\0').update(service).update('\0').update(account).digest('hex')
      super({ id: `keychain-${digest.slice(0, 32)}`, magic: 'DSHKCK01', domain: 'dsh-keychain-journal-wrap-v1\0',
        typeName: 'MacOSKeychainJournalProtector', reason: 'journal Keychain protection unavailable', lookup })
    } catch { throw unavailable() }
  }
}
