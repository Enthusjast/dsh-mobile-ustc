import { createHash } from 'node:crypto'
import { MacOSKeychainLookup, keychainReference, type MacOSKeychainReference } from './macos-keychain.js'
import { PreprovisionedJournalProtector } from './preprovisioned-journal-protector.js'

/** Preprovisioned item must be canonical Base64 decoding to exactly 32 random bytes. */
export interface MacOSKeychainJournalOptions extends MacOSKeychainReference {}

/** Optional read-only adapter; native Keychain UI/ACL behaviour still needs acceptance. */
export class MacOSKeychainJournalProtector extends PreprovisionedJournalProtector {
  constructor(options: MacOSKeychainJournalOptions) {
    try {
      const reference = keychainReference(options), lookup = new MacOSKeychainLookup(reference)
      const digest = createHash('sha256').update('dsh-keychain-reference-v1\0').update(reference.keychainPath).update('\0').update(reference.service).update('\0').update(reference.account).digest('hex')
      super({ id: `keychain-${digest.slice(0, 32)}`, magic: 'DSHKCK01', domain: 'dsh-keychain-journal-wrap-v1\0',
        typeName: 'MacOSKeychainJournalProtector', reason: 'journal Keychain protection unavailable', lookup })
    } catch { throw new Error('journal Keychain protection unavailable') }
  }
}
