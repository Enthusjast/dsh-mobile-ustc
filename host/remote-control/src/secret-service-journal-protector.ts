import { createHash } from 'node:crypto'
import { LinuxSecretServiceLookup, type LinuxSecretServiceReference } from './linux-secret-service.js'
import { PreprovisionedJournalProtector } from './preprovisioned-journal-protector.js'

export interface LinuxSecretServiceJournalOptions extends LinuxSecretServiceReference {
  /** Trusted absolute path to the system secret-tool executable. */
  executable: string
  /** Stable, non-secret lookup attributes for a preprovisioned 32-byte key. */
  service: string
  account: string
}

/** Reads the preprovisioned key. Existing IDs, derivation and ciphertext remain unchanged. */
export class LinuxSecretServiceJournalProtector extends PreprovisionedJournalProtector {
  constructor(options: LinuxSecretServiceJournalOptions) {
    try {
      const reference = { executable: options.executable, service: options.service, account: options.account }
      const lookup = new LinuxSecretServiceLookup(reference)
      const digest = createHash('sha256').update('dsh-secret-service-reference-v1\0').update(reference.service).update('\0').update(reference.account).digest('hex')
      super({ id: `secret-service-${digest.slice(0, 32)}`, magic: 'DSHSSK01', domain: 'dsh-secret-service-journal-wrap-v1\0',
        typeName: 'LinuxSecretServiceJournalProtector', reason: 'journal Secret Service protection unavailable', lookup })
    } catch { throw new Error('journal Secret Service protection unavailable') }
  }
}
