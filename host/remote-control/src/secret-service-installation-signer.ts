import { LinuxSecretServiceLookup, type LinuxSecretServiceReference } from './linux-secret-service.js'
import { PreprovisionedInstallationSigner, type InstallationPublicJwk } from './preprovisioned-installation-signer.js'

export interface LinuxSecretServiceInstallationSignerOptions extends LinuxSecretServiceReference {
  /** Registered installation public key; changing the stored key cannot silently change identity. */
  publicJwk: InstallationPublicJwk
  /** Cancel on logout, installation replacement or loss of key ownership. */
  ownerSignal: AbortSignal
}

/** Reads the preprovisioned PKCS#8 P-256 key for each bounded signing operation. */
export class LinuxSecretServiceInstallationSigner extends PreprovisionedInstallationSigner {
  constructor(options: LinuxSecretServiceInstallationSignerOptions) {
    try {
      super({ lookup: new LinuxSecretServiceLookup(options), publicJwk: options.publicJwk, ownerSignal: options.ownerSignal,
        typeName: 'LinuxSecretServiceInstallationSigner', reason: 'installation Secret Service signing unavailable' })
    } catch { throw new Error('installation Secret Service signing unavailable') }
  }
}
