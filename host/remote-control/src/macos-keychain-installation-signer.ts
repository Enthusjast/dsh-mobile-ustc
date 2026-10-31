import { MacOSKeychainLookup, type MacOSKeychainReference } from './macos-keychain.js'
import { PreprovisionedInstallationSigner, type InstallationPublicJwk } from './preprovisioned-installation-signer.js'

export interface MacOSKeychainInstallationSignerOptions extends MacOSKeychainReference {
  /** Already registered installation identity; never derive new authority from a replacement item. */
  publicJwk: InstallationPublicJwk
  /** Must end on account change, installation replacement or ownership loss. */
  ownerSignal: AbortSignal
}

/** Optional read-only software signing adapter. No creation, registration, key
 * replacement or Secure Enclave claim; real macOS UI/ACL acceptance is pending. */
export class MacOSKeychainInstallationSigner extends PreprovisionedInstallationSigner {
  constructor(options: MacOSKeychainInstallationSignerOptions) {
    try {
      super({ lookup: new MacOSKeychainLookup(options), publicJwk: options.publicJwk, ownerSignal: options.ownerSignal,
        typeName: 'MacOSKeychainInstallationSigner', reason: 'installation Keychain signing unavailable' })
    } catch { throw new Error('installation Keychain signing unavailable') }
  }
}
