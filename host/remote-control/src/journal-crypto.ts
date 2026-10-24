import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { ProbeError } from './protocol.js'

export type Ciphertext = { nonce: Buffer; ciphertext: Buffer; tag: Buffer }

export function encryptJournalBytes(key: Buffer, aad: Uint8Array, plaintext: Uint8Array): Ciphertext {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(aad)
  return { nonce, ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]), tag: cipher.getAuthTag() }
}

export function decryptJournalBytes(key: Buffer, aad: Uint8Array, value: Ciphertext): Buffer {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, value.nonce)
    decipher.setAAD(aad)
    decipher.setAuthTag(value.tag)
    return Buffer.concat([decipher.update(value.ciphertext), decipher.final()])
  } catch { throw new ProbeError('journal.integrity_failed') }
}
