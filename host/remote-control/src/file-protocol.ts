import { createHash, randomUUID } from 'node:crypto'
import { z } from 'zod'
import { fileManifest, MAX_UPLOAD_FILE_BYTES } from './file-admission.js'
import type { HostHandshakeSigner } from './relay-client.js'

export const FILE_HANDOFF_CAPABILITY = 'file.handoff.v1'
export const FILE_READ_PROOF_TYPE = 'dsh-file-read-proof+jwt'
export const FILE_READ_AUDIENCE = 'urn:dsh-mobile-ustc:file-read'
const uuid = z.uuid(), date = z.string().datetime({ offset: true })
const base = { v: z.literal(1), request_id: uuid, runtime_id: uuid, runtime_epoch: uuid }
const session = { ...base, session_id: uuid }
const ids = { handoff_id: uuid, file_id: uuid }
export const FileOffer = fileManifest.extend({
  ...ids, user_id: uuid, device_id: uuid, key_version: z.int().positive(), grant_version: z.int().positive(),
  size_bytes: z.int().min(0).max(MAX_UPLOAD_FILE_BYTES), download_token: z.string().regex(/^[A-Za-z0-9_-]{43}$/), lease_until: date, expires_at: date,
})
export type FileOffer = z.infer<typeof FileOffer>
export const FileFrame = z.discriminatedUnion('type', [
  z.strictObject({ ...session, type: z.literal('file.offer'), payload: FileOffer }),
  z.strictObject({ ...base, type: z.literal('file.renew'), payload: z.strictObject({ handoff_ids: z.array(uuid).min(1).max(32) }) }),
  z.strictObject({ ...base, type: z.literal('file.renewed'), payload: z.strictObject({ leases: z.array(z.strictObject({ handoff_id: uuid, lease_until: date, expires_at: date })).max(32) }) }),
  z.strictObject({ ...session, type: z.literal('file.staged'), payload: fileManifest.extend(ids) }),
  z.strictObject({ ...session, type: z.literal('file.release'), payload: z.strictObject(ids) }),
  z.strictObject({ ...session, type: z.literal('file.staged.ack'), payload: z.strictObject(ids) }),
  z.strictObject({ ...session, type: z.literal('file.release.ack'), payload: z.strictObject(ids) }),
])
export type FileFrame = z.infer<typeof FileFrame>

export async function fileReadProof(signer: HostHandshakeSigner, identity: {
  installationId: string; runtimeId: string; epoch: string; connectionId: string; handoffId: string; fileId: string; token: string; uri: string
}): Promise<string> {
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url')
  const header = encode({ typ: FILE_READ_PROOF_TYPE, alg: 'ES256' })
  const claims = encode({ iss: identity.installationId, aud: FILE_READ_AUDIENCE, htm: 'GET', htu: identity.uri,
    runtime_id: identity.runtimeId, runtime_epoch: identity.epoch, connection_id: identity.connectionId,
    handoff_id: identity.handoffId, file_id: identity.fileId, ath: createHash('sha256').update(identity.token).digest('base64url'),
    iat: Math.floor(Date.now() / 1000), jti: randomUUID() })
  const input = `${header}.${claims}`
  const signature = await signer.sign(Buffer.from(input))
  if (signature.byteLength !== 64) throw new Error('file proof signature unavailable')
  return `${input}.${Buffer.from(signature).toString('base64url')}`
}
