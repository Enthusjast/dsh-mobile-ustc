import { createHash } from 'node:crypto'
import canonicalize from 'canonicalize'
import { z } from 'zod'
import { fileManifest } from './file-admission.js'
import { exportLease, exportNode } from './export-protocol.js'
import { MAX_IMAGE_BYTES, MAX_IMAGE_PIXELS, MAX_IMAGE_DIMENSION, imageMediaType } from './image-protocol.js'

export const visibleMediaReference = z.strictObject({
  v: z.literal(1), origin: z.literal('session_attachment'), native_seq: z.int().min(0).max(Number.MAX_SAFE_INTEGER),
  part_index: z.int().min(0).max(4095), event_version_sha256: fileManifest.shape.sha256,
  manifest: fileManifest.extend({ size_bytes: z.int().min(1).max(MAX_IMAGE_BYTES) }),
  media_type: imageMediaType, width: z.int().min(1).max(MAX_IMAGE_DIMENSION), height: z.int().min(1).max(MAX_IMAGE_DIMENSION),
}).refine(value => value.width * value.height <= MAX_IMAGE_PIXELS)
export type VisibleMediaReference = z.infer<typeof visibleMediaReference>
export const mediaResolveRequest = z.strictObject({ sync_id: z.uuid(), reference: visibleMediaReference })
export const hostMediaResolveRequest = exportLease.extend({ sync_id: z.uuid(), reference: visibleMediaReference, allow_workspace: z.literal(false) })
export const mediaResolveResult = z.strictObject({ reference: visibleMediaReference, source: exportNode }).refine(value =>
  value.source.kind === 'file' && value.source.origin === 'session_attachment' && value.source.unavailable === undefined &&
  value.source.name === value.reference.manifest.name && value.source.size_bytes === value.reference.manifest.size_bytes)
export const mediaErrors = z.enum(['access.denied', 'runtime.changed', 'runtime.offline', 'protocol.unsupported', 'protocol.invalid',
  'protocol.resync_required', 'rate.limited', 'file.export_unavailable', 'file.export_changed', 'file.export_unsupported', 'file.too_large',
  'file.unavailable', 'file.state_changed', 'session.persistence_unavailable'])
export const hostMediaFrame = z.strictObject({
  v: z.literal(1), type: z.literal('session.media.resolve'), request_id: z.uuid(), runtime_id: z.uuid(), runtime_epoch: z.uuid(),
  session_id: z.uuid(), subscription_id: z.uuid(), payload: hostMediaResolveRequest,
})
export type HostMediaResolveFrame = z.infer<typeof hostMediaFrame>

/** Version of the ordinary visibility-filtered event, before adding opt-in media blocks. */
export function mediaEventVersion(event: unknown): string {
  const canonical = canonicalize(event)
  if (canonical === undefined) throw new Error('invalid projected media event')
  return createHash('sha256').update(canonical).digest('hex')
}
