import { z } from 'zod'
import { fileManifest } from './file-admission.js'
import { MAX_EXPORT_FILE_BYTES } from './file-export-source.js'

export const EXPORT_CAPABILITY = 'file.export.v1'
const uuid = z.uuid(), date = z.string().datetime({ offset: true })
export const exportOrigin = z.enum(['session_attachment', 'workspace_artifact'])
export const exportManifest = fileManifest.extend({ size_bytes: z.int().min(0).max(MAX_EXPORT_FILE_BYTES) })
export const exportErrors = z.enum(['access.denied', 'runtime.changed', 'runtime.offline', 'protocol.unsupported', 'protocol.invalid', 'rate.limited',
  'file.export_unavailable', 'file.export_changed', 'file.export_unsupported', 'file.too_large', 'file.unavailable', 'file.scanner_unavailable', 'file.quota_exceeded', 'file.state_changed', 'command.request_conflict'])
const base = { v: z.literal(1), request_id: uuid, runtime_id: uuid }
const session = { ...base, runtime_epoch: uuid, session_id: uuid }
export const exportLease = z.strictObject({ user_id: uuid, device_id: uuid, key_version: z.int().positive(), grant_version: z.int().positive(),
  allow_workspace: z.boolean(), lease_until: date, expires_at: date })
export const exportNode = z.discriminatedUnion('kind', [
  z.strictObject({ source_id: uuid, kind: z.literal('file'), origin: exportOrigin, name: fileManifest.shape.name, size_bytes: z.int().min(0).max(Number.MAX_SAFE_INTEGER), expires_at: date, unavailable: z.literal('file.too_large').optional() }),
  z.strictObject({ source_id: uuid, kind: z.literal('directory'), origin: exportOrigin, name: fileManifest.shape.name, expires_at: date }),
])
export type ExportNode = z.infer<typeof exportNode>
export const exportPage = z.strictObject({ items: z.array(exportNode).max(16), directory_id: uuid.nullable(), cursor: uuid.nullable() })
export type ExportPage = z.infer<typeof exportPage>
export const exportStatus = z.strictObject({ file_id: uuid, runtime_id: uuid, session_id: uuid, direction: z.literal('from_host'),
  name: fileManifest.shape.name, size_bytes: z.int().min(0).max(MAX_EXPORT_FILE_BYTES), sha256: fileManifest.shape.sha256,
  state: z.enum(['uploading', 'scanning', 'clean', 'rejected', 'expired']), error_code: z.enum(['integrity_mismatch', 'content_rejected', 'scan_unavailable', 'storage_unavailable', 'access_revoked', 'expired']).optional(),
  upload_expires_at: date, expires_at: date, created_at: date })
export const exportCapability = z.strictObject({ url: z.string().max(16_384), method: z.literal('PUT'), headers: z.record(z.string(), z.string()), expires_at: date })

export const PhoneExportFrame = z.discriminatedUnion('type', [
  z.strictObject({ ...session, type: z.literal('file.exports.list'), payload: z.strictObject({ directory_id: uuid.optional(), cursor: uuid.optional() }) }),
  z.strictObject({ ...session, type: z.literal('file.export.request'), payload: z.strictObject({ source_id: uuid }) }),
  z.strictObject({ ...session, type: z.literal('file.export.cancel'), payload: z.strictObject({}) }),
])
export const HostExportFrame = z.discriminatedUnion('type', [
  z.strictObject({ ...session, type: z.literal('file.exports.list'), payload: exportLease.extend({ directory_id: uuid.optional(), cursor: uuid.optional() }) }),
  z.strictObject({ ...session, type: z.literal('file.exports.result'), payload: exportPage }),
  z.strictObject({ ...session, type: z.literal('file.export.request'), payload: exportLease.extend({ origin_request_id: uuid, source_id: uuid }) }),
  z.strictObject({ ...session, type: z.literal('file.export.manifest'), payload: exportManifest.extend({ source_id: uuid, origin: exportOrigin, source_expires_at: date }) }),
  z.strictObject({ ...session, type: z.literal('file.export.upload'), payload: z.strictObject({ file: exportStatus, upload: exportCapability.optional() }) }),
  z.strictObject({ ...session, type: z.literal('file.export.uploaded'), payload: z.strictObject({ file_id: uuid }) }),
  z.strictObject({ ...session, type: z.literal('file.export.committed'), payload: z.strictObject({ file_id: uuid }) }),
  z.strictObject({ ...session, type: z.literal('file.export.abort'), payload: z.strictObject({ code: exportErrors }) }),
  z.strictObject({ ...session, type: z.literal('file.export.error'), payload: z.strictObject({ code: exportErrors }) }),
  z.strictObject({ ...base, runtime_epoch: uuid, type: z.literal('file.export.renew'), payload: z.strictObject({ operation_ids: z.array(uuid).min(1).max(8) }) }),
  z.strictObject({ ...base, runtime_epoch: uuid, type: z.literal('file.export.renewed'), payload: z.strictObject({ leases: z.array(z.strictObject({ operation_id: uuid, lease_until: date, expires_at: date })).max(8) }) }),
])
export const ExportReplyFrame = z.discriminatedUnion('type', [
  z.strictObject({ ...session, type: z.literal('file.exports.result'), payload: exportPage }),
  z.strictObject({ ...session, type: z.literal('file.export.accepted'), payload: z.strictObject({ file: exportStatus }) }),
  z.strictObject({ ...session, type: z.literal('file.export.error'), payload: z.strictObject({ code: exportErrors }) }),
])
export const ExportFrame = z.union([PhoneExportFrame, HostExportFrame, ExportReplyFrame])
export type PhoneExportFrame = z.infer<typeof PhoneExportFrame>
export type HostExportFrame = z.infer<typeof HostExportFrame>
