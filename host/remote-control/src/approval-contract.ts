import { z } from 'zod'
import { createHash } from 'node:crypto'
import { canonicalObject } from './canonical.js'

export const APPROVAL_CONTEXT_DOMAIN = 'dsh-mobile-ustc/approval-context/v1'
export const APPROVAL_DECISION_DOMAIN = 'dsh-mobile-ustc/approval-decision/v1'
export const APPROVAL_JWS_TYPE = 'dsh-approval-decision+jws'
export const MAX_APPROVAL_LIFETIME_MS = 180_000
export const APPROVAL_CLOCK_SKEW_MS = 5000
export const MAX_DECISION_AGE_MS = 30_000
const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
const sha256 = z.string().regex(/^[0-9a-f]{64}$/)
const nonce = z.string().regex(/^[A-Za-z0-9_-]{43}$/)
const version = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER)
const utc = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/).refine(value => {
  const time = Date.parse(value)
  return Number.isFinite(time) && new Date(time).toISOString() === value
})
const boundedText = (bytes: number) => z.string().min(1).max(bytes).refine(value => Buffer.byteLength(value) <= bytes && !/[\u0000-\u001f\u007f]/u.test(value))
const identity = { host_id: uuid, installation_id: uuid, runtime_id: uuid, runtime_epoch: uuid, session_id: uuid, approval_id: uuid, execution_id: uuid }

export const ApprovalContext = z.strictObject({
  domain: z.literal(APPROVAL_CONTEXT_DOMAIN), protocol_version: z.literal(1), ...identity,
  dsh_session_id: boundedText(2048), call_id: boundedText(2048), tool: boundedText(128), arguments: z.json(),
  workspace: z.strictObject({ workspace_id: uuid, root_sha256: sha256 }),
  resources: z.array(z.strictObject({ kind: z.enum(['file', 'repository', 'artifact']), resource_id: boundedText(2048), version_sha256: sha256 })).max(256),
  nonce, policy_version: version,
  required_assurance: z.strictObject({ profile: z.string().regex(/^[a-z0-9][a-z0-9./_-]{0,127}$/), max_auth_age_seconds: z.number().int().min(0).max(900) }),
  created_at: utc, expires_at: utc,
}).superRefine((context, issue) => {
  const lifetime = Date.parse(context.expires_at) - Date.parse(context.created_at)
  if (lifetime <= 0 || lifetime > MAX_APPROVAL_LIFETIME_MS) issue.addIssue({ code: 'custom', message: 'approval lifetime is invalid' })
  if (new Set(context.resources.map(item => `${item.kind}\0${item.resource_id}`)).size !== context.resources.length) issue.addIssue({ code: 'custom', message: 'duplicate resource facts' })
  if (Buffer.from(context.nonce, 'base64url').toString('base64url') !== context.nonce) issue.addIssue({ code: 'custom', message: 'noncanonical nonce' })
})
export type ApprovalContext = z.infer<typeof ApprovalContext>

export const ApprovalDecision = z.strictObject({
  domain: z.literal(APPROVAL_DECISION_DOMAIN), protocol_version: z.literal(1), ...identity,
  binding_sha256: sha256, decision: z.enum(['allow_once', 'reject']), user_id: uuid, device_id: uuid,
  key_version: version, policy_version: version, nonce, issued_at: utc, expires_at: utc,
})
export type ApprovalDecision = z.infer<typeof ApprovalDecision>

export function approvalBinding(value: unknown): { context: ApprovalContext; canonical: Uint8Array; sha256: string } {
  const canonical = canonicalObject(value)
  const context = ApprovalContext.parse(value)
  return { context, canonical, sha256: createHash('sha256').update(canonical).digest('hex') }
}

export function approvalKeyID(deviceId: string, keyVersion: number): string { return `dsh-approval/${deviceId}/${keyVersion}` }
