import { z } from 'zod'
import type { ApprovalContext, ApprovalDecision } from './approval-contract.js'

const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
const utc = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/).refine(value => Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value)

/** Internal trusted-authority result, never a client-supplied authorization assertion. */
export const ApprovalAuthorization = z.strictObject({
  lease_id: uuid, action: z.literal('approval.decide'), role: z.literal('owner'),
  runtime_id: uuid, runtime_epoch: uuid, session_id: uuid, approval_id: uuid, execution_id: uuid,
  binding_sha256: z.string().regex(/^[0-9a-f]{64}$/), policy_version: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  user_id: uuid, device_id: uuid, key_version: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  approval_key_jkt: z.string().regex(/^[A-Za-z0-9_-]{43}$/), grant_version: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  assurance_profile: z.string().regex(/^[a-z0-9][a-z0-9./_-]{0,127}$/),
  authenticated_at: utc, issued_at: utc, expires_at: utc,
})
export type ApprovalAuthorization = z.infer<typeof ApprovalAuthorization>
export type ApprovalAuthorizer = (context: ApprovalContext, decision: ApprovalDecision, signal: AbortSignal) => unknown | Promise<unknown>
export type ApprovalGuardAuthorizer = (context: ApprovalContext, decision: ApprovalDecision) => unknown

export function authorizedApproval(value: unknown, context: ApprovalContext, decision: ApprovalDecision, keyJKT: string, now: number): ApprovalAuthorization | undefined {
  const parsed = ApprovalAuthorization.safeParse(value)
  if (!parsed.success) return undefined
  const lease = parsed.data
  for (const field of ['runtime_id', 'runtime_epoch', 'session_id', 'approval_id', 'execution_id', 'policy_version'] as const) if (lease[field] !== context[field]) return undefined
  for (const field of ['user_id', 'device_id', 'key_version', 'binding_sha256'] as const) if (lease[field] !== decision[field]) return undefined
  const issued = Date.parse(lease.issued_at), expires = Date.parse(lease.expires_at), authenticated = Date.parse(lease.authenticated_at)
  if (lease.approval_key_jkt !== keyJKT || lease.assurance_profile !== context.required_assurance.profile ||
    issued > now || expires <= now || expires <= issued || expires - issued > 3000 || expires > Date.parse(context.expires_at) ||
    authenticated > now || now - authenticated > context.required_assurance.max_auth_age_seconds * 1000) return undefined
  return lease
}
