import { createHash, timingSafeEqual } from 'node:crypto'
import { calculateJwkThumbprint, compactVerify, importJWK } from 'jose'
import { z } from 'zod'
import { ApprovalAuthorization, authorizedApproval } from './approval-authorization.js'
import { ApprovalDecision, approvalBinding, approvalDecisionCurrent, type ApprovalContext } from './approval-contract.js'
import { verifyApprovalDecision, type RegisteredApprovalKey } from './approval-signature.js'
import { canonicalObject, parseSigningObject } from './canonical.js'

export const APPROVAL_AUTHORIZATION_DOMAIN = 'dsh-mobile-ustc/approval-authorization/v1'
export const APPROVAL_AUTHORIZATION_AUDIENCE = 'dsh-approval-host/v1'
export const APPROVAL_AUTHORIZATION_JWS_TYPE = 'dsh-approval-authorization+jws'
const invalid = () => new Error('approval: invalid signed authorization')
/** Both signatures verified, but a processed control invalidation fenced this actor. */
export class ApprovalAuthorityRevokedError extends Error { constructor() { super('approval: authorization revoked') } }
const uuid = ApprovalAuthorization.shape.runtime_id
const utc = ApprovalAuthorization.shape.issued_at
const keyID = z.string().regex(/^dsh-approval-authority\/[A-Za-z0-9._-]{1,80}$/)
const issuer = z.string().max(512).refine(value => {
  try { const url = new URL(value); return value.startsWith('https://') && !/[\u0000-\u0020\u007f?#]/u.test(value) && url.protocol === 'https:' && !!url.hostname && !url.username && !url.password } catch { return false }
})
const publicKey = z.strictObject({ kty: z.literal('EC'), crv: z.literal('P-256'), x: z.string().regex(/^[A-Za-z0-9_-]{43}$/), y: z.string().regex(/^[A-Za-z0-9_-]{43}$/) })

export const ApprovalLease = ApprovalAuthorization.extend({
  domain: z.literal(APPROVAL_AUTHORIZATION_DOMAIN), protocol_version: z.literal(1), issuer, audience: z.literal(APPROVAL_AUTHORIZATION_AUDIENCE),
  host_id: uuid, installation_id: uuid, connection_id: uuid,
  decision_payload_sha256: ApprovalAuthorization.shape.binding_sha256,
  approval_public_jwk: publicKey,
}).superRefine((lease, issue) => {
  const issued = Date.parse(lease.issued_at), expires = Date.parse(lease.expires_at)
  if (expires <= issued || expires - issued > 3000 || Date.parse(lease.authenticated_at) > issued) issue.addIssue({ code: 'custom', message: 'invalid authorization interval' })
})
export type ApprovalLease = z.infer<typeof ApprovalLease>

export const TrustedApprovalAuthority = z.strictObject({
  issuer, key_id: keyID, public_jwk: publicKey, key_jkt: z.string().regex(/^[A-Za-z0-9_-]{43}$/), active: z.boolean(), valid_from: utc, valid_until: utc,
})
export type TrustedApprovalAuthority = z.infer<typeof TrustedApprovalAuthority>
export interface VerifiedApprovalLease {
  lease: ApprovalLease
  key: RegisteredApprovalKey
  decision: ApprovalDecision
  authorization: ApprovalAuthorization
}
const equal = (a: Uint8Array, b: Uint8Array) => a.byteLength === b.byteLength && timingSafeEqual(a, b)

/** Pin the authority separately from the peer sending this proof. No key URL is fetched. */
export async function verifyApprovalLease(compact: string, trusted: TrustedApprovalAuthority, expectedContext: unknown, decisionJWS: string, connectionID: string, now = Date.now()): Promise<VerifiedApprovalLease> {
  try {
    const authority = TrustedApprovalAuthority.parse(trusted)
    if (!Number.isSafeInteger(now) || !authority.active || !uuid.safeParse(connectionID).success || !compact || Buffer.byteLength(compact) > 16 * 1024 ||
      Date.parse(authority.valid_from) > now || Date.parse(authority.valid_until) <= now || Date.parse(authority.valid_until) <= Date.parse(authority.valid_from)) throw invalid()
    const parts = compact.split('.')
    if (parts.length !== 3 || parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part))) throw invalid()
    const decoded = parts.map(part => Buffer.from(part, 'base64url'))
    if (decoded.some((bytes, index) => bytes.toString('base64url') !== parts[index]) || decoded[2]!.length !== 64) throw invalid()
    const header = parseSigningObject(decoded[0]!)
    if (!equal(canonicalObject(header), decoded[0]!) || Object.keys(header).length !== 3 || header.alg !== 'ES256' || header.typ !== APPROVAL_AUTHORIZATION_JWS_TYPE || header.kid !== authority.key_id) throw invalid()
    if ([authority.public_jwk.x, authority.public_jwk.y].some(value => Buffer.from(value, 'base64url').toString('base64url') !== value) ||
      await calculateJwkThumbprint(authority.public_jwk, 'sha256') !== authority.key_jkt) throw invalid()
    const key = await importJWK(authority.public_jwk, 'ES256')
    const verified = await compactVerify(compact, key, { algorithms: ['ES256'] })
    const raw = parseSigningObject(verified.payload)
    if (!equal(canonicalObject(raw), verified.payload)) throw invalid()
    const lease = ApprovalLease.parse(raw), binding = approvalBinding(expectedContext), context = binding.context
    for (const field of ['host_id', 'installation_id', 'runtime_id', 'runtime_epoch', 'session_id', 'approval_id', 'execution_id', 'policy_version'] as const) if (lease[field] !== context[field]) throw invalid()
    if (lease.issuer !== authority.issuer || lease.connection_id !== connectionID || lease.binding_sha256 !== binding.sha256 ||
      Date.parse(lease.issued_at) < Date.parse(authority.valid_from) || Date.parse(lease.expires_at) > Date.parse(authority.valid_until) ||
      Date.parse(lease.expires_at) - Date.parse(lease.authenticated_at) > context.required_assurance.max_auth_age_seconds * 1000 ||
      [lease.approval_public_jwk.x, lease.approval_public_jwk.y].some(value => Buffer.from(value, 'base64url').toString('base64url') !== value)) throw invalid()
    const registered: RegisteredApprovalKey = { user_id: lease.user_id, device_id: lease.device_id, key_version: lease.key_version, approval_key_jkt: lease.approval_key_jkt, public_jwk: lease.approval_public_jwk, active: true }
    const decision = await verifyApprovalDecision(decisionJWS, registered, context, now)
    if (decision.payload_sha256 !== lease.decision_payload_sha256 || Date.parse(lease.expires_at) > Date.parse(decision.claims.expires_at)) throw invalid()
    const evidence = Object.fromEntries(ApprovalAuthorization.keyof().options.map(field => [field, lease[field]]))
    const authorization = authorizedApproval(evidence, context, decision.claims, registered.approval_key_jkt, now)
    if (!authorization) throw invalid()
    return { lease, key: registered, decision: decision.claims, authorization }
  } catch { throw invalid() }
}

export const ApprovalLeaseConnection = z.strictObject({ host_id: uuid, installation_id: uuid, runtime_id: uuid, runtime_epoch: uuid, connection_id: uuid })
export type ApprovalLeaseConnection = z.infer<typeof ApprovalLeaseConnection>

/** Ephemeral verified evidence for the synchronous final guard; never persisted. */
export class ApprovalLeaseCache {
  private readonly connection: ApprovalLeaseConnection
  private readonly authorities: TrustedApprovalAuthority[]
  private readonly entries = new Map<string, VerifiedApprovalLease>()
  private readonly revokedDevices = new Set<string>()
  private readonly grantFloors = new Map<string, number>()
  private closed = false
  private inFlight = 0
  private lastTime = -Infinity

  constructor(connection: ApprovalLeaseConnection, authorities: TrustedApprovalAuthority[], private readonly now: () => number = Date.now) {
    this.connection = ApprovalLeaseConnection.parse(connection)
    if (authorities.length < 1 || authorities.length > 8 || new Set(authorities.map(item => item.key_id)).size !== authorities.length) throw invalid()
    this.authorities = authorities.map(value => TrustedApprovalAuthority.parse(value))
  }

  async admit(contextValue: unknown, decisionJWS: string, leaseJWS: string): Promise<RegisteredApprovalKey> {
    if (this.closed || this.inFlight >= 64) throw invalid()
    const binding = approvalBinding(contextValue), context = binding.context
    this.assertConnection(context)
    this.inFlight++
    try {
      let verified: VerifiedApprovalLease | undefined
      const now = this.time()
      for (const authority of this.authorities) {
        try { verified = await verifyApprovalLease(leaseJWS, authority, context, decisionJWS, this.connection.connection_id, now); break } catch {}
      }
      if (this.closed || !verified) throw invalid()
      if (!this.permitted(verified)) throw new ApprovalAuthorityRevokedError()
      const checked = this.time()
      if (!authorizedApproval(verified.authorization, context, verified.decision, verified.key.approval_key_jkt, checked) || !approvalDecisionCurrent(context, verified.decision, checked)) throw invalid()
      for (const [id, entry] of this.entries) if (Date.parse(entry.lease.expires_at) <= checked) this.entries.delete(id)
      const previous = this.entries.get(context.approval_id)
      if (previous && (previous.lease.decision_payload_sha256 !== verified.lease.decision_payload_sha256 || previous.lease.grant_version !== verified.lease.grant_version)) {
        this.entries.delete(context.approval_id)
        throw invalid()
      }
      if (!previous && this.entries.size >= 64) throw invalid()
      this.entries.set(context.approval_id, structuredClone(verified))
      return structuredClone(verified.key)
    } finally { this.inFlight-- }
  }

  authorization(context: ApprovalContext, decision: ApprovalDecision): ApprovalAuthorization | undefined {
    if (this.closed) return undefined
    try {
      this.assertConnection(context)
      const now = this.time(), entry = this.entries.get(context.approval_id)
      if (!entry) return undefined
      if (!this.permitted(entry)) { this.entries.delete(context.approval_id); return undefined }
      const payload = canonicalObject(ApprovalDecision.parse(decision))
      if (approvalBinding(context).sha256 !== entry.lease.binding_sha256 || createHash('sha256').update(payload).digest('hex') !== entry.lease.decision_payload_sha256) return undefined
      const evidence = authorizedApproval(entry.authorization, context, decision, entry.key.approval_key_jkt, now)
      if (!evidence) this.entries.delete(context.approval_id)
      return evidence ? structuredClone(evidence) : undefined
    } catch { return undefined }
  }

  decision(context: ApprovalContext): ApprovalDecision | undefined {
    if (this.closed) return undefined
    try {
      const entry = this.entries.get(context.approval_id)
      if (!entry || approvalBinding(context).sha256 !== entry.lease.binding_sha256 || !this.authorization(context,entry.decision)) return undefined
      return structuredClone(entry.decision)
    } catch { return undefined }
  }

  invalidateDevice(deviceID: string): string[] {
    uuid.parse(deviceID)
    if (this.closed) return []
    if (!this.revokedDevices.has(deviceID) && this.revokedDevices.size + this.grantFloors.size >= 1024) { this.close(); throw invalid() }
    this.revokedDevices.add(deviceID)
    return this.removeInvalidated()
  }

  invalidateGrant(userID: string, version: number): string[] {
    uuid.parse(userID); ApprovalAuthorization.shape.grant_version.parse(version)
    if (this.closed) return []
    if (!this.grantFloors.has(userID) && this.revokedDevices.size + this.grantFloors.size >= 1024) { this.close(); throw invalid() }
    this.grantFloors.set(userID, Math.max(this.grantFloors.get(userID) ?? 0, version))
    return this.removeInvalidated()
  }

  private permitted(entry: VerifiedApprovalLease): boolean {
    return !this.revokedDevices.has(entry.key.device_id) && entry.lease.grant_version >= (this.grantFloors.get(entry.key.user_id) ?? 0)
  }
  private removeInvalidated(): string[] {
    const ids: string[] = []
    for (const [id, entry] of this.entries) if (!this.permitted(entry)) { this.entries.delete(id); ids.push(id) }
    return ids
  }

  close(): void { this.closed = true; this.entries.clear() }

  private assertConnection(context: ApprovalContext): void {
    for (const field of ['host_id', 'installation_id', 'runtime_id', 'runtime_epoch'] as const) if (context[field] !== this.connection[field]) throw invalid()
  }

  private time(): number {
    const now = this.now()
    if (!Number.isSafeInteger(now) || now < this.lastTime) { this.close(); throw invalid() }
    this.lastTime = now
    return now
  }
}
