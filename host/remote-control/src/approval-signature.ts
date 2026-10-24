import { createHash, timingSafeEqual } from 'node:crypto'
import { calculateJwkThumbprint, compactVerify, importJWK, type JWK } from 'jose'
import { z } from 'zod'
import { canonicalObject, parseSigningObject } from './canonical.js'
import { ApprovalDecision, approvalBinding, approvalDecisionCurrent, approvalKeyID, APPROVAL_JWS_TYPE } from './approval-contract.js'

const invalid = () => new Error('approval: invalid signed decision')
const publicKey = z.strictObject({
  kty: z.literal('EC'), crv: z.literal('P-256'), x: z.string().regex(/^[A-Za-z0-9_-]{43}$/), y: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  alg: z.literal('ES256').optional(), use: z.literal('sig').optional(), key_ops: z.tuple([z.literal('verify')]).optional(),
  kid: z.string().max(128).refine(value => Buffer.byteLength(value) <= 128).optional(), ext: z.boolean().optional(),
})
export interface RegisteredApprovalKey {
  user_id: string
  device_id: string
  key_version: number
  approval_key_jkt: string
  public_jwk: JWK
  active: boolean
}
const equal = (a: Uint8Array, b: Uint8Array) => a.byteLength === b.byteLength && timingSafeEqual(a, b)

/** Pure cryptographic verification. Current authorization and one-use consumption are separate required steps. */
export async function verifyApprovalDecision(compact: string, registered: RegisteredApprovalKey, expectedContext: unknown, now = Date.now()): Promise<{ claims: ApprovalDecision; canonical_payload: Uint8Array; payload_sha256: string }> {
  try {
    if (registered.active !== true || !Number.isSafeInteger(registered.key_version) || registered.key_version < 1 || !Number.isSafeInteger(now) || !compact || Buffer.byteLength(compact) > 16 * 1024) throw invalid()
    const parts = compact.split('.')
    if (parts.length !== 3 || parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part))) throw invalid()
    const decoded = parts.map(part => Buffer.from(part, 'base64url'))
    if (decoded.some((bytes, index) => bytes.toString('base64url') !== parts[index]) || decoded[2]!.length !== 64) throw invalid()
    const header = parseSigningObject(decoded[0]!)
    if (!equal(canonicalObject(header), decoded[0]!) || Object.keys(header).length !== 3 || header.alg !== 'ES256' || header.typ !== APPROVAL_JWS_TYPE || header.kid !== approvalKeyID(registered.device_id, registered.key_version)) throw invalid()
    const validated = publicKey.parse(registered.public_jwk)
    const jwk = { kty: validated.kty, crv: validated.crv, x: validated.x, y: validated.y }
    if ([jwk.x, jwk.y].some(value => Buffer.from(value, 'base64url').toString('base64url') !== value)) throw invalid()
    const thumbprint = await calculateJwkThumbprint(jwk, 'sha256')
    if (!equal(Buffer.from(thumbprint), Buffer.from(registered.approval_key_jkt))) throw invalid()
    const key = await importJWK(jwk, 'ES256')
    const verified = await compactVerify(compact, key, { algorithms: ['ES256'] })
    const raw = parseSigningObject(verified.payload)
    if (!equal(canonicalObject(raw), verified.payload)) throw invalid()
    const decision = ApprovalDecision.parse(raw)
    const binding = approvalBinding(expectedContext)
    const context = binding.context
    for (const field of ['host_id', 'installation_id', 'runtime_id', 'runtime_epoch', 'session_id', 'approval_id', 'execution_id', 'policy_version', 'nonce'] as const) {
      if (decision[field] !== context[field]) throw invalid()
    }
    if (!equal(Buffer.from(decision.binding_sha256), Buffer.from(binding.sha256)) || decision.user_id !== registered.user_id || decision.device_id !== registered.device_id || decision.key_version !== registered.key_version) throw invalid()
    if (!approvalDecisionCurrent(context, decision, now)) throw invalid()
    return { claims: decision, canonical_payload: Buffer.from(verified.payload), payload_sha256: createHash('sha256').update(verified.payload).digest('hex') }
  } catch { throw invalid() }
}
