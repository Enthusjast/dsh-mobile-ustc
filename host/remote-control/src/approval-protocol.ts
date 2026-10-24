import { createHash, randomUUID } from 'node:crypto'
import { z } from 'zod'
import { ApprovalContext, approvalBinding } from './approval-contract.js'
import { ApprovalAuthorization } from './approval-authorization.js'
import { canonicalObject } from './canonical.js'

export const SIGNED_APPROVAL_CAPABILITY = 'approval.signed.v1'
const uuid = ApprovalAuthorization.shape.runtime_id
const sha256 = ApprovalAuthorization.shape.binding_sha256
const statusStates = ['pending', 'decision_received', 'allowed', 'denied', 'expired', 'cancelled', 'invalidated', 'outcome_unknown'] as const
const hostStates = ['approved', 'denied', 'consumed', 'settled', 'expired', 'cancelled', 'invalidated', 'outcome_unknown'] as const
const outcome = z.enum(['succeeded', 'failed', 'cancelled'])
export const ApprovalWireStatus = z.strictObject({
  approval_id: uuid, runtime_id: uuid, runtime_epoch: uuid, session_id: uuid, execution_id: uuid, binding_sha256: sha256,
  state: z.enum(statusStates), decision: z.enum(['allow_once', 'reject']).optional(), decision_payload_sha256: sha256.optional(),
  expires_at: z.string().datetime({ offset: true }), host_state: z.enum(hostStates).optional(), execution_outcome: outcome.optional(),
}).superRefine((status, issue) => {
  if ((status.host_state === 'settled') !== (status.execution_outcome !== undefined)) issue.addIssue({ code: 'custom', message: 'invalid native result' })
})
export type ApprovalWireStatus = z.infer<typeof ApprovalWireStatus>

const runtime = { v: z.literal(1), request_id: uuid, runtime_id: uuid }
const scoped = { ...runtime, runtime_epoch: uuid, session_id: uuid }
const contextPayload = z.strictObject({ context: ApprovalContext })
const statusPayload = z.strictObject({ status: ApprovalWireStatus })
const compactJWS = z.string().min(1).max(16 * 1024).regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
const resultPayload = z.strictObject({
  approval_id: uuid, execution_id: uuid, binding_sha256: sha256, decision_payload_sha256: sha256.optional(), state: z.enum(hostStates), execution_outcome: outcome.optional(),
}).superRefine((result, issue) => {
  if ((result.state === 'settled') !== (result.execution_outcome !== undefined)) issue.addIssue({ code: 'custom', message: 'invalid native result' })
  if (['approved', 'denied', 'consumed', 'settled', 'outcome_unknown'].includes(result.state) && result.decision_payload_sha256 === undefined) issue.addIssue({ code: 'custom', message: 'missing decision evidence' })
})
export const ApprovalResultFrame = z.strictObject({ ...scoped, type: z.literal('approval.result'), payload_sha256: sha256, payload: resultPayload })
const resultFacts = ApprovalResultFrame.omit({ payload_sha256: true, request_id: true, v: true })
export type ApprovalResultFacts = z.infer<typeof resultFacts>
export type ApprovalResultFrame = z.infer<typeof ApprovalResultFrame>
export function approvalResultDigest(value: ApprovalResultFacts): string {
  return createHash('sha256').update(canonicalObject(resultFacts.parse(value))).digest('hex')
}

/** Content-derived correlation ID; the complete SHA-256 remains the receipt identity. */
export function makeApprovalResultFrame(value: ApprovalResultFacts): ApprovalResultFrame {
  const facts = resultFacts.parse(value), digest = approvalResultDigest(facts)
  const bytes = createHash('sha256').update('dsh-mobile-ustc/approval-report-id/v1\0').update(digest).digest().subarray(0, 16)
  bytes[6] = (bytes[6]! & 0x0f) | 0x80
  bytes[8] = (bytes[8]! & 0x3f) | 0x80
  const hex = bytes.toString('hex')
  const requestID = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
  return ApprovalResultFrame.parse({ v: 1, request_id: requestID, ...facts, payload_sha256: digest })
}

export const ApprovalWireFrame = z.discriminatedUnion('type', [
  z.strictObject({ ...scoped, type: z.literal('approval.request'), payload: contextPayload }),
  z.strictObject({ ...scoped, type: z.literal('approval.registered'), payload: statusPayload }),
  z.strictObject({ ...runtime, type: z.literal('approval.subscribe'), payload: z.strictObject({}) }),
  z.strictObject({ ...runtime, type: z.literal('approval.status.get'), payload: z.strictObject({ approval_id: uuid }) }),
  z.strictObject({ ...runtime, type: z.literal('approval.unsubscribe'), payload: z.strictObject({}) }),
  z.strictObject({ ...runtime, type: z.literal('approval.unsubscribed'), payload: z.strictObject({}) }),
  z.strictObject({ ...runtime, type: z.literal('approval.snapshot'), payload: z.strictObject({ items: z.array(ApprovalWireStatus).max(64) }) }),
  z.strictObject({ ...scoped, type: z.literal('approval.reference'), payload: statusPayload }),
  z.strictObject({ ...scoped, type: z.literal('approval.details.get'), payload: z.strictObject({ approval_id: uuid }) }),
  z.strictObject({ ...scoped, type: z.literal('approval.details'), payload: contextPayload }),
  z.strictObject({ ...scoped, type: z.literal('approval.fragment'), payload: z.strictObject({
    kind: z.enum(['approval.request', 'approval.details']), transfer_id: uuid, index: z.int().min(0).max(3), count: z.int().min(1).max(4),
    data: z.string().min(1).max(54_616).regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/),
  }).superRefine((fragment, issue) => { if (fragment.index >= fragment.count) issue.addIssue({ code: 'custom', message: 'invalid fragment index' }) }) }),
  z.strictObject({ ...scoped, type: z.literal('approval.error'), payload: z.strictObject({ approval_id: uuid, code: z.enum(['approval.stale', 'approval.expired', 'internal']) }) }),
  z.strictObject({ ...scoped, type: z.literal('approval.decision'), payload: z.strictObject({ approval_id: uuid, decision_jws: compactJWS, authorization_jws: compactJWS }) }),
  ApprovalResultFrame,
  z.strictObject({ ...scoped, type: z.literal('approval.result.ack'), payload_sha256: sha256, payload: statusPayload }),
])
export type ApprovalWireFrame = z.infer<typeof ApprovalWireFrame>

/** Only canonical context bytes are fragmented; visible routing stays on every part. */
export function encodeApprovalContextFrames(type: 'approval.request' | 'approval.details', requestID: string, value: unknown): ApprovalWireFrame[] {
  const { context, canonical } = approvalBinding(value)
  const frame = ApprovalWireFrame.parse({ v: 1, type, request_id: requestID, runtime_id: context.runtime_id, runtime_epoch: context.runtime_epoch, session_id: context.session_id, payload: { context } })
  if (Buffer.byteLength(JSON.stringify(frame)) <= 64 * 1024) return [frame]
  const bytes = Buffer.from(canonical), size = 40 * 1024, count = Math.ceil(bytes.length / size), transfer = randomUUID()
  return Array.from({ length: count }, (_, index) => ApprovalWireFrame.parse({
    v: 1, type: 'approval.fragment', request_id: requestID, runtime_id: context.runtime_id, runtime_epoch: context.runtime_epoch, session_id: context.session_id,
    payload: { kind: type, transfer_id: transfer, index, count, data: bytes.subarray(index * size, (index + 1) * size).toString('base64') },
  }))
}
