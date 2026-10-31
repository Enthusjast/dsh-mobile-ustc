import { createHash } from 'node:crypto'
import { z } from 'zod'

export const FORK_CAPABILITY = 'session.fork.v1'
export const MESSAGE_ACTIONS_CAPABILITY = 'session.message.actions.v1'
const uuid = z.uuid()
const digest = z.string().regex(/^[0-9a-f]{64}$/)
export const forkAnchorSchema = z.strictObject({
  v: z.literal(1), subscription_id: uuid, sync_id: uuid,
  native_seq: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  message_version_sha256: digest, anchor_sha256: digest,
})
export const forkPayloadSchema = z.strictObject({ workspace_id: uuid, anchor: forkAnchorSchema })
export const forkOutcomeSchema = z.strictObject({
  v: z.literal(1), workspace_attachment: z.enum(['attached', 'failed', 'unknown']),
  checkpoint: z.enum(['persisted', 'unavailable', 'failed', 'unknown']),
})
export const messagePreviewRequest = z.strictObject({ sync_id: uuid, native_seq: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER) })
export const messagePreviewConfirmRequest = z.strictObject({ sync_id: uuid, anchor: forkAnchorSchema })
export const messagePreviewSchema = z.strictObject({ v: z.literal(1), anchor: forkAnchorSchema,
  text: z.string().min(1).refine(value => Buffer.byteLength(value, 'utf8') <= 32 * 1024).nullable(),
  shareable: z.boolean(), complete: z.literal(true),
}).refine(value => value.shareable === (value.text !== null))
export type ForkAnchor = z.infer<typeof forkAnchorSchema>
export type ForkPayload = z.infer<typeof forkPayloadSchema>
export type ForkOutcome = z.infer<typeof forkOutcomeSchema>
export interface ForkPartialResult { child_session_id: string; fork_outcome: ForkOutcome }
export interface ForkResult extends ForkPartialResult {
  checkpoint: { state: 'persisted'; through_seq: number } | { state: 'unavailable' | 'failed' }
  command_state?: 'outcome_unknown'
  catalog_item?: { session_id: string; dsh_session_id: string; workspace_id: string | null; state: 'available' | 'running' | 'archived' | 'unavailable'; last_persisted_seq: number }
}
export interface MessageActionBinding {
  runtimeId: string; runtimeEpoch: string; sessionId: string; subscriptionId: string; syncId: string
  userId: string; deviceId: string
}

/** Matches Relay's HTML-safe serialization before its routing envelope is added. */
export function messagePreviewWireBytes(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`))
}

export function canonicalForkJson(value: unknown): string {
  let nodes = 0
  const visit = (item: unknown, depth: number): unknown => {
    if (++nodes > 16_384 || depth > 32) throw new Error('bounded JSON required')
    if (Array.isArray(item)) return item.map(child => visit(child, depth + 1))
    if (item !== null && typeof item === 'object') return Object.fromEntries(Object.entries(item).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([key, child]) => [key, visit(child, depth + 1)]))
    return item
  }
  return JSON.stringify(visit(value, 0))
}
export function relayForkDigest(runtimeEpoch: string, sessionId: string, payload: ForkPayload): string {
  return createHash('sha256').update(canonicalForkJson({ type: 'session.fork', runtime_epoch: runtimeEpoch, session_id: sessionId, payload })).digest('hex')
}
