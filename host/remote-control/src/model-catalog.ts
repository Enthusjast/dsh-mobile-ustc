import { createHash } from 'node:crypto'
import { z } from 'zod'
import { parseSigningObject } from './canonical.js'
import { ProbeError } from './protocol.js'

export const MODEL_CATALOG_CAPABILITY = 'session.models.v1'
export const MAX_MODEL_PAGE_BYTES = 32 * 1024
const id = z.string().min(1).max(128)
const label = z.string().min(1).max(256).regex(/^[^\u0000-\u001f\u007f]*$/u)
export const modelPageItem = z.strictObject({
  provider: z.strictObject({ id, label }), model: z.strictObject({ id, label }),
  reasoning_efforts: z.array(z.strictObject({ id: z.string().min(1).max(64), label })).max(32),
})
export const modelPage = z.strictObject({ items: z.array(modelPageItem).max(50), next_cursor: z.string().min(1).max(1024).nullable(), unavailable_provider_count: z.int().min(0).max(128) })
export const modelPageRequest = z.strictObject({ sync_id: z.uuid(), limit: z.int().min(1).max(50), cursor: z.string().min(1).max(1024).optional() })
export interface ModelPageBinding { runtimeId: string; runtimeEpoch: string; sessionId: string; syncId: string }
export type ModelPage = z.infer<typeof modelPage>
export type ModelPageRequest = z.infer<typeof modelPageRequest>

const cursorSchema = z.strictObject({ v: z.literal(1), purpose: z.literal('session-models'), runtime_id: z.uuid(), runtime_epoch: z.uuid(),
  session_id: z.uuid(), sync_id: z.uuid(), sha256: z.string().regex(/^[0-9a-f]{64}$/), after: z.int().min(1).max(8191) })
type Snapshot = { items: z.infer<typeof modelPageItem>[]; sha256: string; unavailable: number }
// Share even across reconnecting Relay readers for the same native controller.
// An adapter that ignores cancellation occupies one flight until it settles.
const flights = new WeakMap<object, Promise<Snapshot>>()

function pageBytes(value: unknown): number {
  // Account for the Relay's JSON HTML escaping as well as the Host wire bytes.
  return Buffer.byteLength(JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, ch => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0')))
}

function projectCatalog(value: unknown): Snapshot {
  const source = value as { failures?: unknown[]; groups?: Array<{ id: string; name: string; models: Array<{ id: string; name: string; reasoning?: { efforts: Array<{ id: string; name: string }> } }> }> }
  if (!source || !Array.isArray(source.groups) || source.groups.length > 128) throw new ProbeError('protocol.snapshot_too_large')
  const unavailable = Array.isArray(source.failures) ? source.failures.length : 0
  if (unavailable > 128) throw new ProbeError('protocol.snapshot_too_large')
  const items: Snapshot['items'] = [], providers = new Set<string>()
  let bytes = 0
  for (const group of source.groups) {
    if (!group || !Array.isArray(group.models) || providers.has(group.id)) throw new ProbeError('protocol.invalid')
    providers.add(group.id)
    const models = new Set<string>()
    for (const model of group.models) {
      if (!model || models.has(model.id)) throw new ProbeError('protocol.invalid')
      models.add(model.id)
      const item = modelPageItem.parse({ provider: { id: group.id, label: group.name }, model: { id: model.id, label: model.name },
        reasoning_efforts: model.reasoning === undefined ? [] : model.reasoning.efforts.map(effort => ({ id: effort.id, label: effort.name })) })
      if (new Set(item.reasoning_efforts.map(effort => effort.id)).size !== item.reasoning_efforts.length) throw new ProbeError('protocol.invalid')
      bytes += Buffer.byteLength(JSON.stringify(item))
      if (items.length >= 8192 || bytes > 4 * 1024 * 1024) throw new ProbeError('protocol.snapshot_too_large')
      items.push(item)
    }
  }
  items.sort((a, b) => a.provider.id < b.provider.id ? -1 : a.provider.id > b.provider.id ? 1 : a.model.id < b.model.id ? -1 : a.model.id > b.model.id ? 1 : 0)
  return { items, unavailable, sha256: createHash('sha256').update(JSON.stringify({ items, unavailable })).digest('hex') }
}

async function waitFor<Value>(promise: Promise<Value>, signal: AbortSignal): Promise<Value> {
  signal.throwIfAborted()
  return await new Promise<Value>((resolve, reject) => {
    const aborted = () => { signal.removeEventListener('abort', aborted); reject(new ProbeError('runtime.offline')) }
    signal.addEventListener('abort', aborted, { once: true })
    promise.then(value => { signal.removeEventListener('abort', aborted); resolve(value) }, error => { signal.removeEventListener('abort', aborted); reject(error) })
    if (signal.aborted) aborted()
  })
}

/** Read-only, current-profile metadata. Cursors locate rows; they confer no authority. */
export async function readModelPage(controller: object, load: () => Promise<unknown>, binding: ModelPageBinding, request: ModelPageRequest, signal: AbortSignal): Promise<ModelPage> {
  modelPageRequest.parse(request)
  if (request.sync_id !== binding.syncId) throw new ProbeError('protocol.resync_required')
  signal.throwIfAborted()
  let flight = flights.get(controller)
  if (!flight) {
    flight = Promise.resolve().then(load).then(projectCatalog)
    flights.set(controller, flight)
    const owned = flight
    void flight.finally(() => { if (flights.get(controller) === owned) flights.delete(controller) }).catch(() => {})
  }
  const snapshot = await waitFor(flight, signal)
  signal.throwIfAborted()
  let after = 0
  if (request.cursor) {
    try {
      const raw = Buffer.from(request.cursor, 'base64url')
      if (raw.toString('base64url') !== request.cursor) throw new Error()
      const cursor = cursorSchema.parse(parseSigningObject(raw))
      if (cursor.runtime_id !== binding.runtimeId || cursor.runtime_epoch !== binding.runtimeEpoch || cursor.session_id !== binding.sessionId ||
        cursor.sync_id !== binding.syncId || cursor.sha256 !== snapshot.sha256 || cursor.after >= snapshot.items.length) throw new Error()
      after = cursor.after
    } catch { throw new ProbeError('protocol.resync_required') }
  }
  const result: ModelPage = { items: [], next_cursor: null, unavailable_provider_count: snapshot.unavailable }
  const nextCursor = (index: number) => index < snapshot.items.length ? Buffer.from(JSON.stringify({ v: 1, purpose: 'session-models',
    runtime_id: binding.runtimeId, runtime_epoch: binding.runtimeEpoch, session_id: binding.sessionId, sync_id: binding.syncId, sha256: snapshot.sha256, after: index })).toString('base64url') : null
  for (let index = after; index < snapshot.items.length && result.items.length < request.limit; index++) {
    const candidate = { items: [...result.items, snapshot.items[index]!], next_cursor: nextCursor(index + 1), unavailable_provider_count: snapshot.unavailable }
    if (pageBytes(candidate) > MAX_MODEL_PAGE_BYTES) break
    result.items = candidate.items
  }
  if (result.items.length === 0 && after < snapshot.items.length) throw new ProbeError('protocol.snapshot_too_large')
  result.next_cursor = nextCursor(after + result.items.length)
  return result
}
