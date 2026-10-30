import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import { modelPageRequest, type ModelPageBinding, type ModelPageRequest, type ModelPage } from './model-catalog.js'
import { parseCommand, ProbeError, type Command, type Frame } from './protocol.js'

const uuid = z.uuid()
const base = {
  v: z.literal(1), request_id: uuid, runtime_id: uuid, runtime_epoch: uuid,
  session_id: uuid, subscription_id: uuid,
}
const requestSchema = z.discriminatedUnion('type', [
  z.strictObject({ ...base, type: z.literal('session.subscribe'), payload: z.strictObject({ max_messages: z.int().min(1).max(100), questions: z.boolean().optional(), timed_questions: z.boolean().optional() }) }),
  z.strictObject({ ...base, type: z.literal('session.unsubscribe'), payload: z.strictObject({}) }),
  z.strictObject({ ...base, type: z.literal('session.models.get'), payload: modelPageRequest }),
  z.strictObject({ ...base, type: z.literal('session.page'), payload: z.strictObject({
    sync_id: uuid, through_seq: z.int().min(-1), before_seq: z.int().min(0), max_messages: z.int().min(1).max(100),
  }) }),
  z.strictObject({ ...base, sync_id: uuid, type: z.literal('question.claim'), payload: z.strictObject({ question_id: uuid }) }),
  z.strictObject({ ...base, sync_id: uuid, type: z.literal('question.release'), payload: z.strictObject({ claim_id: uuid }) }),
])
type ReadRequest = z.infer<typeof requestSchema>

export interface SessionReaderRuntime {
  epoch: string
  client: { runtimeId: string; modelPage?(binding: ModelPageBinding, request: ModelPageRequest, signal: AbortSignal): Promise<ModelPage> }
  follow(command: Extract<Command, { type: 'session.subscribe' }>, signal: AbortSignal): AsyncIterable<Frame>
  dispatch(command: Command, signal: AbortSignal): Promise<unknown>
  claimQuestion?(sessionId: string, questionId: string, signal: AbortSignal): AsyncIterable<{ remaining_ms: number; expires_at: string }>
}

interface Subscription {
  request: Extract<ReadRequest, { type: 'session.subscribe' }>
  abort: AbortController
  queue: Array<{ frame: unknown; bytes: number }>
  bytes: number
  writing: boolean
  finished: boolean
  pages: Set<string>
  models: Set<string>
  syncId?: string
  claims: Map<string, AbortController>
  usedClaims: Set<string>
}

const MAX_FRAME = 64 * 1024
const MAX_PAYLOAD = 2 * 1024 * 1024
const MAX_SUBSCRIPTION_BYTES = 3 * 1024 * 1024
const MAX_TOTAL_BYTES = 12 * 1024 * 1024
const contentTypes = new Set(['session.snapshot', 'session.event', 'session.checkpoint', 'assistant.start', 'assistant.chunk', 'assistant.end', 'question.snapshot', 'question.timed.snapshot'])

/** Split only the projected payload. Routing and sync identities remain visible on every fragment. */
export function encodeSessionFrames(frame: Record<string, unknown>): Record<string, unknown>[] {
  const encoded = Buffer.from(JSON.stringify(frame.payload))
  if (encoded.length > MAX_PAYLOAD) throw new ProbeError('protocol.snapshot_too_large')
  if (Buffer.byteLength(JSON.stringify(frame)) <= MAX_FRAME) return [frame]
  const size = 40 * 1024
  const count = Math.ceil(encoded.length / size)
  const fragmentId = randomUUID()
  return Array.from({ length: count }, (_, index) => ({
    ...frame, type: 'session.fragment', payload: {
      type: frame.type, fragment_id: fragmentId, index, count,
      data: encoded.subarray(index * size, (index + 1) * size).toString('base64'),
    },
  }))
}

/** One native follower per routed subscription, with finite queues independent of socket writes. */
export class RelaySessions {
  private readonly subscriptions = new Map<string, Subscription>()
  private bytes = 0
  private closed = false

  constructor(private readonly runtime: SessionReaderRuntime, private readonly send: (frame: unknown) => Promise<void>, private readonly timedEnabled = false, private readonly modelsEnabled = false) {}

  handle(value: unknown): boolean {
    if (value === null || typeof value !== 'object' || !['session.subscribe', 'session.unsubscribe', 'session.page', 'session.models.get', 'question.claim', 'question.release'].includes(String((value as { type?: unknown }).type))) return false
    const parsed = requestSchema.safeParse(value)
    if (!parsed.success || this.closed) throw new ProbeError('protocol.invalid')
    const request = parsed.data
    if (request.runtime_id !== this.runtime.client.runtimeId || request.runtime_epoch !== this.runtime.epoch) throw new ProbeError('runtime.changed')
    const existing = this.subscriptions.get(request.subscription_id)
    if (request.type === 'session.subscribe') {
      if (request.payload.timed_questions && !this.timedEnabled) throw new ProbeError('protocol.unsupported')
      if (existing || this.subscriptions.size >= 32) {
        void this.sendError(request, 'rate.limited')
        return true
      }
      const subscription: Subscription = { request, abort: new AbortController(), queue: [], bytes: 0, writing: false, finished: false, pages: new Set(), models: new Set(), claims: new Map(), usedClaims: new Set() }
      this.subscriptions.set(request.subscription_id, subscription)
      void this.follow(subscription)
    } else if (!existing || existing.request.session_id !== request.session_id) {
      if (request.type !== 'session.unsubscribe') void this.sendError(request, 'protocol.resync_required')
    } else if (request.type === 'session.unsubscribe') this.remove(existing)
    else if (request.type === 'question.claim' || request.type === 'question.release') {
      if (!this.timedEnabled || !existing.request.payload.timed_questions || !this.runtime.claimQuestion) throw new ProbeError('protocol.unsupported')
      if (request.sync_id !== existing.syncId) { void this.sendError(request, 'protocol.resync_required'); return true }
      if (request.type === 'question.release') {
        existing.claims.get(request.payload.claim_id)?.abort()
        existing.claims.delete(request.payload.claim_id)
      } else if (existing.usedClaims.has(request.request_id)) throw new ProbeError('protocol.invalid')
      else if (existing.claims.size >= 4 || existing.usedClaims.size >= 256) {
        this.enqueue(existing, this.envelope(request, 'question.claim.closed', { question_id: request.payload.question_id, code: 'rate.limited' }, request.sync_id))
      } else {
        const abort = new AbortController()
        existing.usedClaims.add(request.request_id)
        existing.claims.set(request.request_id, abort)
        void this.claim(existing, request, abort)
      }
    }
    else if (request.type === 'session.models.get') {
      if (!this.modelsEnabled || !this.runtime.client.modelPage) throw new ProbeError('protocol.unsupported')
      if (request.payload.sync_id !== existing.syncId) { void this.sendError(request, 'protocol.resync_required'); return true }
      if (existing.models.size >= 2 || existing.models.has(request.request_id)) { void this.sendError(request, 'rate.limited'); return true }
      existing.models.add(request.request_id)
      void this.models(existing, request)
    }
    else {
      if (existing.pages.size >= 4 || existing.pages.has(request.request_id)) {
        void this.sendError(request, 'rate.limited')
        return true
      }
      existing.pages.add(request.request_id)
      void this.page(existing, request)
    }
    return true
  }

  close(): void {
    this.closed = true
    for (const subscription of this.subscriptions.values()) this.remove(subscription)
  }

  private envelope(request: ReadRequest, type: string, payload: unknown, syncId?: string): Record<string, unknown> {
    return {
      v: 1, type, request_id: request.request_id, runtime_id: request.runtime_id, runtime_epoch: request.runtime_epoch,
      session_id: request.session_id, subscription_id: request.subscription_id,
      ...(syncId === undefined ? {} : { sync_id: syncId }), payload,
    }
  }

  private async follow(subscription: Subscription): Promise<void> {
    const request = subscription.request
    try {
      const command = parseCommand({ v: 0, type: 'session.subscribe', request_id: request.request_id,
        runtime_epoch: request.runtime_epoch, session_id: request.session_id, payload: { max_messages: request.payload.max_messages } })
      if (command.type !== 'session.subscribe') throw new ProbeError('protocol.invalid')
      for await (const source of this.runtime.follow(command, subscription.abort.signal)) {
        if (subscription.abort.signal.aborted) return
        if (source.type === 'question.snapshot' && (request.type !== 'session.subscribe' || !request.payload.questions)) continue
        if (source.type === 'question.timed.snapshot' && !request.payload.timed_questions) continue
        if (!contentTypes.has(source.type) || source.session_id !== request.session_id || source.runtime_epoch !== request.runtime_epoch || !source.sync_id) throw new ProbeError('protocol.invalid')
        if (source.type === 'session.snapshot') subscription.syncId = source.sync_id
        this.enqueue(subscription, this.envelope(request, source.type, source.payload, source.sync_id))
      }
      if (!subscription.abort.signal.aborted) {
        this.enqueue(subscription, this.envelope(request, 'session.closed', { code: 'protocol.resync_required' }))
        subscription.finished = true
        if (!subscription.writing) this.remove(subscription)
      }
    } catch (error) { this.fail(subscription, error) }
  }

  private async claim(subscription: Subscription, request: Extract<ReadRequest, { type: 'question.claim' }>, abort: AbortController): Promise<void> {
    try {
      for await (const result of this.runtime.claimQuestion!(request.session_id, request.payload.question_id, abort.signal)) {
        if (abort.signal.aborted) return
        this.enqueue(subscription, this.envelope(request, 'question.claimed', { question_id: request.payload.question_id, ...result }, request.sync_id))
      }
      if (!abort.signal.aborted) this.enqueue(subscription, this.envelope(request, 'question.claim.closed', { question_id: request.payload.question_id, code: 'question.ended' }, request.sync_id))
    } catch (error) {
      if (!abort.signal.aborted) {
        const code = error instanceof ProbeError && ['interaction.stale', 'rate.limited'].includes(error.code) ? error.code : 'internal'
        try { this.enqueue(subscription, this.envelope(request, 'question.claim.closed', { question_id: request.payload.question_id, code }, request.sync_id)) }
        catch (failure) { this.fail(subscription, failure) }
      }
    } finally {
      abort.abort()
      if (subscription.claims.get(request.request_id) === abort) subscription.claims.delete(request.request_id)
    }
  }

  private async models(subscription: Subscription, request: Extract<ReadRequest, { type: 'session.models.get' }>): Promise<void> {
    const signal = AbortSignal.any([subscription.abort.signal, AbortSignal.timeout(3000)])
    try {
      const payload = await this.runtime.client.modelPage!({ runtimeId: request.runtime_id, runtimeEpoch: request.runtime_epoch,
        sessionId: request.session_id, syncId: request.payload.sync_id }, request.payload, signal)
      if (!signal.aborted) this.enqueue(subscription, this.envelope(request, 'session.models.result', payload, request.payload.sync_id))
    } catch (error) {
      if (!subscription.abort.signal.aborted) {
        const code = signal.aborted ? 'runtime.offline' : this.errorCode(error)
        try { this.enqueue(subscription, this.envelope(request, 'session.models.error', { code }, request.payload.sync_id)) }
        catch (failure) { this.fail(subscription, failure) }
      }
    } finally { subscription.models.delete(request.request_id) }
  }

  private async page(subscription: Subscription, request: Extract<ReadRequest, { type: 'session.page' }>): Promise<void> {
    try {
      const command = parseCommand({ v: 0, type: 'session.page', request_id: request.request_id,
        runtime_epoch: request.runtime_epoch, session_id: request.session_id, payload: request.payload })
      const response = await this.runtime.dispatch(command, subscription.abort.signal) as Frame
      if (!subscription.abort.signal.aborted) this.enqueue(subscription, this.envelope(request, 'session.page.result', response.payload, request.payload.sync_id))
    } catch (error) {
      if (!subscription.abort.signal.aborted) await this.sendError(request, this.errorCode(error))
    } finally { subscription.pages.delete(request.request_id) }
  }

  private enqueue(subscription: Subscription, frame: Record<string, unknown>): void {
    const frames = encodeSessionFrames(frame).map(frame => ({ frame, bytes: Buffer.byteLength(JSON.stringify(frame)) }))
    const bytes = frames.reduce((total, item) => total + item.bytes, 0)
    if (subscription.bytes + bytes > MAX_SUBSCRIPTION_BYTES || this.bytes + bytes > MAX_TOTAL_BYTES) throw new ProbeError('protocol.resync_required')
    subscription.queue.push(...frames)
    subscription.bytes += bytes
    this.bytes += bytes
    if (!subscription.writing) void this.write(subscription)
  }

  private async write(subscription: Subscription): Promise<void> {
    subscription.writing = true
    try {
      while (!subscription.abort.signal.aborted) {
        const item = subscription.queue.shift()
        if (!item) break
        subscription.bytes -= item.bytes
        this.bytes -= item.bytes
        await this.send(item.frame)
      }
    } catch (error) { this.fail(subscription, error) }
    finally {
      subscription.writing = false
      if (subscription.finished) this.remove(subscription)
    }
  }

  private fail(subscription: Subscription, error: unknown): void {
    if (subscription.abort.signal.aborted) return
    this.remove(subscription)
    void this.sendError(subscription.request, this.errorCode(error))
  }

  private errorCode(error: unknown): string {
    const allowed = new Set(['session.not_found', 'runtime.changed', 'access.denied', 'protocol.snapshot_too_large', 'protocol.resync_required', 'rate.limited'])
    return error instanceof ProbeError && allowed.has(error.code) ? error.code : 'protocol.resync_required'
  }

  private async sendError(request: ReadRequest, code: string): Promise<void> {
    try { await this.send(this.envelope(request, request.type === 'session.models.get' ? 'session.models.error' : 'session.error', { code }, request.type === 'session.models.get' ? request.payload.sync_id : undefined)) } catch { /* The connection owner handles transport failure. */ }
  }

  private remove(subscription: Subscription): void {
    if (this.subscriptions.get(subscription.request.subscription_id) === subscription) this.subscriptions.delete(subscription.request.subscription_id)
    subscription.abort.abort()
    for (const claim of subscription.claims.values()) claim.abort()
    subscription.claims.clear()
    this.bytes -= subscription.bytes
    subscription.bytes = 0
    subscription.queue.length = 0
  }
}
