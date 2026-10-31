import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import type { SessionWireEvent } from '@deepseek-ai/dsh-api-session-controller/types'
import type { DshClient } from './dsh-client.js'
import type { CommandOwner } from './command-journal.js'
import { isHumanInput } from './visible-message.js'
import { ProbeError } from './protocol.js'
import { canonicalForkJson, forkAnchorSchema, messagePreviewConfirmRequest, messagePreviewRequest, messagePreviewSchema, messagePreviewWireBytes, type ForkAnchor, type MessageActionBinding } from './fork-protocol.js'

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}
function same(left: string, right: string): boolean {
  const a = Buffer.from(left, 'hex'), b = Buffer.from(right, 'hex')
  return a.length === 32 && b.length === 32 && timingSafeEqual(a, b)
}
function visibleText(event: SessionWireEvent): string | null {
  const data = object(event.data)
  if (event.type !== 'assistant/message' && !(event.type === 'user/message' && isHumanInput(data.source))) throw new ProbeError('message.unavailable')
  const body = event.type === 'user/message' ? data : object(data.message)
  if (!Array.isArray(body.content) || body.content.length > 1024) throw new ProbeError('message.unavailable')
  const text: string[] = []
  let bytes = 0
  for (const value of body.content) {
    const part = object(value)
    // Explicit visible text only: no reasoning, tool payload, attachments, paths or producer context.
    if (part.type !== 'text') continue
    if (typeof part.text !== 'string') throw new ProbeError('message.unavailable')
    bytes += Buffer.byteLength(part.text, 'utf8') + (text.length === 0 ? 0 : 1)
    if (bytes > 32 * 1024 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(part.text)) return null
    text.push(part.text)
  }
  const result = text.join('\n')
  if (result.length === 0 || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(result)) return null
  return result
}
function eventVersion(event: SessionWireEvent): string {
  const pending: Array<{ value: unknown; depth: number }> = [{ value: event, depth: 0 }]
  let nodes = 0, bytes = 0
  while (pending.length > 0) {
    const { value, depth } = pending.pop()!
    if (++nodes > 16_384 || depth > 32) throw new ProbeError('message.unavailable')
    if (typeof value === 'string') bytes += Buffer.byteLength(value, 'utf8')
    else if (Array.isArray(value)) { if (value.length > 16_384) throw new ProbeError('message.unavailable'); for (const child of value) pending.push({ value: child, depth: depth + 1 }) }
    else if (value !== null && typeof value === 'object') for (const [key, child] of Object.entries(value)) { bytes += Buffer.byteLength(key); pending.push({ value: child, depth: depth + 1 }) }
    if (bytes > 256 * 1024 || pending.length > 16_384) throw new ProbeError('message.unavailable')
  }
  return createHash('sha256').update(canonicalForkJson(event)).digest('hex')
}
interface Context { binding: MessageActionBinding; alive: () => boolean; expires: number; anchors: Map<number, ForkAnchor> }

/** Per-reader, short-lived authority to act on an actual persisted visible message. Never a text-to-history lookup. */
export class SessionMessageActions {
  private readonly key = randomBytes(32)
  private readonly contexts = new Map<string, Context>()
  private closed = false
  constructor(private readonly client: DshClient, private readonly now: () => number = Date.now) {}

  private context(binding: MessageActionBinding, alive: () => boolean): Context {
    if (this.closed || !alive()) throw new ProbeError('message.stale')
    for (const [id, entry] of this.contexts) if (entry.expires <= this.now() || !entry.alive()) this.contexts.delete(id)
    const old = this.contexts.get(binding.subscriptionId)
    if (old && canonicalForkJson(old.binding) === canonicalForkJson(binding)) { old.alive = alive; old.expires = this.now() + 30_000; return old }
    if (this.contexts.size >= 32) throw new ProbeError('rate.limited')
    const entry = { binding, alive, expires: this.now() + 30_000, anchors: new Map<number, ForkAnchor>() }
    this.contexts.set(binding.subscriptionId, entry)
    return entry
  }
  private signature(binding: MessageActionBinding, seq: number, version: string): string {
    return createHmac('sha256', this.key).update(canonicalForkJson({ binding, native_seq: seq, message_version_sha256: version })).digest('hex')
  }
  private check(entry: Context, signal: AbortSignal): void {
    signal.throwIfAborted()
    if (this.closed || this.contexts.get(entry.binding.subscriptionId) !== entry || entry.expires <= this.now() || !entry.alive()) throw new ProbeError('message.stale')
  }
  private async persistedMessage(entry: Context, seq: number, signal: AbortSignal): Promise<SessionWireEvent> {
    this.check(entry, signal)
    const { native } = await this.client.configuredSessionContext(entry.binding.sessionId, signal)
    this.check(entry, signal)
    const cursor = await this.client.persistedCursor(native, signal)
    this.check(entry, signal)
    if (cursor.state !== 'persisted' || seq > cursor.through_seq) throw new ProbeError('message.not_persisted')
    let before = cursor.through_seq + 1, count = 0
    for (let pages = 0; pages < 64; pages++) {
      const page = await this.client.page(native, { throughSeq: cursor.through_seq, beforeSeq: before, maxMessages: 10 }, signal)
      this.check(entry, signal)
      if (page.records.length === 0 || (count += page.records.length) > 8192) throw new ProbeError('message.unavailable')
      let earliest = before
      let found: SessionWireEvent | undefined
      for (const { event } of page.records) {
        if (!Number.isSafeInteger(event.seq) || event.seq < 0 || event.seq >= before) throw new ProbeError('message.unavailable')
        earliest = Math.min(earliest, event.seq)
        if (event.seq === seq) found = event
        if (event.seq > seq) {
          const op = object(event.surfaceOp)
          if (op.op === 'replace') {
            // Replacement endpoints must be understood before an old visible version can be authorized.
            if (!Number.isSafeInteger(op.startSeq) || !Number.isSafeInteger(op.endSeq) || (op.startSeq as number) > (op.endSeq as number)) throw new ProbeError('message.unavailable')
            if ((op.startSeq as number) <= seq && seq <= (op.endSeq as number)) throw new ProbeError('message.stale')
          }
        }
      }
      if (found) { visibleText(found); return found }
      if (earliest <= seq || earliest >= before || !page.hasMore) throw new ProbeError('message.stale')
      before = earliest
    }
    throw new ProbeError('message.unavailable')
  }

  async preview(binding: MessageActionBinding, value: unknown, alive: () => boolean, signal: AbortSignal) {
    const request = messagePreviewRequest.safeParse(value)
    if (!request.success || request.data.sync_id !== binding.syncId) throw new ProbeError('protocol.invalid')
    const entry = this.context(binding, alive)
    const event = await this.persistedMessage(entry, request.data.native_seq, signal)
    const version = eventVersion(event)
    const anchor: ForkAnchor = { v: 1, subscription_id: binding.subscriptionId, sync_id: binding.syncId,
      native_seq: event.seq, message_version_sha256: version, anchor_sha256: this.signature(binding, event.seq, version) }
    if (!entry.anchors.has(event.seq) && entry.anchors.size >= 64) entry.anchors.delete(entry.anchors.keys().next().value!)
    entry.anchors.set(event.seq, anchor)
    const text = visibleText(event)
    const payload = { v: 1, anchor, text, shareable: text !== null, complete: true }
    if (messagePreviewWireBytes(payload) > 48 * 1024) throw new ProbeError('message.unavailable')
    return messagePreviewSchema.parse(payload)
  }
  async confirm(binding: MessageActionBinding, value: unknown, alive: () => boolean, signal: AbortSignal) {
    const request = messagePreviewConfirmRequest.safeParse(value)
    if (!request.success || request.data.sync_id !== binding.syncId) throw new ProbeError('protocol.invalid')
    const entry = this.context(binding, alive)
    await this.validate(entry, request.data.anchor, signal)
    const event = await this.persistedMessage(entry, request.data.anchor.native_seq, signal)
    if (!same(eventVersion(event), request.data.anchor.message_version_sha256)) throw new ProbeError('message.stale')
    const text = visibleText(event)
    if (text === null) throw new ProbeError('message.unavailable')
    const payload = { v: 1, anchor: request.data.anchor, text, shareable: true, complete: true }
    if (messagePreviewWireBytes(payload) > 48 * 1024) throw new ProbeError('message.unavailable')
    return messagePreviewSchema.parse(payload)
  }
  private async validate(entry: Context, value: unknown, signal: AbortSignal): Promise<ForkAnchor> {
    const parsed = forkAnchorSchema.safeParse(value)
    if (!parsed.success) throw new ProbeError('protocol.invalid')
    const anchor = parsed.data, binding = entry.binding
    this.check(entry, signal)
    const known = entry.anchors.get(anchor.native_seq)
    if (anchor.subscription_id !== binding.subscriptionId || anchor.sync_id !== binding.syncId || !known ||
      !same(known.anchor_sha256, anchor.anchor_sha256) || !same(known.message_version_sha256, anchor.message_version_sha256) ||
      !same(this.signature(binding, anchor.native_seq, anchor.message_version_sha256), anchor.anchor_sha256)) throw new ProbeError('message.stale')
    const event = await this.persistedMessage(entry, anchor.native_seq, signal)
    if (!same(eventVersion(event), anchor.message_version_sha256)) throw new ProbeError('message.stale')
    this.check(entry, signal)
    return anchor
  }
  async validateFork(sessionId: string, workspaceId: string, anchor: ForkAnchor, owner: CommandOwner, signal: AbortSignal) {
    const entry = this.contexts.get(anchor.subscription_id)
    if (!entry || entry.binding.sessionId !== sessionId || entry.binding.userId !== owner.userId || entry.binding.deviceId !== owner.deviceId) throw new ProbeError('message.stale')
    await this.validate(entry, anchor, signal)
    const resolved = await this.client.configuredSessionContext(sessionId, signal)
    this.check(entry, signal)
    if (resolved.workspace.remoteId !== workspaceId) throw new ProbeError('access.denied')
    return resolved.native
  }
  retire(subscriptionId: string): void { this.contexts.delete(subscriptionId) }
  close(): void { this.closed = true; this.contexts.clear(); this.key.fill(0) }
}
