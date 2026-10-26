import { randomUUID } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'
import { questionReferencesAck, questionReferencesFrame, type QuestionReferenceSource } from './question-reference-protocol.js'

export interface QuestionReferenceBinding {
  runtimeId: string
  epoch: string
  signal: AbortSignal
  send(frame: unknown): Promise<void>
  publishCatalog(nativeSessionId: string, signal: AbortSignal): Promise<void>
  fail(): void
}
export interface HostQuestionReferences { handle(frame: unknown): Promise<boolean>; close(): void }

/** One finite, acknowledged snapshot at a time, independently of foreground subscriptions. */
export class RelayQuestionReferences implements HostQuestionReferences {
  private readonly lifetime: AbortController
  private readonly unwatch: () => void
  private readonly heartbeat: NodeJS.Timeout
  private readonly catalogReady = new Set<string>()
  private scheduled: NodeJS.Timeout | undefined
  private pending: { id: string; sequence: number; count: number; resolve(): void; reject(error: Error): void } | undefined
  private lastWrite = 0
  private sequence = 0
  private dirty = true
  private flushing = false
  private closed = false
  private readonly aborted = () => this.close()

  constructor(private readonly source: QuestionReferenceSource, private readonly binding: QuestionReferenceBinding,
    private readonly heartbeatMs = 15_000, private readonly ackMs = 10_000) {
    binding.signal.throwIfAborted()
    this.lifetime = new AbortController()
    this.unwatch = source.watchReferences(() => this.changed())
    this.heartbeat = setInterval(() => this.changed(), heartbeatMs); this.heartbeat.unref()
    binding.signal.addEventListener('abort', this.aborted, { once: true })
    this.changed()
  }
  private changed() {
    this.dirty = true
    if (this.closed || this.flushing || this.scheduled) return
    this.scheduled = setTimeout(() => {
      this.scheduled = undefined
      void this.flush().catch(() => { if (!this.closed) { this.close(); this.binding.fail() } })
    }, 100)
    this.scheduled.unref()
  }
  private async flush() {
    this.flushing = true
    try {
      while (this.dirty && !this.closed) {
        const remaining = 250 - (Date.now() - this.lastWrite)
        if (remaining > 0) await delay(remaining, undefined, { signal: this.lifetime.signal })
        this.dirty = false
        const items = this.source.references()
        if (items.length > 128 || new Set(items.map(item => item.reference.question_id)).size !== items.length) throw new Error('invalid question reference snapshot')
        const native = [...new Set(items.map(item => item.nativeSessionId))]
        for (const id of this.catalogReady) if (!native.includes(id)) this.catalogReady.delete(id)
        const missing = native.filter(id => !this.catalogReady.has(id))
        for (let index = 0; index < missing.length; index += 32) {
          await Promise.all(missing.slice(index, index + 32).map(async id => { await this.binding.publishCatalog(id, this.lifetime.signal); this.catalogReady.add(id) }))
        }
        if (this.closed) return
        // Changes during the catalog barrier need a new snapshot before publishing.
        if (this.dirty) continue
        const frame = questionReferencesFrame.parse({ v: 1, type: 'question.references', request_id: randomUUID(), runtime_id: this.binding.runtimeId,
          runtime_epoch: this.binding.epoch, payload: { sequence: ++this.sequence, items: items.map(item => item.reference).sort((a, b) => a.question_id.localeCompare(b.question_id)) } })
        if (Buffer.byteLength(JSON.stringify(frame)) > 64 * 1024) throw new Error('question reference frame too large')
        let timer: NodeJS.Timeout
        const acknowledged = new Promise<void>((resolve, reject) => {
          const cleanup = () => { clearTimeout(timer); this.pending = undefined }
          this.pending = { id: frame.request_id, sequence: frame.payload.sequence, count: items.length,
            resolve: () => { cleanup(); resolve() }, reject: error => { cleanup(); reject(error) } }
          timer = setTimeout(() => this.pending?.reject(new Error('question reference acknowledgement timed out')), this.ackMs); timer.unref()
        })
        void acknowledged.catch(() => {})
        this.lastWrite = Date.now()
        await this.binding.send(frame)
        await acknowledged
      }
    } finally { this.flushing = false }
  }
  async handle(value: unknown): Promise<boolean> {
    if (!value || typeof value !== 'object' || !('type' in value)) return false
    const rejected = this.pending
    if (value.type === 'error' && 'request_id' in value && rejected && rejected.id === value.request_id) {
      rejected.reject(new Error('question reference publication rejected')); return true
    }
    if (value.type !== 'question.references.ack') return false
    const frame = questionReferencesAck.parse(value)
    if (frame.runtime_id !== this.binding.runtimeId || frame.runtime_epoch !== this.binding.epoch) throw new Error('question reference acknowledgement route mismatch')
    const pending = this.pending
    if (!pending || pending.id !== frame.request_id) throw new Error('unexpected question reference acknowledgement')
    if (pending.sequence !== frame.payload.sequence || pending.count !== frame.payload.item_count) throw new Error('question reference acknowledgement mismatch')
    pending.resolve()
    return true
  }
  close() {
    if (this.closed) return
    this.closed = true; this.lifetime.abort(); this.unwatch()
    this.binding.signal.removeEventListener('abort', this.aborted)
    clearInterval(this.heartbeat); clearTimeout(this.scheduled)
    this.catalogReady.clear()
    this.pending?.reject(new Error('question reference connection closed'))
  }
}
