import { randomUUID } from 'node:crypto'
import type { DshClient } from './dsh-client.js'
import type { Command, Frame } from './protocol.js'
import { ProbeError } from './protocol.js'
import { projectChunk, projectEvent, projectStream } from './projection.js'
import type { QuestionSource, TimedQuestionSource } from './questions.js'

interface Sync { session: string; through: number }

export class SessionSync {
  private readonly cuts = new Map<string, Sync>()
  constructor(private readonly client: DshClient, private readonly epoch: string, private readonly questions?: QuestionSource, private readonly timed?: TimedQuestionSource) {}

  async *follow(command: Extract<Command, { type: 'session.subscribe' }>, signal: AbortSignal): AsyncIterable<Frame> {
    if (!this.questions) { yield* this.nativeFollow(command, signal); return }
    const lifetime = new AbortController()
    let changed = true
    let timedChanged = true
    let wake: (() => void) | undefined
    const abort = () => { lifetime.abort(); wake?.() }
    signal.addEventListener('abort', abort, { once: true })
    if (signal.aborted) abort()
    const dispose = this.questions.watch(command.session_id, () => { changed = true; wake?.() })
    const disposeTimed = this.timed?.watch(command.session_id, () => { timedChanged = true; wake?.() })
    const iterator = this.nativeFollow(command, lifetime.signal)[Symbol.asyncIterator]()
    let nativeValue: IteratorResult<Frame> | undefined
    let nativeFailed = false
    let nativeError: unknown
    const advance = () => {
      // Attach once per native read. Repeated question notices must not add
      // Promise.race handlers to an indefinitely pending native follower.
      void iterator.next().then(value => { nativeValue = value; wake?.() }, error => {
        nativeFailed = true; nativeError = error; wake?.()
      })
    }
    advance()
    let syncId: string | undefined
    let baselineReady = false
    try {
      while (!signal.aborted) {
        if (nativeFailed) throw nativeError
        if (changed && syncId && baselineReady) {
          changed = false
          yield { v: 0, type: 'question.snapshot', runtime_epoch: this.epoch, request_id: command.request_id,
            session_id: command.session_id, sync_id: syncId, payload: this.questions.snapshot(command.session_id) }
          continue
        }
        if (timedChanged && this.timed && syncId && baselineReady) {
          timedChanged = false
          yield { v: 0, type: 'question.timed.snapshot', runtime_epoch: this.epoch, request_id: command.request_id,
            session_id: command.session_id, sync_id: syncId, payload: this.timed.snapshot(command.session_id) }
          continue
        }
        if (!nativeValue) {
          await new Promise<void>(resolve => { wake = resolve })
          wake = undefined
          continue
        }
        const item = nativeValue
        nativeValue = undefined
        if (item.done) return
        const frame = item.value
        if (frame.type === 'session.snapshot') syncId = frame.sync_id
        if (frame.type === 'session.checkpoint') baselineReady = true
        advance()
        yield frame
      }
    } finally {
      dispose()
      disposeTimed?.()
      signal.removeEventListener('abort', abort)
      lifetime.abort()
      await iterator.return?.()
    }
  }

  private async *nativeFollow(command: Extract<Command, { type: 'session.subscribe' }>, signal: AbortSignal): AsyncIterable<Frame> {
    if (this.cuts.size >= 32) throw new ProbeError('rate.limited')
    const native = await this.client.resolve(command.session_id, signal)
    const syncId = randomUUID()
    const frame = (type: string, payload: unknown): Frame => ({
      v: 0, type, runtime_epoch: this.epoch, request_id: command.request_id, session_id: command.session_id, sync_id: syncId, payload,
    })
    try {
      for await (const source of this.client.follow(native, command.payload.max_messages, signal)) {
        if (source.type === 'snapshot') {
          this.cuts.set(syncId, { session: command.session_id, through: source.cursor })
          yield frame('session.snapshot', {
            cursor: source.cursor, has_more: source.hasMore, records: source.records.map(record => projectEvent(record.event)),
            assistant: source.assistantStream === undefined ? null : {
              revision: source.assistantStream.revision,
              ...(source.assistantStream.activeAttempt === undefined ? {} : { activeAttempt: {
                ...source.assistantStream.activeAttempt, stream: projectStream(source.assistantStream.activeAttempt.stream),
              } }),
            },
          })
          yield frame('session.checkpoint', await this.client.checkpoint(native))
        } else if (source.type === 'event') {
          yield frame('session.event', projectEvent(source.event))
          // turn/end is an observation until its own flush barrier has succeeded.
          if (source.event.type === 'turn/end') yield frame('session.checkpoint', await this.client.checkpoint(native))
        } else {
          yield frame(`assistant.${source.frame.type}`, source.frame.type === 'chunk' ? { ...source.frame, chunk: projectChunk(source.frame.chunk) } : source.frame)
        }
      }
    } finally { this.cuts.delete(syncId) }
  }

  async page(command: Extract<Command, { type: 'session.page' }>, signal: AbortSignal) {
    const cut = this.cuts.get(command.payload.sync_id)
    if (!cut || cut.session !== command.session_id || cut.through !== command.payload.through_seq
      || command.payload.before_seq > cut.through + 1) throw new ProbeError('protocol.resync_required')
    const native = await this.client.resolve(command.session_id, signal)
    const page = await this.client.page(native, {
      throughSeq: cut.through, beforeSeq: command.payload.before_seq, maxMessages: command.payload.max_messages,
    }, signal)
    return { records: page.records.map(record => projectEvent(record.event)), has_more: page.hasMore, through_seq: cut.through }
  }
}
