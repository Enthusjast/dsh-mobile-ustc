import { randomUUID } from 'node:crypto'
import type { DshClient } from './dsh-client.js'
import type { Command, Frame } from './protocol.js'
import { ProbeError } from './protocol.js'
import { projectChunk, projectEvent, projectStream } from './projection.js'

interface Sync { session: string; through: number }

export class SessionSync {
  private readonly cuts = new Map<string, Sync>()
  constructor(private readonly client: DshClient, private readonly epoch: string) {}

  async *follow(command: Extract<Command, { type: 'session.subscribe' }>, signal: AbortSignal): AsyncIterable<Frame> {
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
