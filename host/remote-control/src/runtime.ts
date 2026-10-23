import { createHash, randomUUID } from 'node:crypto'
import type { DshClient } from './dsh-client.js'
import type { InteractionRouter } from './interaction-router.js'
import { type Command, type Frame, ProbeError } from './protocol.js'
import { SessionSync } from './session-sync.js'

export class ProbeRuntime {
  readonly epoch = randomUUID()
  private readonly sync: SessionSync
  private readonly commands = new Map<string, { digest: string; result: Promise<unknown> }>()
  private readonly serial = new Map<string, Promise<unknown>>()
  private closed = false

  constructor(readonly client: DshClient, private readonly interactions: InteractionRouter) {
    this.sync = new SessionSync(client, this.epoch)
  }

  private check(command: Command): void {
    if (this.closed) throw new ProbeError('runtime.offline')
    if (command.runtime_epoch !== this.epoch) throw new ProbeError('runtime.changed')
  }

  async dispatch(command: Command, signal: AbortSignal): Promise<Frame> {
    this.check(command)
    signal.throwIfAborted()
    const run = async () => {
      this.check(command)
      switch (command.type) {
        case 'session.list': return this.client.list(signal)
        case 'model.catalog': return this.client.modelCatalog()
        case 'session.create': return this.client.create(command.payload.workspace, command.payload.preset)
        case 'session.page': return this.sync.page(command, signal)
        case 'interaction.list': return this.interactions.list()
        case 'interaction.answer': {
          const answer = command.payload.answer
          return this.interactions.answer(command.payload.interaction_id, 'decision' in answer ? answer : {
            answers: answer.answers.map(item => ({ id: item.id, selected: item.selected, ...(item.custom === undefined ? {} : { custom: item.custom }) })),
          })
        }
        case 'session.cancel': return this.client.cancel(await this.client.resolve(command.session_id, signal))
        case 'session.model.select': {
          const id = await this.client.resolve(command.session_id, signal)
          return this.client.selectModel(id, {
            provider: command.payload.provider,
            model: command.payload.model,
            ...(command.payload.reasoning_effort === undefined ? {} : { reasoning_effort: command.payload.reasoning_effort }),
          })
        }
        case 'message.submit': {
          const id = await this.client.resolve(command.session_id, signal)
          return this.client.prompt(id, command.request_id, command.payload.mode, command.payload.text, signal)
        }
        case 'session.subscribe': throw new ProbeError('protocol.streaming_required')
      }
    }
    const mutating = ['session.create', 'message.submit', 'session.cancel', 'session.model.select', 'interaction.answer'].includes(command.type)
    let payload: unknown
    if (!mutating) payload = await run()
    else {
      const digest = createHash('sha256').update(JSON.stringify(command)).digest('hex')
      const existing = this.commands.get(command.request_id)
      if (existing) {
        if (existing.digest !== digest) throw new ProbeError('command.request_conflict')
        payload = await existing.result
      } else {
        // No eviction: losing an in-epoch mutation record would silently permit replay.
        if (this.commands.size >= 2048) throw new ProbeError('rate.limited')
        const key = 'session_id' in command ? command.session_id : command.type
        const result = (this.serial.get(key) ?? Promise.resolve()).catch(() => {}).then(run)
        this.serial.set(key, result)
        this.commands.set(command.request_id, { digest, result })
        void result.finally(() => { if (this.serial.get(key) === result) this.serial.delete(key) }).catch(() => {})
        payload = await result
      }
    }
    return { v: 0, type: `${command.type}.result`, request_id: command.request_id, runtime_epoch: this.epoch, payload }
  }

  follow(command: Extract<Command, { type: 'session.subscribe' }>, signal: AbortSignal) {
    this.check(command)
    return this.sync.follow(command, signal)
  }

  close(): void { this.closed = true; this.interactions.close() }
}
