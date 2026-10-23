import { randomUUID } from 'node:crypto'
import type { DshClient } from './dsh-client.js'
import type { InteractionRouter } from './interaction-router.js'
import { commandDigest, MemoryCommandJournal, type CommandJournal, type CommandOwner, type CommandState } from './command-journal.js'
import { type Command, type Frame, ProbeError } from './protocol.js'
import { SessionSync } from './session-sync.js'

const localCommandOwner: CommandOwner = { userId: 'local', deviceId: 'local' }
const definiteRejections = new Set([
  'access.denied', 'model.not_available', 'protocol.invalid', 'runtime.changed', 'runtime.offline', 'session.not_found',
  'interaction.stale', 'interaction.invalid_answer',
])

export type CommandStateObserver = (state: CommandState, result?: unknown) => void | Promise<void>

export class ProbeRuntime {
  readonly epoch = randomUUID()
  private readonly sync: SessionSync
  private readonly commands = new Map<string, { digest: string; result: Promise<unknown> }>()
  private readonly serial = new Map<string, Promise<unknown>>()
  private closed = false

  constructor(readonly client: DshClient, private readonly interactions: InteractionRouter, private readonly journal: CommandJournal = new MemoryCommandJournal(client.runtimeId)) {
    this.sync = new SessionSync(client, this.epoch, interactions)
  }

  private check(command: Command): void {
    if (this.closed) throw new ProbeError('runtime.offline')
    if (command.runtime_epoch !== this.epoch) throw new ProbeError('runtime.changed')
  }

  async dispatch(command: Command, signal: AbortSignal, owner: CommandOwner = localCommandOwner, observe?: CommandStateObserver): Promise<Frame> {
    this.check(command)
    signal.throwIfAborted()
    const report = async (state: CommandState, result?: unknown) => {
      try { await observe?.(state, result) } catch { /* Receipts are best effort; the durable local journal remains authoritative. */ }
    }
    const run = async () => {
      this.check(command)
      switch (command.type) {
        case 'session.list': return this.client.list(signal)
        case 'model.catalog': return this.client.modelCatalog()
        case 'session.create': return 'workspace_id' in command.payload
          ? this.client.createRemote(command.payload.workspace_id, command.payload.preset, signal)
          : this.client.create(command.payload.workspace, command.payload.preset)
        case 'session.page': return this.sync.page(command, signal)
        case 'interaction.list': return this.interactions.list()
        case 'interaction.answer': {
          const answer = command.payload.answer
          return this.interactions.answer(command.payload.interaction_id, 'decision' in answer ? answer : {
            answers: answer.answers.map(item => ({ id: item.id, selected: item.selected, ...(item.custom === undefined ? {} : { custom: item.custom }) })),
          })
        }
        case 'session.cancel': return this.client.cancel(await this.client.resolve(command.session_id, signal))
        case 'question.answer': return this.interactions.answerQuestion(command.session_id, command.payload.question_id, {
          answers: command.payload.answers.map(item => ({ id: item.id, selected: item.selected, ...(item.custom === undefined ? {} : { custom: item.custom }) })),
        })
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
          const content = 'text' in command.payload ? command.payload.text : command.payload.content
          const nativeRequestId = owner.deviceId === 'local'
            ? command.request_id
            : `${owner.deviceId}:${command.request_id}`
          return this.client.prompt(id, nativeRequestId, command.payload.mode, content, signal)
        }
        case 'session.subscribe': throw new ProbeError('protocol.streaming_required')
      }
    }
    const mutating = ['session.create', 'message.submit', 'session.cancel', 'session.model.select', 'interaction.answer', 'question.answer'].includes(command.type)
    let payload: unknown
    if (!mutating) payload = await run()
    else {
      const flightKey = `${owner.userId}\0${owner.deviceId}\0${command.request_id}`
      const existing = this.commands.get(flightKey)
      if (existing === undefined && this.commands.size >= 2048) throw new ProbeError('rate.limited')
      const admission = this.journal.admit(command, owner)
      if (existing) {
        if (existing.digest !== admission.digest) throw new ProbeError('command.request_conflict')
        payload = await existing.result
      } else if (admission.state === 'rejected') {
        await report(admission.state)
        throw new ProbeError(admission.errorCode ?? 'command.rejected')
      } else if (admission.state === 'outcome_unknown') {
        await report(admission.state)
        throw new ProbeError('command.outcome_unknown')
      } else if (admission.state === 'agent_queued' || admission.state === 'settled') {
        if (admission.result === undefined) throw new ProbeError('journal.integrity_failed')
        // A mobile retry may reach a host whose durable journal is ahead of the
        // Relay. Rebuild the server transition from its last known `received` state.
        await report('host_accepted')
        await report(admission.state, admission.result)
        payload = admission.result
      } else if (admission.state === 'dispatching' && command.type !== 'message.submit') {
        this.journal.fail(command.request_id, owner, 'outcome_unknown', 'command.outcome_unknown')
        await report('outcome_unknown')
        throw new ProbeError('command.outcome_unknown')
      } else {
        const admittedState = admission.state === 'dispatching' ? 'host_accepted' : admission.state
        const recoveringDispatch = admission.state === 'dispatching'
        const key = 'session_id' in command ? command.session_id : command.type
        const result = (this.serial.get(key) ?? Promise.resolve()).catch(() => {}).then(async () => {
          await report(admittedState)
          this.check(command)
          signal.throwIfAborted()
          this.journal.start(command.request_id, owner)
          await report('dispatching')
          try {
            const value = await run()
            const checkpointRequired = command.type === 'message.submit' || command.type === 'session.create'
            if (checkpointRequired && value !== null && typeof value === 'object'
              && 'checkpoint' in value && value.checkpoint !== null && typeof value.checkpoint === 'object'
              && 'state' in value.checkpoint && value.checkpoint.state !== 'persisted') {
              const uncertain = { ...value, command_state: 'outcome_unknown' }
              this.journal.fail(command.request_id, owner, 'outcome_unknown', 'command.outcome_unknown')
              await report('outcome_unknown')
              return uncertain
            }
            if (checkpointRequired && (value === null || typeof value !== 'object' || !('checkpoint' in value)
              || value.checkpoint === null || typeof value.checkpoint !== 'object' || !('state' in value.checkpoint))) {
              this.journal.fail(command.request_id, owner, 'outcome_unknown', 'command.outcome_unknown')
              await report('outcome_unknown')
              return { command_state: 'outcome_unknown' }
            }
            const state = command.type === 'message.submit' ? 'agent_queued' : 'settled'
            this.journal.complete(command.request_id, owner, state, value)
            await report(state, value)
            return value
          } catch (error) {
            if (!recoveringDispatch && error instanceof ProbeError && definiteRejections.has(error.code)) {
              this.journal.fail(command.request_id, owner, 'rejected', error.code)
              await report('rejected')
            } else {
              this.journal.fail(command.request_id, owner, 'outcome_unknown', 'command.outcome_unknown')
              await report('outcome_unknown')
            }
            throw error
          }
        })
        this.serial.set(key, result)
        this.commands.set(flightKey, { digest: admission.digest, result })
        void result.finally(() => {
          if (this.serial.get(key) === result) this.serial.delete(key)
          if (this.commands.get(flightKey)?.result === result) this.commands.delete(flightKey)
        }).catch(() => {})
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
