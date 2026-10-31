import { randomUUID } from 'node:crypto'
import type { DshClient, DshPromptPart } from './dsh-client.js'
import type { InteractionRouter } from './interaction-router.js'
import { commandDigest, MemoryCommandJournal, type CommandJournal, type CommandOwner, type CommandState } from './command-journal.js'
import { type Command, type Frame, ProbeError } from './protocol.js'
import { SessionSync } from './session-sync.js'
import { NativeFileRegistry } from './file-registry.js'
import { FileExportRegistry } from './file-export-registry.js'
import { SessionMessageActions } from './session-message-actions.js'
import { forkSessionOnce } from './session-fork.js'
import { WorkspaceChanges } from './workspace-changes.js'

const localCommandOwner: CommandOwner = { userId: 'local', deviceId: 'local' }
const definiteRejections = new Set([
  'access.denied', 'model.not_available', 'protocol.invalid', 'runtime.changed', 'runtime.offline', 'session.not_found',
  'interaction.stale', 'interaction.invalid_answer',
  'session.active', 'session.archived',
  'file.staging_required',
  'image.invalid', 'image.too_large', 'image.busy', 'image.model_unsupported',
  'message.stale', 'message.unavailable', 'message.not_persisted',
])

export type CommandStateObserver = (state: CommandState, result?: unknown) => void | Promise<void>

export class ProbeRuntime {
  readonly files: NativeFileRegistry
  readonly exports: FileExportRegistry
  readonly messageActions: SessionMessageActions
  readonly changes = new WorkspaceChanges()
  private readonly sync: SessionSync
  private readonly commands = new Map<string, { digest: string; result: Promise<unknown> }>()
  private readonly serial = new Map<string, Promise<unknown>>()
  private closed = false
  private readonly lifetime = new AbortController()

  constructor(readonly client: DshClient, private readonly interactions: InteractionRouter, private readonly journal: CommandJournal = new MemoryCommandJournal(client.runtimeId), readonly epoch = randomUUID()) {
    this.files = new NativeFileRegistry(client, epoch)
    this.exports = new FileExportRegistry(client)
    this.sync = new SessionSync(client, this.epoch, interactions, interactions.timed)
    this.messageActions = new SessionMessageActions(client)
  }

  private check(command: Command): void {
    if (this.closed) throw new ProbeError('runtime.offline')
    if (command.runtime_epoch !== this.epoch) throw new ProbeError('runtime.changed')
  }

  async dispatch(command: Command, signal: AbortSignal, owner: CommandOwner = localCommandOwner, observe?: CommandStateObserver): Promise<Frame> {
    return this.execute(command, signal, owner, observe, false)
  }

  async reconcileFileMessage(command: Extract<Command, { type: 'message.submit' }>, signal: AbortSignal, owner: CommandOwner, observe?: CommandStateObserver): Promise<Frame> {
    if (command.type !== 'message.submit' || !('content' in command.payload) || !command.payload.content.some(part => part.type !== 'text')) throw new ProbeError('protocol.invalid')
    return this.execute(command, signal, owner, observe, true)
  }

  private async execute(command: Command, signal: AbortSignal, owner: CommandOwner, observe: CommandStateObserver | undefined, reconciliation: boolean): Promise<Frame> {
    this.check(command)
    signal = AbortSignal.any([signal, this.lifetime.signal])
    signal.throwIfAborted()
    const report = async (state: CommandState, result?: unknown) => {
      try { await observe?.(state, result) } catch { /* Receipts are best effort; the durable local journal remains authoritative. */ }
    }
    const run = async (recoveringDispatch = false) => {
      this.check(command)
      signal.throwIfAborted()
      switch (command.type) {
        case 'session.list': return this.client.list(signal)
        case 'model.catalog': return this.client.modelCatalog(signal)
        case 'session.create': return 'workspace_id' in command.payload
          ? this.client.createRemote(command.payload.workspace_id, command.payload.preset, signal)
          : this.client.create(command.payload.workspace, command.payload.preset, signal)
        case 'session.fork': return forkSessionOnce(this.client, this.messageActions, command.session_id, command.payload, owner, signal,
          partial => this.journal.noteResult(command.request_id, owner, partial))
        case 'session.page': return this.sync.page(command, signal)
        case 'interaction.list': return this.interactions.list()
        case 'interaction.answer': {
          const answer = command.payload.answer
          return this.interactions.answer(command.payload.interaction_id, 'decision' in answer ? answer : {
            answers: answer.answers.map(item => ({ id: item.id, selected: item.selected, ...(item.custom === undefined ? {} : { custom: item.custom }) })),
          })
        }
        case 'session.cancel': return this.client.cancel(await this.client.resolve(command.session_id, signal), signal)
        case 'session.archive': return this.client.archive(await this.client.resolve(command.session_id, signal), command.payload.archived, command.payload.stop_activity, signal)
        case 'question.answer': return this.interactions.answerQuestion(command.session_id, command.payload.question_id, {
          answers: command.payload.answers.map(item => ({ id: item.id, selected: item.selected, ...(item.custom === undefined ? {} : { custom: item.custom }) })),
        })
        case 'question.timed.answer': {
          const native = await this.client.resolve(command.session_id, signal)
          const result = this.interactions.timed.answer(command.session_id, command.payload.question_id, {
            answers: command.payload.answers.map(item => ({ id: item.id, selected: item.selected, ...(item.custom === undefined ? {} : { custom: item.custom }) })),
          })
          return result.delivery === 'late_message' ? { ...result, checkpoint: await this.client.checkpoint(native) } : result
        }
        case 'session.model.select': {
          const id = await this.client.resolve(command.session_id, signal)
          return this.client.selectModel(id, {
            provider: command.payload.provider,
            model: command.payload.model,
            ...(command.payload.reasoning_effort === undefined ? {} : { reasoning_effort: command.payload.reasoning_effort }),
          }, signal)
        }
        case 'message.submit': {
          const id = await this.client.resolve(command.session_id, signal)
          const nativeRequestId = owner.deviceId === 'local' ? command.request_id : `${owner.deviceId}:${command.request_id}`
          if (reconciliation) return this.client.reconcilePrompt(id, nativeRequestId, signal)
          const wire = 'text' in command.payload ? command.payload.text : command.payload.content
          const files = new Set<string>()
          let missing = false
          let content: string | DshPromptPart[]
          if (typeof wire === 'string') content = wire
          else {
            const resolved: DshPromptPart[] = []
            for (const part of wire) {
              if (part.type === 'text') { resolved.push(part); continue }
              files.add(part.file_id)
              try { resolved.push(part.type === 'image' ? await this.files.resolveImage(part.file_id, command.session_id, owner, signal) : this.files.resolve(part.file_id, command.session_id, owner)) }
              catch (error) {
                if (!recoveringDispatch || !(error instanceof ProbeError) || error.code !== 'file.staging_required') throw error
                missing = true
              }
            }
            content = resolved
          }
          if (missing) return this.client.reconcilePrompt(id, nativeRequestId, signal)
          try { return await this.client.prompt(id, nativeRequestId, command.payload.mode, content, signal) }
          finally { for (const file of files) this.files.drop(file) }
        }
        case 'session.subscribe': throw new ProbeError('protocol.streaming_required')
      }
    }
    const mutating = ['session.create', 'session.fork', 'message.submit', 'session.cancel', 'session.archive', 'session.model.select', 'interaction.answer', 'question.answer', 'question.timed.answer'].includes(command.type)
    let payload: unknown
    if (!mutating) payload = await run()
    else {
      const flightKey = `${owner.userId}\0${owner.deviceId}\0${command.request_id}`
      const existing = this.commands.get(flightKey)
      if (existing === undefined && this.commands.size >= 2048) throw new ProbeError('rate.limited')
      const admission = reconciliation ? this.journal.lookup(command, owner) : this.journal.admit(command, owner)
      if (!admission) { await report('outcome_unknown'); throw new ProbeError('command.outcome_unknown') }
      if (existing) {
        if (existing.digest !== admission.digest) throw new ProbeError('command.request_conflict')
        try { payload = await existing.result }
        finally {
          if (reconciliation) {
            const latest = this.journal.lookup(command, owner)
            if (latest?.state === 'agent_queued' || latest?.state === 'settled') { await report('host_accepted'); await report(latest.state, latest.result) }
            else {
              if (latest?.state === 'host_accepted' || latest?.state === 'dispatching') this.journal.fail(command.request_id, owner, 'outcome_unknown', 'command.outcome_unknown')
              await report(latest?.state === 'rejected' ? 'rejected' : 'outcome_unknown')
            }
          }
        }
      } else if (admission.state === 'rejected') {
        await report(admission.state)
        throw new ProbeError(admission.errorCode ?? 'command.rejected')
      } else if (admission.state === 'outcome_unknown') {
        await report(admission.state, admission.result)
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
        await report('outcome_unknown', admission.result)
        throw new ProbeError('command.outcome_unknown')
      } else {
        const admittedState = admission.state === 'dispatching' ? 'host_accepted' : admission.state
        const recoveringDispatch = admission.state === 'dispatching' || reconciliation
        const key = 'session_id' in command ? command.session_id : command.type
        const result = (this.serial.get(key) ?? Promise.resolve()).catch(() => {}).then(async () => {
          await report(admittedState)
          this.check(command)
          signal.throwIfAborted()
          this.journal.start(command.request_id, owner)
          await report('dispatching')
          try {
            const value = await run(recoveringDispatch)
            if (command.type === 'session.fork' && value !== null && typeof value === 'object' && 'command_state' in value && value.command_state === 'outcome_unknown') {
              this.journal.noteResult(command.request_id, owner, value)
              this.journal.fail(command.request_id, owner, 'outcome_unknown', 'command.outcome_unknown')
              await report('outcome_unknown', value)
              return value
            }
            const lateAnswer = command.type === 'question.timed.answer' && value !== null && typeof value === 'object' && 'delivery' in value && value.delivery === 'late_message'
            const checkpointRequired = command.type === 'message.submit' || command.type === 'session.create' || command.type === 'session.fork' || command.type === 'session.model.select' || lateAnswer
            if (checkpointRequired && value !== null && typeof value === 'object'
              && 'checkpoint' in value && value.checkpoint !== null && typeof value.checkpoint === 'object'
              && 'state' in value.checkpoint && value.checkpoint.state !== 'persisted') {
              const uncertain = { ...value, command_state: 'outcome_unknown' }
              this.journal.fail(command.request_id, owner, 'outcome_unknown', 'command.outcome_unknown')
              await report('outcome_unknown', uncertain)
              return uncertain
            }
            if (checkpointRequired && (value === null || typeof value !== 'object' || !('checkpoint' in value)
              || value.checkpoint === null || typeof value.checkpoint !== 'object' || !('state' in value.checkpoint))) {
              this.journal.fail(command.request_id, owner, 'outcome_unknown', 'command.outcome_unknown')
              await report('outcome_unknown')
              return { command_state: 'outcome_unknown' }
            }
            const state = command.type === 'message.submit' || lateAnswer ? 'agent_queued' : 'settled'
            this.journal.complete(command.request_id, owner, state, value)
            await report(state, value)
            return value
          } catch (error) {
            if (!recoveringDispatch && error instanceof ProbeError && definiteRejections.has(error.code)) {
              this.journal.fail(command.request_id, owner, 'rejected', error.code)
              await report('rejected')
            } else {
              this.journal.fail(command.request_id, owner, 'outcome_unknown', 'command.outcome_unknown')
              await report('outcome_unknown', this.journal.lookup(command, owner)?.result)
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


  mediaCurrent(session: string, sync: string): boolean { return !this.closed && this.sync.mediaCurrent(session, sync) }
  follow(command: Extract<Command, { type: 'session.subscribe' }>, signal: AbortSignal) {
    this.check(command)
    return this.sync.follow(command, AbortSignal.any([signal, this.lifetime.signal]))
  }

  claimQuestion(sessionId: string, questionId: string, signal: AbortSignal) {
    if (this.closed) throw new ProbeError('runtime.offline')
    return this.interactions.timed.claim(sessionId, questionId, AbortSignal.any([signal, this.lifetime.signal]))
  }

  close(): void {
    if (this.closed) return
    this.closed = true
    this.lifetime.abort()
    // The plugin's asynchronous teardown separately awaits export cleanup.
    void this.exports.close().catch(() => {})
    this.files.close()
    this.messageActions.close()
    this.changes.close()
    this.interactions.close()
  }
}
