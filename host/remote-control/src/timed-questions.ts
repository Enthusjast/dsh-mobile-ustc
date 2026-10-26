import { randomUUID } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type { ToolCallId } from '@deepseek-ai/dsh-llm'
import { UserQuestionError, type AskUserQuestionAnswer, type AskUserQuestionRequest, type AskUserQuestionItem, type UserQuestionProjectionView } from '@deepseek-ai/dsh-user-questions'
import { mobileSessionId } from './dsh-client.js'
import { ProbeError } from './protocol.js'
import type { BlockingQuestion, TimedQuestionSnapshot, TimedQuestionView } from './questions.js'
import type { LocalQuestionReference } from './question-reference-protocol.js'
import { routableQuestionAgent } from './question-owner.js'

interface TimedRecord {
  id: string
  agent: Agent
  callId: ToolCallId
  questions: readonly AskUserQuestionItem[]
  projected: BlockingQuestion['questions']
  bytes: number
  view?: TimedQuestionView
  wait?: { finish(answer?: AskUserQuestionAnswer, error?: unknown): void }
  replied: boolean
  foregroundAnswered: boolean
  expiresAt?: number
  timer?: NodeJS.Timeout
  claims: Set<AbortController>
}

/** Adapts native timed waits and continued replies without recreating a tool callback. */
export class TimedQuestions {
  private readonly records = new Map<string, TimedRecord>()
  private readonly listeners = new Map<string, Set<() => void>>()
  private readonly referenceListeners = new Set<() => void>()
  private readonly invalidated = new WeakSet<Agent>()
  private revision = 0
  private bytes = 0
  private claimCount = 0
  private closed = false

  constructor(
    private readonly ctx: Context,
    private readonly runtimeId: string,
    private readonly managed: (agent: Agent | undefined) => boolean,
    private readonly project: (questions: readonly AskUserQuestionItem[]) => BlockingQuestion['questions'],
    private readonly validate: (questions: readonly AskUserQuestionItem[], answer: AskUserQuestionAnswer) => void,
  ) {
    ctx.on('session/event', session => {
      const agent = ctx.agents.get(session.id)
      if (agent && this.live(agent)) this.refresh(agent)
    }, { global: true })
    ctx.on('agent/inbox/discarded', ({ agent, message }) => {
      if (message.source.kind !== 'user-question-reply') return
      const record = this.records.get(this.key(agent, message.source.callId))
      if (record) { record.replied = false; this.refresh(agent) }
    }, { global: true })
  }

  private key(agent: Agent, callId: string): string { return JSON.stringify([agent.id, callId]) }
  private live(agent: Agent, roots?: ReadonlySet<Agent>): boolean {
    return !this.closed && !this.invalidated.has(agent) && routableQuestionAgent(this.ctx, agent, this.managed, roots)
  }

  private create(agent: Agent, callId: ToolCallId, questions: readonly AskUserQuestionItem[]): TimedRecord {
    const projected = this.project(questions)
    const bytes = Buffer.byteLength(JSON.stringify(projected))
    if (this.records.size >= 64 || bytes > 128 * 1024 || this.bytes + bytes > 1024 * 1024) throw new ProbeError('question.too_large')
    const record: TimedRecord = { id: randomUUID(), agent, callId, questions, projected, bytes, replied: false, foregroundAnswered: false, claims: new Set() }
    this.records.set(this.key(agent, callId), record)
    this.bytes += bytes
    return record
  }

  async question(request: AskUserQuestionRequest): Promise<AskUserQuestionAnswer> {
    const agent = request.agent
    if (!agent || !request.wait?.timed || !request.signal || !this.live(agent)) throw new ProbeError('question.unavailable')
    if (request.signal.aborted) throw request.signal.reason
    const key = this.key(agent, request.wait.callId)
    if (this.records.has(key)) throw new ProbeError('interaction.stale')
    const record = this.create(agent, request.wait.callId, request.questions)
    return new Promise<AskUserQuestionAnswer>((resolve, reject) => {
      const signal = request.signal!
      const aborted = () => finish(undefined, signal.reason)
      const finish = (answer?: AskUserQuestionAnswer, error?: unknown) => {
        if (!record.wait) return
        delete record.wait
        signal.removeEventListener('abort', aborted)
        this.release(record)
        if (answer) { record.foregroundAnswered = true; resolve(answer) }
        else reject(error ?? new UserQuestionError('timed question was cancelled', 'ASK_ABORTED'))
        this.refresh(agent)
      }
      record.wait = { finish }
      this.setView(record, 'open')
      signal.addEventListener('abort', aborted, { once: true })
      if (signal.aborted) aborted()
    })
  }

  /** A claim is tied to a UI/subscription lifetime and never extends the native deadline. */
  async *claim(sessionId: string, id: string, signal: AbortSignal): AsyncIterable<{ remaining_ms: number; expires_at: string }> {
    const record = this.find(sessionId, id)
    if (!record.wait || this.claimCount >= 128 || record.claims.size >= 8) throw new ProbeError(record.wait ? 'rate.limited' : 'interaction.stale')
    const lifetime = new AbortController()
    const abort = () => lifetime.abort()
    signal.addEventListener('abort', abort, { once: true })
    if (signal.aborted) abort()
    record.claims.add(lifetime)
    this.claimCount++
    const native = this.ctx.userQuestions.attachWait(record.agent, record.callId, lifetime.signal)[Symbol.asyncIterator]()
    try {
      const startedAt = Date.now()
      const first = await native.next()
      if (first.done || signal.aborted || !record.wait) return
      // Use the pre-read clock as an upper bound; scheduling the first yield
      // must not add its delay to the native foreground deadline.
      const deadline = startedAt + first.value.remainingMs
      const remaining = Math.max(0, deadline - Date.now())
      if (record.expiresAt === undefined || deadline < record.expiresAt) {
        record.expiresAt = deadline
        clearTimeout(record.timer)
        record.timer = setTimeout(() => record.wait?.finish(undefined,
          new UserQuestionError('timed question foreground window expired', 'ASK_TIMED_OUT')), Math.max(0, deadline - Date.now()))
        record.timer.unref()
      }
      this.setView(record, 'open')
      yield { remaining_ms: remaining, expires_at: new Date(record.expiresAt).toISOString() }
      await native.next()
    } finally {
      signal.removeEventListener('abort', abort)
      lifetime.abort()
      record.claims.delete(lifetime)
      this.claimCount--
      await native.return?.()
    }
  }

  answer(sessionId: string, id: string, answer: AskUserQuestionAnswer): { accepted: true; delivery: 'foreground' | 'late_message' } {
    const record = this.find(sessionId, id)
    this.refresh(record.agent)
    if (!this.records.has(this.key(record.agent, record.callId)) || record.foregroundAnswered || record.replied) throw new ProbeError('interaction.stale')
    this.validate(record.questions, answer)
    if (record.wait) {
      if (record.expiresAt !== undefined && Date.now() >= record.expiresAt) {
        record.wait.finish(undefined, new UserQuestionError('timed question foreground window expired', 'ASK_TIMED_OUT'))
        throw new ProbeError('interaction.stale')
      }
      record.wait.finish(answer)
      return { accepted: true, delivery: 'foreground' }
    }
    if (record.view?.state !== 'continued') throw new ProbeError('interaction.stale')
    try {
      if (!this.ctx.userQuestions.answer(record.agent, record.callId, answer)) throw new ProbeError('interaction.stale')
    } catch (error) {
      if (error instanceof UserQuestionError && error.code === 'BAD_ANSWER') throw new ProbeError('interaction.invalid_answer')
      if (error instanceof UserQuestionError && error.code === 'REPLY_QUEUED') throw new ProbeError('interaction.stale')
      throw error
    }
    record.replied = true
    this.refresh(record.agent)
    return { accepted: true, delivery: 'late_message' }
  }

  private find(sessionId: string, id: string): TimedRecord {
    for (const record of this.records.values()) {
      if (record.id === id && mobileSessionId(this.runtimeId, record.agent.id) === sessionId && this.live(record.agent)) return record
    }
    throw new ProbeError('interaction.stale')
  }

  private refresh(agent: Agent, roots?: ReadonlySet<Agent>): void {
    if (!this.live(agent, roots)) return
    const projection = this.ctx.sessionProjections.snapshot(agent.session, ['userQuestions']).values.userQuestions as UserQuestionProjectionView | undefined
    const active = new Map((projection?.active ?? []).map(item => [String(item.callId), item]))
    for (const question of active.values()) {
      if (question.state !== 'continued' || this.records.has(this.key(agent, question.callId))) continue
      try { this.create(agent, question.callId, question.questions) }
      catch { /* Unprojectable or over-budget history cannot break native event commits. */ }
    }
    for (const record of [...this.records.values()]) {
      if (record.agent !== agent) continue
      const question = active.get(String(record.callId))
      if (record.wait) this.setView(record, 'open')
      else if (!record.foregroundAnswered && question?.state === 'continued') this.setView(record, record.replied ? 'reply_queued' : 'continued')
      else if (question?.state === 'open') this.setView(record, undefined)
      else this.remove(record)
    }
  }

  private setView(record: TimedRecord, state: TimedQuestionView['state'] | undefined): void {
    const next = state === undefined ? undefined : {
      question_id: record.id, state, questions: record.projected,
      expires_at: state === 'open' && record.expiresAt !== undefined ? new Date(record.expiresAt).toISOString() : null,
    }
    if (JSON.stringify(next) === JSON.stringify(record.view)) return
    if (next) record.view = next
    else delete record.view
    this.changed(mobileSessionId(this.runtimeId, record.agent.id))
  }

  snapshot(sessionId: string): TimedQuestionSnapshot {
    for (const agent of this.ctx.agents.roots()) if (mobileSessionId(this.runtimeId, agent.id) === sessionId && this.live(agent)) this.refresh(agent)
    return { revision: this.revision, items: [...this.records.values()].filter(record => record.view && mobileSessionId(this.runtimeId, record.agent.id) === sessionId).map(record => structuredClone(record.view!)) }
  }

  watch(sessionId: string, changed: () => void): () => void {
    const listeners = this.listeners.get(sessionId) ?? new Set()
    listeners.add(changed)
    this.listeners.set(sessionId, listeners)
    return () => { listeners.delete(changed); if (!listeners.size) this.listeners.delete(sessionId) }
  }

  private changed(sessionId: string): void {
    this.revision++
    for (const listener of this.listeners.get(sessionId) ?? []) listener()
    for (const listener of this.referenceListeners) listener()
  }

  references(): LocalQuestionReference[] {
    const roots = new Set(this.ctx.agents.roots())
    for (const agent of roots) this.refresh(agent, roots)
    return [...this.records.values()].flatMap(record => {
      const view = record.view
      if (!view) return []
      const common = { question_id: view.question_id, session_id: mobileSessionId(this.runtimeId, record.agent.id), kind: 'timed_question' as const }
      return [{ nativeSessionId: record.agent.id, reference: view.state === 'open'
        ? { ...common, state: 'pending' as const, expires_at: view.expires_at }
        : { ...common, state: view.state, expires_at: null } }]
    })
  }

  watchReferences(changed: () => void): () => void {
    this.referenceListeners.add(changed)
    return () => { this.referenceListeners.delete(changed) }
  }

  private release(record: TimedRecord): void {
    clearTimeout(record.timer)
    delete record.timer
    for (const claim of record.claims) claim.abort()
  }

  private remove(record: TimedRecord): void {
    this.release(record)
    if (!this.records.delete(this.key(record.agent, record.callId))) return
    this.bytes -= record.bytes
    if (record.view) this.changed(mobileSessionId(this.runtimeId, record.agent.id))
  }

  invalidate(sessionId: string): void {
    for (const agent of this.ctx.agents.roots()) if (mobileSessionId(this.runtimeId, agent.id) === sessionId) this.invalidated.add(agent)
    for (const record of [...this.records.values()]) if (mobileSessionId(this.runtimeId, record.agent.id) === sessionId) {
      record.wait?.finish(undefined, new UserQuestionError('question owner was invalidated', 'ASK_ABORTED'))
      this.remove(record)
    }
  }

  close(): void {
    this.closed = true
    for (const record of [...this.records.values()]) {
      record.wait?.finish(undefined, new UserQuestionError('question adapter was disposed', 'ASK_ABORTED'))
      this.remove(record)
    }
    this.listeners.clear()
    this.referenceListeners.clear()
  }
}
