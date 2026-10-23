import { randomUUID } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type { ToolExecution } from '@deepseek-ai/dsh-tools'
import type { ApprovalRequest, ApprovalOutcome } from '@deepseek-ai/dsh-user-approval'
import type { AskUserQuestionRequest, AskUserQuestionAnswer } from '@deepseek-ai/dsh-user-questions'
import { mobileSessionId } from './dsh-client.js'
import { ProbeError } from './protocol.js'
import { questionItem, type BlockingQuestion, type QuestionSnapshot, type QuestionSource } from './questions.js'

type Answer = { decision: 'allow_once' | 'reject' } | AskUserQuestionAnswer
interface Pending {
  view: { interaction_id: string; session_id: string; kind: 'approval' | 'question'; expires_at: string; detail: unknown }
  finish(answer?: Answer): void
  question?: BlockingQuestion
}

/** M0 local human answerer, without mobile identity or production signing claims. */
export class InteractionRouter implements QuestionSource {
  private readonly pending = new Map<string, Pending>()
  private readonly executions = new Map<string, ToolExecution>()
  private readonly approved = new Set<symbol>()
  private closed = false
  private revision = 0
  private questionBytes = 0
  private readonly questionListeners = new Map<string, Set<() => void>>()

  constructor(
    private readonly ctx: Context,
    private readonly runtimeId: string,
    private readonly managed: (agent: Agent | undefined) => boolean,
    private readonly highRiskTools: readonly string[],
    private readonly timeoutMs: number,
  ) {
    ctx.on('tools/pre-execute', async (exec, next) => {
      if (!this.protected(exec)) return next()
      const previous = await next()
      // Preserve every existing denial, cancellation, or stronger native ask.
      if (previous.kind === 'deny' || previous.kind === 'cancel') return previous
      if (this.closed || exec.agent === undefined) return { kind: 'deny', reason: 'remote probe unavailable' }
      const key = this.key(exec.agent, exec.callId)
      this.executions.set(key, exec)
      try {
        const outcome = await ctx.approval.request({ agent: exec.agent, toolName: exec.name, callId: exec.callId, signal: exec.signal,
          ...(previous.kind === 'ask' && previous.reason !== undefined ? { reason: previous.reason } : {}),
        })
        return outcome === 'allowed-once' ? { kind: 'allow' } : { kind: 'deny', reason: 'local remote-control approval required' }
      } finally { this.executions.delete(key) }
    }, { prepend: true })

    ctx.on('approval/request', (request, next) => this.approval(request, next), { prepend: true })
    ctx.on('user-questions/request', (request, next) => this.question(request, next), { prepend: true })
    ctx.tools.guard(exec => {
      if (!this.protected(exec)) return
      // Only this answerer can mint a token. A preceding allow-listener cannot.
      if (!this.approved.delete(exec.token)) return 'local remote-control approval missing'
      if (this.closed || exec.signal.aborted) return 'local remote-control approval invalidated'
    })
    ctx.on('tools/result', exec => { this.approved.delete(exec.token) })
    ctx.on('agent/disposed', ({ agent }) => this.invalidate(mobileSessionId(runtimeId, agent.id)), { global: true })
    ctx.effect(() => () => this.close(), 'remote-control.interactions')
  }

  private key(agent: Agent, callId: string): string { return JSON.stringify([agent.id, callId]) }
  private protected(exec: Readonly<ToolExecution>): boolean {
    return this.highRiskTools.includes(exec.name) && (exec.agent === undefined || this.managed(exec.agent))
  }

  private async approval(request: ApprovalRequest, next: () => Promise<ApprovalOutcome>): Promise<ApprovalOutcome> {
    if (!this.managed(request.agent)) return next()
    const exec = request.callId === undefined ? undefined : this.executions.get(this.key(request.agent, request.callId))
    if (exec === undefined || exec.name !== request.toolName || this.closed) return 'unavailable'
    const answer = await this.wait(request.agent, 'approval', {
      call_id: exec.callId, tool: exec.name, arguments: exec.arguments,
    }, request.signal)
    if (answer === undefined || !('decision' in answer)) return 'cancelled'
    if (answer.decision === 'reject') return 'rejected'
    if (this.closed || exec.signal.aborted) return 'cancelled'
    this.approved.add(exec.token)
    return 'allowed-once'
  }

  private async question(request: AskUserQuestionRequest, next: () => Promise<AskUserQuestionAnswer>): Promise<AskUserQuestionAnswer> {
    if (!this.managed(request.agent)) return next()
    // A timed question also requires the native wait claim and late-answer path.
    // Until that adapter is verified, fail closed instead of pretending it is indefinite.
    if (request.wait?.timed) throw new ProbeError('question.timed_unsupported')
    if (request.agent === undefined) throw new ProbeError('question.unavailable')
    const answer = await this.wait(request.agent, 'question', { questions: request.questions }, request.signal)
    if (answer === undefined || !('answers' in answer)) throw new ProbeError('question.cancelled')
    return answer
  }

  private wait(agent: Agent, kind: 'approval' | 'question', detail: unknown, signal?: AbortSignal): Promise<Answer | undefined> {
    if (this.closed || signal?.aborted || this.pending.size >= 64) return Promise.resolve(undefined)
    const id = randomUUID()
    const sessionId = mobileSessionId(this.runtimeId, agent.id)
    const expiresAt = new Date(Date.now() + this.timeoutMs).toISOString()
    const question = kind === 'question' ? this.projectQuestion(id, expiresAt, detail) : undefined
    const bytes = question === undefined ? 0 : Buffer.byteLength(JSON.stringify(question))
    if (bytes > 128 * 1024 || this.questionBytes + bytes > 1024 * 1024) return Promise.reject(new ProbeError('question.too_large'))
    return new Promise(resolve => {
      const onAbort = () => finish()
      const timer = setTimeout(onAbort, this.timeoutMs)
      timer.unref()
      const finish = (answer?: Answer) => {
        if (!this.pending.delete(id)) return
        this.questionBytes -= bytes
        clearTimeout(timer)
        signal?.removeEventListener('abort', onAbort)
        resolve(answer)
        if (question) this.changed(sessionId)
      }
      this.pending.set(id, {
        view: { interaction_id: id, session_id: sessionId, kind, expires_at: expiresAt, detail },
        finish, ...(question ? { question } : {}),
      })
      this.questionBytes += bytes
      if (question) this.changed(sessionId)
      signal?.addEventListener('abort', onAbort, { once: true })
      if (signal?.aborted) finish()
    })
  }

  list() { return { items: [...this.pending.values()].map(item => item.view) } }

  private projectQuestion(id: string, expiresAt: string, detail: unknown): BlockingQuestion {
    const { questions } = detail as { questions: AskUserQuestionRequest['questions'] }
    const projected = questions.map(question => questionItem.parse({
      id: question.id, question: question.question,
      ...(question.detail === undefined ? {} : { detail: question.detail }),
      ...(question.header === undefined ? {} : { header: question.header }),
      ...(question.options === undefined ? {} : { options: question.options.map(option => ({ label: option.label, ...(option.description === undefined ? {} : { description: option.description }) })) }),
      ...(question.multiSelect === undefined ? {} : { multi_select: question.multiSelect }),
      ...(question.intent === undefined ? {} : { intent: { kind: question.intent.kind, approve: question.intent.approve } }),
    }))
    if (projected.length < 1 || projected.length > 32 || new Set(projected.map(item => item.id)).size !== projected.length) throw new ProbeError('question.invalid')
    return { question_id: id, expires_at: expiresAt, questions: projected }
  }

  snapshot(sessionId: string): QuestionSnapshot {
    return { revision: this.revision, items: [...this.pending.values()].filter(item => item.view.session_id === sessionId && item.question).map(item => structuredClone(item.question!)) }
  }

  watch(sessionId: string, listener: () => void): () => void {
    const listeners = this.questionListeners.get(sessionId) ?? new Set()
    listeners.add(listener)
    this.questionListeners.set(sessionId, listeners)
    return () => { listeners.delete(listener); if (!listeners.size) this.questionListeners.delete(sessionId) }
  }

  private changed(sessionId: string): void {
    this.revision++
    for (const listener of this.questionListeners.get(sessionId) ?? []) listener()
  }

  answerQuestion(sessionId: string, id: string, answer: AskUserQuestionAnswer) {
    const pending = this.pending.get(id)
    if (!pending || pending.view.kind !== 'question' || pending.view.session_id !== sessionId) throw new ProbeError('interaction.stale')
    return this.answer(id, answer)
  }

  answer(id: string, answer: Answer) {
    const item = this.pending.get(id)
    if (item === undefined) throw new ProbeError('interaction.stale')
    if (Date.now() >= Date.parse(item.view.expires_at)) { item.finish(); throw new ProbeError('interaction.stale') }
    if ((item.view.kind === 'approval') !== ('decision' in answer)) throw new ProbeError('interaction.invalid_answer')
    if ('answers' in answer) this.validateAnswer(item.view.detail, answer)
    item.finish(answer)
    return { accepted: true }
  }

  private validateAnswer(detail: unknown, answer: AskUserQuestionAnswer): void {
    const { questions } = detail as { questions: AskUserQuestionRequest['questions'] }
    const ids = new Set(answer.answers.map(item => item.id))
    if (ids.size !== questions.length || answer.answers.length !== questions.length) throw new ProbeError('interaction.invalid_answer')
    for (const question of questions) {
      const value = answer.answers.find(item => item.id === question.id)
      if (value === undefined || new Set(value.selected).size !== value.selected.length
        || (!question.multiSelect && value.selected.length > 1)
        || value.selected.some(label => !question.options?.some(option => option.label === label))
        || (value.selected.length === 0 && !value.custom?.trim())) throw new ProbeError('interaction.invalid_answer')
    }
  }

  invalidate(sessionId: string): void {
    for (const item of this.pending.values()) if (item.view.session_id === sessionId) item.finish()
  }
  close(): void {
    this.closed = true
    for (const item of this.pending.values()) item.finish()
    this.approved.clear()
    this.executions.clear()
    this.questionListeners.clear()
  }
}
