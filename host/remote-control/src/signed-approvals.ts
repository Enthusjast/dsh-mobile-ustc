import { createHash, createPublicKey, randomBytes, randomUUID } from 'node:crypto'
import { realpathSync } from 'node:fs'
import { isAbsolute, relative, sep } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type { ToolDefinition, ToolExecution } from '@deepseek-ai/dsh-tools'
import type { ApprovalOutcome } from '@deepseek-ai/dsh-user-approval'
import type {} from '@deepseek-ai/dsh-working-directory'
import { z } from 'zod'
import { ApprovalContext, approvalBinding, type ApprovalDecision } from './approval-contract.js'
import { ApprovalAuthorityRevokedError, ApprovalLeaseCache, TrustedApprovalAuthority, type ApprovalLeaseConnection } from './approval-lease.js'
import type { ApprovalInvalidation } from './approval-protocol.js'
import type { PersistentApprovalJournal } from './approval-journal.js'
import { canonicalObject } from './canonical.js'
import { mobileSessionId, type Workspace } from './dsh-client.js'
import { fenceExecutionSignal, fenceToolDefinition, type DefinitionExecutionFence, type ExecutionSignalFence } from './execution-fence.js'

const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
const configShape = z.strictObject({ hostId: uuid, installationId: uuid, policyVersion: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  requiredAssurance: ApprovalContext.shape.required_assurance, authorities: z.array(TrustedApprovalAuthority).min(1).max(8) })
const unavailable = () => new Error('approval: signed native approval unavailable')
type Execution = Readonly<ToolExecution>

/** Trusted process integration, never settings received from a mobile peer. */
export interface SignedApprovalOptions {
  hostId: string
  installationId: string
  policyVersion: number
  requiredAssurance: ApprovalContext['required_assurance']
  authorities: TrustedApprovalAuthority[]
  /** Default: every managed invocation. Exceptions must use the current capability policy. */
  requiresApproval?(execution: Execution): boolean
  /** Pure synchronous live version/ownership facts; required for composite run_code support. */
  resourceFacts?(execution: Execution): ApprovalContext['resources']
  /** Omit to use the native WorkingDirectory service, never the immutable header cwd. */
  workingDirectory?(execution: Execution): string
}

export interface NativeApprovalSession {
  details(approvalId: string): ApprovalContext
  decide(approvalId: string, decisionJWS: string, authorizationJWS: string): Promise<void>
  invalidate(event: ApprovalInvalidation): void
  close(): void
}
interface Connection {
  identity: ApprovalLeaseConnection
  cache: ApprovalLeaseCache
  publish(context: ApprovalContext, signal: AbortSignal): Promise<void>
  closed: boolean
}
interface Invocation {
  execution: Execution
  key: string
  identity: Pick<Execution, 'token' | 'agent' | 'callId' | 'rootCallId' | 'parent' | 'name'>
  context: ApprovalContext
  definition: ToolDefinition
  fence: DefinitionExecutionFence
  connection: Connection
  controller: AbortController
  response: Promise<ApprovalOutcome>
  resolve(outcome: ApprovalOutcome): void
  responseSent: boolean
  phase: 'waiting' | 'approved' | 'consumed' | 'ended'
  nativeOwned: boolean
  nativeSettled: boolean
  timer: NodeJS.Timeout
  onAbort(): void
  caller: AbortSignal
  signal?: ExecutionSignalFence
  decision?: ApprovalDecision
}

/** Current-process terminal answerer plus a durable, actual-body execution fence. */
export class SignedApprovals {
  private readonly options: z.infer<typeof configShape>
  private readonly active = new Map<symbol, Invocation>()
  private readonly byExecution = new WeakMap<object, Invocation>()
  private readonly byCall = new Map<string, Invocation>()
  private readonly byID = new Map<string, Invocation>()
  private readonly listeners = new Set<() => void>()
  private connection: Connection | undefined
  private closed = false
  private notificationQueued = false
  private readonly timeout: number

  constructor(private readonly ctx: Context, readonly runtimeId: string, readonly epoch: string, readonly journal: PersistentApprovalJournal,
    private readonly workspaces: readonly Workspace[], private readonly managed: (agent: Agent | undefined) => boolean, timeoutMs: number, private readonly integration: SignedApprovalOptions) {
    this.options = configShape.parse({ hostId: integration.hostId, installationId: integration.installationId, policyVersion: integration.policyVersion,
      requiredAssurance: integration.requiredAssurance, authorities: integration.authorities })
    this.integration = { ...integration, requiredAssurance:this.options.requiredAssurance, authorities:this.options.authorities }
    this.workspaces = workspaces.map(workspace => ({ ...workspace }))
    if (!uuid.safeParse(runtimeId).success || !uuid.safeParse(epoch).success || journal.runtimeId !== runtimeId || journal.epoch !== epoch ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || !workspaces.length || new Set(workspaces.map(item => item.cwd)).size !== workspaces.length ||
      new Set(workspaces.map(item => item.remoteId)).size !== workspaces.length || workspaces.some(item => !item.remoteId || !uuid.safeParse(item.remoteId).success || !isAbsolute(item.cwd)) ||
      (!integration.workingDirectory && !ctx.get('workingDirectory'))) throw unavailable()
    this.timeout = Math.min(timeoutMs, 180_000)
    if (!this.options.authorities.some(key => key.active && Date.parse(key.valid_from) <= Date.now() && Date.parse(key.valid_until) > Date.now())) throw unavailable()
    for (const key of this.options.authorities) {
      createPublicKey({ format: 'jwk', key: key.public_jwk })
      if (createHash('sha256').update(canonicalObject(key.public_jwk)).digest('base64url') !== key.key_jkt) throw unavailable()
    }
    ctx.on('tools/pre-execute', async (execution, next) => {
      if (!this.protected(execution)) return next()
      const previous = await next()
      if (previous.kind === 'deny' || previous.kind === 'cancel') return previous
      let invocation: Invocation | undefined
      try {
        invocation = this.prepare(execution)
        const current = invocation
        const native = ctx.approval.request({ agent: execution.agent!, toolName: execution.name, callId: execution.callId, signal: current.controller.signal,
          ...(previous.kind === 'ask' && previous.reason !== undefined ? { reason: previous.reason } : {}) }).catch((): ApprovalOutcome => 'unavailable').then(outcome => {
          current.nativeSettled = true
          if (outcome !== 'allowed-once') this.end(current, outcome)
          return outcome
        })
        void current.connection.publish(structuredClone(current.context), current.controller.signal).catch(() => this.end(current, 'unavailable'))
        const decision = await current.response
        if (decision !== 'allowed-once' && !current.nativeOwned && !current.nativeSettled) current.controller.abort()
        const outcome = await native
        if (decision !== 'allowed-once' || outcome !== 'allowed-once' || current.phase !== 'approved') return { kind: 'deny', reason: 'signed approval unavailable' }
        return { kind: 'allow' }
      } catch { if (invocation) this.end(invocation, 'unavailable'); return { kind: 'deny', reason: 'signed approval unavailable' } }
      finally { if (invocation) this.byCall.delete(invocation.key) }
    }, { prepend: true })
    ctx.on('approval/request', (request, next) => {
      if (!this.managed(request.agent)) return next()
      const invocation = request.callId === undefined ? undefined : this.byCall.get(JSON.stringify([request.agent.id, request.callId]))
      if (!invocation || invocation.execution.agent !== request.agent || request.toolName !== invocation.execution.name || this.closed) return Promise.resolve('unavailable')
      invocation.nativeOwned = true
      return invocation.response
    }, { prepend: true })
    ctx.tools.guard(execution => {
      const invocation = this.byExecution.get(execution)
      if (!invocation && !this.protected(execution)) return
      if (!invocation || !this.valid(invocation, execution.arguments)) return 'signed approval missing or invalid'
      try { invocation.signal = fenceExecutionSignal(execution, () => this.valid(invocation, execution.arguments)) }
      catch { this.end(invocation, 'unavailable'); return 'unsupported native execution boundary' }
    })
    ctx.on('tools/result', (execution, result) => {
      const invocation = this.byExecution.get(execution)
      if (!invocation) return
      try {
        const status = journal.get(invocation.context.approval_id).status
        if (status.state === 'consumed') journal.settle(invocation.context.approval_id, result.isError ? (execution.signal.aborted ? 'cancelled' : 'failed') : 'succeeded')
        else if (status.state === 'pending' || status.state === 'approved') journal.invalidate(invocation.context.approval_id)
      } catch { /* A recorded spent permit stays unknown if final storage fails. */ }
      this.retire(invocation)
      this.changed()
    })
    ctx.on('agent/disposed', ({ agent }) => { for (const invocation of this.active.values()) if (invocation.identity.agent === agent) this.end(invocation, 'cancelled') }, { global: true })
    ctx.effect(() => () => this.close(), 'remote-control.signed-approvals')
  }

  watchReports(listener: () => void): () => void { this.listeners.add(listener); return () => { this.listeners.delete(listener) } }
  get identity(): Omit<ApprovalLeaseConnection, 'connection_id'> { return { host_id:this.options.hostId,installation_id:this.options.installationId,runtime_id:this.runtimeId,runtime_epoch:this.epoch } }
  private changed(): void {
    if (this.notificationQueued) return
    this.notificationQueued = true
    queueMicrotask(() => { this.notificationQueued = false; for (const listener of this.listeners) { try { listener() } catch {} } })
  }
  private protected(execution: Execution): boolean {
    if (execution.agent && !this.managed(execution.agent)) return false
    try { return this.integration.requiresApproval ? this.integration.requiresApproval(execution) !== false : true } catch { return true }
  }
  private callKey(execution: Execution): string { return JSON.stringify([execution.agent?.id, execution.callId]) }

  private facts(execution: Execution, definition: ToolDefinition, fence: DefinitionExecutionFence): Pick<ApprovalContext, 'workspace' | 'resources'> {
    const agent = execution.agent
    if (!agent || agent.session.header.parentSession !== undefined || this.ctx.tools.get(execution.name, agent) !== definition || definition.execute !== fence.execute) throw unavailable()
    if (this.integration.requiresApproval && typeof this.integration.requiresApproval(execution) !== 'boolean') throw unavailable()
    if (execution.name === 'run_code' && !this.integration.resourceFacts) throw unavailable()
    const workspace = this.workspaces.find(item => item.cwd === agent.session.header.cwd)
    if (!workspace?.remoteId) throw unavailable()
    const root = realpathSync(workspace.cwd)
    const nativeDirectory = this.integration.workingDirectory ? this.integration.workingDirectory(execution) : this.ctx.workingDirectory.get(agent.session)
    if (typeof nativeDirectory !== 'string' || !isAbsolute(nativeDirectory)) throw unavailable()
    const directory = realpathSync(nativeDirectory), path = relative(root, directory)
    if (isAbsolute(path) || path === '..' || path.startsWith(`..${sep}`)) throw unavailable()
    const hash = (value: unknown) => createHash('sha256').update(canonicalObject(value)).digest('hex')
    const schema = this.ctx.tools.schemas(agent).find(item => item.name === execution.name)
    if (!schema) throw unavailable()
    return { workspace: { workspace_id: workspace.remoteId, root_sha256: hash({ root }) }, resources: [
      { kind: 'artifact', resource_id: `dsh/execution-directory/v1:${path.split(sep).join('/') || '.'}`, version_sha256: hash({ root, directory }) },
      { kind: 'artifact', resource_id: `dsh/tool-definition/v1:${execution.name}`, version_sha256: hash({ definition: fence.version, schema }) },
      ...(this.integration.resourceFacts ? this.integration.resourceFacts(execution) : []),
    ] }
  }

  private prepare(execution: Execution): Invocation {
    const connection = this.connection
    if (this.closed || !connection || connection.closed || execution.signal.aborted || !execution.agent || !this.managed(execution.agent) || this.active.size >= 64) throw unavailable()
    const key = this.callKey(execution)
    if (this.byCall.has(key)) throw unavailable()
    const definition = this.ctx.tools.get(execution.name, execution.agent)
    if (!definition) throw unavailable()
    const fence = fenceToolDefinition(definition), facts = this.facts(execution, definition, fence), now = Date.now()
    const context = approvalBinding({ domain: 'dsh-mobile-ustc/approval-context/v1', protocol_version: 1, host_id: this.options.hostId, installation_id: this.options.installationId,
      runtime_id: this.runtimeId, runtime_epoch: this.epoch, session_id: mobileSessionId(this.runtimeId, execution.agent.id), dsh_session_id: String(execution.agent.id),
      approval_id: randomUUID(), execution_id: randomUUID(), call_id: String(execution.callId), tool: execution.name, arguments: structuredClone(execution.arguments), ...facts,
      nonce: randomBytes(32).toString('base64url'), policy_version: this.options.policyVersion, required_assurance: this.options.requiredAssurance,
      created_at: new Date(now).toISOString(), expires_at: new Date(now + this.timeout).toISOString() }).context
    this.journal.register(context)
    let resolve!: (value: ApprovalOutcome) => void
    const response = new Promise<ApprovalOutcome>(done => { resolve = done })
    const invocation: Invocation = { execution, key, identity:{ token:execution.token,agent:execution.agent,callId:execution.callId,rootCallId:execution.rootCallId,name:execution.name,...(execution.parent?{parent:execution.parent}:{}) },
      context, definition, fence, connection, controller: new AbortController(), response, resolve, responseSent: false,
      phase: 'waiting', nativeOwned: false, nativeSettled: false, caller: execution.signal, timer: setTimeout(() => this.end(invocation, 'cancelled'), this.timeout),
      onAbort: () => this.end(invocation, 'cancelled') }
    invocation.timer.unref()
    this.active.set(execution.token, invocation); this.byExecution.set(execution,invocation); this.byCall.set(key, invocation); this.byID.set(context.approval_id, invocation)
    fence.arm(execution, (args, actual) => {
      if (actual !== execution || !this.valid(invocation, args) || !invocation.signal || !invocation.decision) throw unavailable()
      this.journal.consume(context.approval_id, { ...context, arguments: args, ...this.facts(actual, definition, fence) }, (request, decision) => connection.cache.authorization(request, decision))
      invocation.signal.enterBody(); invocation.phase = 'consumed'; clearTimeout(invocation.timer)
      this.changed()
    })
    execution.signal.addEventListener('abort', invocation.onAbort, { once: true })
    if (execution.signal.aborted) this.end(invocation, 'cancelled')
    return invocation
  }

  private valid(invocation: Invocation, args: unknown): boolean {
    try {
      if (this.closed || this.connection !== invocation.connection || invocation.connection.closed || invocation.controller.signal.aborted || invocation.phase !== 'approved' || !invocation.decision || invocation.caller.aborted) return false
      for (const field of ['token','agent','callId','rootCallId','parent','name'] as const) if (invocation.execution[field] !== invocation.identity[field]) return false
      if (!invocation.execution.agent || String(invocation.execution.agent.id) !== invocation.context.dsh_session_id ||
        mobileSessionId(this.runtimeId,invocation.execution.agent.id) !== invocation.context.session_id || String(invocation.execution.callId) !== invocation.context.call_id ||
        invocation.execution.name !== invocation.context.tool) return false
      const actual = approvalBinding({ ...invocation.context, arguments: args, ...this.facts(invocation.execution, invocation.definition, invocation.fence) })
      if (actual.sha256 !== approvalBinding(invocation.context).sha256 || this.journal.get(invocation.context.approval_id).status.state !== 'approved') return false
      return invocation.connection.cache.authorization(invocation.context, invocation.decision) !== undefined &&
        this.ctx.tools.get(invocation.execution.name,invocation.execution.agent) === invocation.definition && invocation.definition.execute === invocation.fence.execute
    } catch { return false }
  }

  attach(identity: ApprovalLeaseConnection, publish: Connection['publish']): NativeApprovalSession {
    if (this.closed || identity.host_id !== this.options.hostId || identity.installation_id !== this.options.installationId || identity.runtime_id !== this.runtimeId || identity.runtime_epoch !== this.epoch) throw unavailable()
    if (this.connection) this.detach(this.connection)
    const connection: Connection = { identity, cache: new ApprovalLeaseCache(identity, this.options.authorities), publish, closed: false }
    this.connection = connection
    return {
      details: id => {
        if (this.connection !== connection || connection.closed) throw unavailable()
        const { context } = this.journal.get(id)
        if (context.runtime_epoch !== this.epoch || context.host_id !== this.options.hostId || context.installation_id !== this.options.installationId) throw unavailable()
        this.journal.confirmRegistration({ approval_id: id, runtime_id: this.runtimeId, runtime_epoch: this.epoch, session_id: context.session_id, execution_id: context.execution_id,
          binding_sha256: approvalBinding(context).sha256, state: 'pending', expires_at: context.expires_at })
        this.changed()
        return context
      },
      decide: async (id, decisionJWS, leaseJWS) => {
        const invocation = this.byID.get(id)
        if (!invocation || invocation.connection !== connection || this.connection !== connection || connection.closed || !['waiting', 'approved'].includes(invocation.phase)) throw unavailable()
        let key
        try { key = await connection.cache.admit(invocation.context, decisionJWS, leaseJWS) }
        catch (error) { if (error instanceof ApprovalAuthorityRevokedError) this.end(invocation,'unavailable'); throw error }
        const decision = connection.cache.decision(invocation.context)
        if (!decision) throw unavailable()
        const status = await this.journal.decide(id, decisionJWS, key, (request, claims) => this.connection === connection && !connection.closed ? connection.cache.authorization(request, claims) : undefined)
        if (this.connection !== connection || connection.closed || invocation.phase === 'ended') throw unavailable()
        invocation.decision = decision
        if (status.state === 'approved') {
          const authorization = connection.cache.authorization(invocation.context, decision)
          if (!authorization) { this.end(invocation, 'unavailable'); throw unavailable() }
          invocation.phase = 'approved'; clearTimeout(invocation.timer)
          invocation.timer = setTimeout(() => this.end(invocation, 'cancelled'), Math.max(1, Math.min(Date.parse(authorization.expires_at), Date.parse(invocation.context.expires_at), Date.parse(decision.expires_at)) - Date.now()))
          invocation.timer.unref()
          this.resolve(invocation, 'allowed-once')
        } else this.resolve(invocation, 'rejected')
        this.changed()
      },
      invalidate: event => {
        if (this.connection !== connection || connection.closed || event.connection_id !== connection.identity.connection_id) throw unavailable()
        const ids = event.kind === 'device.revoked' ? connection.cache.invalidateDevice(event.device_id) : connection.cache.invalidateGrant(event.user_id,event.grant_version)
        for (const id of ids) { const invocation = this.byID.get(id); if (invocation?.connection === connection && invocation.phase !== 'consumed') this.end(invocation,'unavailable') }
      },
      close: () => this.detach(connection),
    }
  }

  private resolve(invocation: Invocation, outcome: ApprovalOutcome): void {
    if (!invocation.responseSent) { invocation.responseSent = true; invocation.resolve(outcome) }
  }
  private end(invocation: Invocation, outcome: ApprovalOutcome): void {
    if (invocation.phase === 'consumed' || invocation.phase === 'ended') return
    try { const state = this.journal.get(invocation.context.approval_id).status.state; if (state === 'pending' || state === 'approved') this.journal.invalidate(invocation.context.approval_id, outcome === 'cancelled' ? 'cancelled' : 'invalidated') } catch {}
    invocation.phase = 'ended'; invocation.fence.block(invocation.execution); invocation.signal?.cancel(); clearTimeout(invocation.timer)
    invocation.controller.abort(); this.resolve(invocation, outcome); this.changed()
  }
  private retire(invocation: Invocation): void {
    invocation.fence.block(invocation.execution); invocation.signal?.release(); clearTimeout(invocation.timer)
    invocation.caller.removeEventListener('abort', invocation.onAbort)
    this.active.delete(invocation.identity.token); this.byID.delete(invocation.context.approval_id); this.byCall.delete(invocation.key)
    this.byExecution.delete(invocation.execution)
  }
  private detach(connection: Connection): void {
    connection.closed = true; connection.cache.close()
    if (this.connection === connection) this.connection = undefined
    for (const invocation of this.active.values()) if (invocation.connection === connection && invocation.phase !== 'consumed') this.end(invocation, 'unavailable')
  }
  close(): void {
    if (this.closed) return
    this.closed = true
    if (this.connection) this.detach(this.connection)
    for (const invocation of this.active.values()) {
      this.end(invocation, 'unavailable')
      if (invocation.phase === 'consumed') { try { this.journal.invalidate(invocation.context.approval_id) } catch {} }
      this.retire(invocation)
    }
    this.listeners.clear()
  }
}
