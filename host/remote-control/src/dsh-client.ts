import { createHash } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { SessionId } from '@deepseek-ai/dsh-session'
import type { SessionController } from '@deepseek-ai/dsh-api-session-controller'
import type { SessionFollowFrame, SessionPageRequest } from '@deepseek-ai/dsh-api-session-controller/types'
import { ProbeError } from './protocol.js'

export interface Workspace { id: string; cwd: string }

/** Stable UUIDv5 mapping; DSH identities remain opaque and never enter request routing. */
export function mobileSessionId(runtimeId: string, nativeId: string): string {
  const namespace = Buffer.from(runtimeId.replaceAll('-', ''), 'hex')
  const bytes = createHash('sha1').update(namespace).update(nativeId, 'utf8').digest().subarray(0, 16)
  bytes[6] = (bytes[6]! & 0x0f) | 0x50
  bytes[8] = (bytes[8]! & 0x3f) | 0x80
  const hex = bytes.toString('hex')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

/** Calls the services in the current process; creates no SDK child or second writer. */
export class DshClient {
  private ids = new Map<string, string>()
  constructor(
    private readonly ctx: Context,
    readonly runtimeId: string,
    private readonly workspaces: readonly Workspace[],
    private readonly presets: readonly string[],
  ) {}

  private get controller(): SessionController { return this.ctx.sessionController }

  async list(signal: AbortSignal) {
    const { items } = await this.controller.list({}, signal)
    const allowed = items.filter(item => item.cwd !== undefined && this.workspaces.some(w => w.cwd === item.cwd))
    // Child sessions require a verified parent address and cannot be independently taken over.
    const roots = []
    const ids = new Map<string, string>()
    for (const item of allowed) {
      const inspection = await this.controller.inspect(item.sessionId, signal)
      if (inspection.meta.parentSession !== undefined || inspection.meta.origin === 'subagent') continue
      const id = mobileSessionId(this.runtimeId, item.sessionId)
      ids.set(id, item.sessionId)
      roots.push({ session_id: id, running: item.running, agent_available: item.agentAvailable, updated_at: item.updatedAt })
    }
    this.ids = ids
    return { items: roots }
  }

  async resolve(id: string, signal: AbortSignal): Promise<SessionId> {
    // Refresh every operation so a prior list cannot keep a removed resource accessible.
    await this.list(signal)
    const nativeId = this.ids.get(id)
    if (nativeId === undefined) throw new ProbeError('session.not_found')
    return SessionId(nativeId)
  }

  async create(workspace: string, preset: string) {
    const allowed = this.workspaces.find(item => item.id === workspace)
    if (allowed === undefined || !this.presets.includes(preset)) throw new ProbeError('access.denied')
    const result = await this.controller.create({ cwd: allowed.cwd, agentPreset: preset })
    return { session_id: mobileSessionId(this.runtimeId, result.sessionId) }
  }

  async modelCatalog() {
    const catalog = await this.controller.modelCatalog()
    return {
      default: catalog.default,
      groups: catalog.groups.map(group => ({
        id: group.id, name: group.name,
        models: group.models.map(model => ({
          id: model.id, name: model.name,
          ...(model.description === undefined ? {} : { description: model.description }),
          ...(model.reasoning === undefined ? {} : { reasoning: model.reasoning }),
        })),
      })),
    }
  }

  async selectModel(id: SessionId, selection: { provider: string; model: string; reasoning_effort?: string }) {
    const catalog = await this.controller.modelCatalog()
    const model = catalog.groups.find(group => group.id === selection.provider)?.models.find(item => item.id === selection.model)
    if (model === undefined || (selection.reasoning_effort !== undefined
      && !model.reasoning?.efforts.some(item => item.id === selection.reasoning_effort))) throw new ProbeError('model.not_available')
    return this.controller.selectModel({
      sessionId: id, provider: selection.provider, model: selection.model,
      ...(selection.reasoning_effort === undefined ? {} : { reasoningEffort: selection.reasoning_effort }),
    })
  }

  async prompt(id: SessionId, requestId: string, mode: 'queue' | 'steer', text: string, signal: AbortSignal) {
    // Native requestId is namespaced away from other desktop/remote input channels.
    await this.controller.prompt({ sessionId: id, requestId: `m0:${requestId}` as never, mode, content: [{ type: 'text', text }] }, signal)
    const checkpoint = await this.checkpoint(id)
    return { native_accepted: true, checkpoint }
  }

  cancel(id: SessionId) { return this.controller.cancel({ sessionId: id }) }

  follow(id: SessionId, maxMessages: number, signal: AbortSignal): AsyncIterable<SessionFollowFrame> {
    return this.controller.follow({ address: { kind: 'session', sessionId: id }, maxMessages, assistantStream: true }, signal)
  }

  page(id: SessionId, request: Omit<SessionPageRequest, 'address'>, signal: AbortSignal) {
    return this.controller.page({ ...request, address: { kind: 'session', sessionId: id } }, signal)
  }

  async checkpoint(id: SessionId): Promise<{ state: 'persisted'; through_seq: number } | { state: 'unavailable' | 'failed' }> {
    const session = this.ctx.sessions.get(id)
    if (session === undefined) return { state: 'unavailable' }
    const through = session.seq - 1
    try {
      return await this.ctx.sessions.flush(session) ? { state: 'persisted', through_seq: through } : { state: 'unavailable' }
    } catch { return { state: 'failed' } }
  }
}
