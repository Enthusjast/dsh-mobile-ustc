import { createHash } from 'node:crypto'
import { symbols, type Context } from '@deepseek-ai/cordis'
import { SessionId } from '@deepseek-ai/dsh-session'
import type { SessionController } from '@deepseek-ai/dsh-api-session-controller'
import type { SessionFollowFrame, SessionPageRequest } from '@deepseek-ai/dsh-api-session-controller/types'
import type { PromptContentPart } from '@deepseek-ai/dsh-api-session-controller/types'
import type { FileUploadReceiptId } from '@deepseek-ai/dsh-client-file-upload'
import { WorkspaceActiveSessionError, workspaceDomainSpec, workspaceDomainState } from '@deepseek-ai/dsh-workspace'
import { ProbeError } from './protocol.js'
import { configuredCreationOptions } from './creation-options.js'
import { admitNativeFile, fileManifest, releaseNativeFile, type FileManifest } from './file-admission.js'
import { PinnedExportSource } from './file-export-source.js'
import { sessionAttachmentSource,sessionAttachmentManifest } from './session-file-export.js'
import { ExportDirectory } from './export-directory.js'
import { LocalFileSystem } from '@deepseek-ai/dsh-fs-local'
import { SandboxedFileSystem } from '@deepseek-ai/dsh-fs-sandbox'
import { NativeObservations } from './native-observations.js'

export type DshPromptPart = Extract<PromptContentPart, { type: 'text' | 'file' }>

export interface WorkspaceExportRoot { id: string; directory: string }
export interface AttachmentExportCursor { through:number;before:number;skipSeq?:number;skipIndex?:number }
export interface Workspace { id: string; cwd: string; remoteId?: string; label?: string; exportRoots?: WorkspaceExportRoot[] }

export interface SessionCatalogItem {
  session_id: string
  dsh_session_id: string
  workspace_id: string | null
  state: 'available' | 'running' | 'archived' | 'unavailable'
  last_persisted_seq: number
}
export type SessionCatalogChange = { kind: 'snapshot' } | { kind: 'delta'; sessionIds: readonly string[] }

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
    readonly observations = new NativeObservations(),
  ) {
    for (const workspace of workspaces) {
      const roots = workspace.exportRoots ?? []
      if (roots.length > 8 || new Set(roots.map(root => root.id)).size !== roots.length || roots.some(root =>
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(root.id) || typeof root.directory !== 'string' ||
        root.directory !== '.' && (root.directory.split('/').length > 16 || root.directory.split('/').some(part => !fileManifest.shape.name.safeParse(part).success)))) throw new ProbeError('file.export_invalid')
    }
  }

  private get controller(): SessionController { return this.ctx.sessionController }
  creationOptions() { return configuredCreationOptions(this.workspaces, this.presets) }

  async list(signal: AbortSignal) {
    signal.throwIfAborted()
    const { items } = await this.controller.list({}, signal)
    signal.throwIfAborted()
    const allowed = items.filter(item => item.cwd !== undefined && this.workspaces.some(w => w.cwd === item.cwd))
    // Child sessions require a verified parent address and cannot be independently taken over.
    const roots = []
    const ids = new Map<string, string>()
    for (const item of allowed) {
      const inspection = await this.controller.inspect(item.sessionId, signal)
      signal.throwIfAborted()
      if (inspection.meta.parentSession !== undefined || inspection.meta.origin === 'subagent') continue
      const id = mobileSessionId(this.runtimeId, item.sessionId)
      ids.set(id, item.sessionId)
      roots.push({ session_id: id, running: item.running, archived: this.isArchived(item.sessionId), agent_available: item.agentAvailable, updated_at: item.updatedAt })
    }
    this.ids = ids
    return { items: roots }
  }

  async sessionCatalog(signal: AbortSignal, sessionIds?: readonly string[]): Promise<SessionCatalogItem[]> {
    const { items } = await this.controller.list({}, signal)
    const requested = sessionIds === undefined ? undefined : new Set(sessionIds)
    const catalog: SessionCatalogItem[] = []
    const ids = new Map<string, string>()
    const found = new Set<string>()
    const tombstone = (nativeId: string) => ({
      session_id: mobileSessionId(this.runtimeId, nativeId), dsh_session_id: nativeId,
      workspace_id: null, state: 'unavailable' as const, last_persisted_seq: -1,
    })
    for (const item of items) {
      signal.throwIfAborted()
      const nativeId = String(item.sessionId)
      if (requested && !requested.has(nativeId)) continue
      found.add(nativeId)
      const workspace = this.workspaces.find(candidate => candidate.cwd === item.cwd)
      if (!workspace) {
        if (requested) catalog.push(tombstone(nativeId))
        continue
      }
      const inspection = await this.controller.inspect(item.sessionId, signal)
      if (inspection.meta.parentSession !== undefined || inspection.meta.origin === 'subagent') {
        if (requested) catalog.push(tombstone(nativeId))
        continue
      }
      const sessionId = mobileSessionId(this.runtimeId, nativeId)
      if (workspace?.remoteId !== undefined && !UUID.test(workspace.remoteId)) throw new ProbeError('access.denied')
      const nativeSession = SessionId(nativeId)
      const persisted = this.ctx.sessions.get(nativeSession) === undefined
        ? await this.readColdCursor(nativeSession, signal)
        : await this.checkpoint(nativeSession)
      if (persisted.state !== 'persisted') throw new ProbeError('session.persistence_unavailable')
      ids.set(sessionId, nativeId)
      catalog.push({
        session_id: sessionId,
        dsh_session_id: nativeId,
        workspace_id: workspace?.remoteId ?? null,
        state: this.isArchived(item.sessionId) ? 'archived' : item.running ? 'running' : 'available',
        last_persisted_seq: persisted.through_seq,
      })
    }
    if (requested) {
      for (const nativeId of requested) {
        if (!found.has(nativeId)) catalog.push(tombstone(nativeId))
      }
      for (const item of catalog) {
        if (item.state === 'unavailable') this.ids.delete(item.session_id)
        else this.ids.set(item.session_id, item.dsh_session_id)
      }
    } else this.ids = ids
    return catalog.sort((left, right) => left.session_id.localeCompare(right.session_id))
  }

  watchSessionCatalog(onChange: (change: SessionCatalogChange) => void): () => void {
    let archived = new Set<string>(this.ctx.workspaceRegistry.archivedSessionIds)
    let timer: NodeJS.Timeout | undefined
    let fullSnapshot = false
    const sessionIds = new Set<string>()
    const schedule = (full = false, sessionId?: string) => {
      if (full) {
        fullSnapshot = true
        sessionIds.clear()
      } else if (!fullSnapshot && sessionId) sessionIds.add(String(sessionId))
      // Keep a fixed publication window so continuous activity cannot defer
      // catalog updates indefinitely.
      if (timer) return
      timer = setTimeout(() => {
        timer = undefined
        if (fullSnapshot) onChange({ kind: 'snapshot' })
        else if (sessionIds.size > 0) onChange({ kind: 'delta', sessionIds: [...sessionIds] })
        fullSnapshot = false
        sessionIds.clear()
      }, 200)
      timer.unref()
    }
    const disposers = [
      this.ctx.on('api-session/added', () => schedule(true), { global: true }),
      this.ctx.on('api-session/removed', sessionId => schedule(true, String(sessionId)), { global: true }),
      this.ctx.on('api-session/status', sessionId => schedule(false, String(sessionId)), { global: true }),
      this.ctx.on('api-session/activity', sessionId => schedule(false, String(sessionId)), { global: true }),
      this.ctx.on('domain/changed', change => {
        if (change.domain !== workspaceDomainSpec.name || change.table !== '' || change.operation !== 'put') return
        // The domain emits before the registry updates its own cache. Diff the
        // durable event snapshot, then publish through the existing window.
        const state = workspaceDomainState.parse(change.value)
        const next = new Set<string>(state.archivedSessionIds)
        for (const id of new Set([...archived, ...next])) {
          if (archived.has(id) !== next.has(id)) schedule(false, id)
        }
        archived = next
      }, { global: true }),
    ]
    return () => {
      if (timer) clearTimeout(timer)
      for (const dispose of disposers) dispose()
    }
  }

  async resolve(id: string, signal: AbortSignal): Promise<SessionId> {
    // Refresh every operation so a prior list cannot keep a removed resource accessible.
    await this.list(signal)
    signal.throwIfAborted()
    const nativeId = this.ids.get(id)
    if (nativeId === undefined) throw new ProbeError('session.not_found')
    return SessionId(nativeId)
  }

  private async exportWorkspace(id: string, signal: AbortSignal): Promise<{ native: SessionId; workspace: Workspace }> {
    const native = await this.resolve(id, signal)
    const inspection = await this.controller.inspect(native, signal)
    const matches = this.workspaces.filter(workspace => workspace.cwd === inspection.meta.cwd)
    if (matches.length !== 1 || inspection.meta.parentSession !== undefined || inspection.meta.origin === 'subagent') throw new ProbeError('access.denied')
    return { native, workspace: matches[0]! }
  }

  /** Host-selected artifact under an explicitly configured root; never decode this from a phone path. */
  private async workspaceExportLocation(id: string, rootId: string, parts: readonly string[], signal: AbortSignal, current: () => void) {
    signal.throwIfAborted(); current()
    const { workspace } = await this.exportWorkspace(id, signal)
    const roots = workspace.exportRoots?.filter(root => root.id === rootId) ?? []
    if (roots.length !== 1) throw new ProbeError('access.denied')
    const directory = roots[0]!.directory
    const prefix = directory === '.' ? [] : directory.split('/')
    const cwd = workspace.cwd
    const filesystem = this.ctx.fs
    if (!filesystem) throw new ProbeError('file.export_unsupported')
    const provider = Reflect.get(filesystem, symbols.original) ?? filesystem
    // These pinned native backends share unrestricted read semantics. An
    // unknown execution world or read-policy wrapper needs its own adapter;
    // opening a coincidentally matching Host path would bypass that provider.
    const backend = Object.getPrototypeOf(provider)?.constructor
    if (backend !== LocalFileSystem && backend !== SandboxedFileSystem) throw new ProbeError('file.export_unsupported')
    const guard = () => {
      current()
      const active = this.ctx.fs
      if (!active || (Reflect.get(active, symbols.original) ?? active) !== provider) throw new ProbeError('access.denied')
      const matches = this.workspaces.filter(item => item.cwd === cwd)
      const allowed = matches.length === 1 ? matches[0]!.exportRoots?.filter(root => root.id === rootId && root.directory === directory) : []
      if (allowed?.length !== 1) throw new ProbeError('access.denied')
    }
    return {root:cwd,parts:[...prefix,...parts],guard}
  }
  async workspaceExportSource(id: string, rootId: string, parts: readonly string[], signal: AbortSignal, current: () => void): Promise<PinnedExportSource> {
    const location=await this.workspaceExportLocation(id,rootId,parts,signal,current)
    return PinnedExportSource.open({root:location.root,parts:location.parts},signal,location.guard)
  }
  async workspaceExportRootIds(id:string,signal:AbortSignal,current:()=>void):Promise<string[]> {
    current();signal.throwIfAborted();const {workspace}=await this.exportWorkspace(id,signal);current()
    return (workspace.exportRoots??[]).map(root=>root.id)
  }
  async workspaceExportPage(id:string,root:string,parts:readonly string[],signal:AbortSignal,current:()=>void,reader?:ExportDirectory) {
    const location=await this.workspaceExportLocation(id,root,parts,signal,current)
    if(reader&&!reader.matches(location.root,location.parts))throw new ProbeError('file.export_changed')
    const directory=reader??await ExportDirectory.open(location.root,location.parts,signal,location.guard)
    try {const page=await directory.page(signal,location.guard);return {...page,reader:directory}}
    catch(error){await directory.close();throw error}
  }
  async attachmentExportPage(id:string,signal:AbortSignal,current:()=>void,cursor?:AttachmentExportCursor) {
    current();signal.throwIfAborted();const {native}=await this.exportWorkspace(id,signal)
    let through:number,records:readonly import('@deepseek-ai/dsh-api-session-controller/types').SessionHistoryRecord[],more:boolean
    if(cursor){through=cursor.through;const page=await this.page(native,{throughSeq:through,beforeSeq:cursor.before,maxMessages:10},signal);records=page.records;more=page.hasMore}
    else {
      const iterator=this.follow(native,10,signal)[Symbol.asyncIterator]()
      try {const opening=await iterator.next();if(opening.done||opening.value.type!=='snapshot')throw new ProbeError('file.export_unavailable');through=opening.value.cursor;records=opening.value.records;more=opening.value.hasMore}
      finally {await iterator.return?.()}
      if(this.ctx.sessions.get(native)!==undefined){const saved=await this.checkpoint(native);if(saved.state!=='persisted'||saved.through_seq<through)throw new ProbeError('session.persistence_unavailable')}
    }
    const items:Array<{seq:number;index:number;manifest:FileManifest}>=[]
    for(const {event} of [...records].reverse()) {
      current();signal.throwIfAborted()
      const data=event.data as Record<string,unknown>
      const body=event.type==='user/message'?data:(data?.message as Record<string,unknown>|undefined)
      const content=body?.content
      if(!Array.isArray(content))continue
      for(let index=cursor?.skipSeq===event.seq?cursor.skipIndex??0:0;index<content.length;index++) {
        let manifest:FileManifest
        try {manifest=sessionAttachmentManifest(event,index)}catch{continue}
        items.push({seq:event.seq,index,manifest})
        if(items.length===16)return {items,cursor:{through,before:event.seq+1,skipSeq:event.seq,skipIndex:index+1} satisfies AttachmentExportCursor}
      }
    }
    current();signal.throwIfAborted()
    return {items,cursor:more&&records.length?{through,before:records[0]!.event.seq} satisfies AttachmentExportCursor:undefined}
  }

  /** File/image selection is a log position in this scoped Session, never a caller-supplied native reference. */
  async attachmentExportSource(id: string, seq: number, index: number, signal: AbortSignal, current: () => void): Promise<PinnedExportSource> {
    if (!Number.isSafeInteger(seq) || seq < 0 || seq >= Number.MAX_SAFE_INTEGER || !Number.isSafeInteger(index) || index < 0 || index > 4095) throw new ProbeError('file.export_invalid')
    signal.throwIfAborted(); current()
    const { native, workspace } = await this.exportWorkspace(id, signal)
    const checkpoint = this.ctx.sessions.get(native) === undefined ? await this.readColdCursor(native, signal) : await this.checkpoint(native)
    if (checkpoint.state !== 'persisted' || checkpoint.through_seq < seq) throw new ProbeError('session.persistence_unavailable')
    const page = await this.page(native, { throughSeq: checkpoint.through_seq, beforeSeq: seq + 1, maxMessages: 1 }, signal)
    const event = page.records.find(record => record.event.seq === seq)?.event
    if (event === undefined) throw new ProbeError('file.export_unavailable')
    const cwd = workspace.cwd
    const guard = () => { current(); if (this.workspaces.filter(item => item.cwd === cwd).length !== 1) throw new ProbeError('access.denied') }
    signal.throwIfAborted(); guard()
    return sessionAttachmentSource(this.ctx, event, index, signal, guard)
  }

  async create(workspace: string, preset: string, signal?: AbortSignal) {
    signal?.throwIfAborted()
    const allowed = this.workspaces.find(item => item.id === workspace)
    if (allowed === undefined || !this.presets.includes(preset)) throw new ProbeError('access.denied')
    const result = await this.observations.measure('create', () => this.controller.create({ cwd: allowed.cwd, agentPreset: preset }), undefined, signal)
    const id = SessionId(result.sessionId)
    const mobile = mobileSessionId(this.runtimeId, result.sessionId)
    this.ids.set(mobile, String(id))
    return { session_id: mobile, checkpoint: await this.checkpoint(id) }
  }

  async createRemote(workspaceId: string, preset: string, signal: AbortSignal) {
    const matches = this.workspaces.filter(item => item.remoteId === workspaceId)
    if (matches.length !== 1) throw new ProbeError('access.denied')
    signal.throwIfAborted()
    const result = await this.create(matches[0]!.id, preset, signal)
    if (result.checkpoint.state !== 'persisted') return result
    const nativeId = this.ids.get(result.session_id)
    if (!nativeId) throw new ProbeError('session.not_found')
    const items = await this.sessionCatalog(signal, [nativeId])
    const item = items.find(item => item.session_id === result.session_id && item.workspace_id === workspaceId && item.state !== 'unavailable')
    if (!item) throw new ProbeError('session.persistence_unavailable')
    return { ...result, catalog_item: item }
  }

  async modelCatalog(signal?: AbortSignal) {
    signal?.throwIfAborted()
    const catalog = await this.controller.modelCatalog()
    signal?.throwIfAborted()
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

  async selectModel(id: SessionId, selection: { provider: string; model: string; reasoning_effort?: string }, signal?: AbortSignal) {
    signal?.throwIfAborted()
    this.requireUnarchived(id)
    const catalog = await this.controller.modelCatalog()
    signal?.throwIfAborted()
    this.requireUnarchived(id)
    const model = catalog.groups.find(group => group.id === selection.provider)?.models.find(item => item.id === selection.model)
    if (model === undefined || (selection.reasoning_effort !== undefined
      && !model.reasoning?.efforts.some(item => item.id === selection.reasoning_effort))) throw new ProbeError('model.not_available')
    return this.controller.selectModel({
      sessionId: id, provider: selection.provider, model: selection.model,
      ...(selection.reasoning_effort === undefined ? {} : { reasoningEffort: selection.reasoning_effort }),
    })
  }

  async prompt(
    id: SessionId,
    requestId: string,
    mode: 'queue' | 'steer',
    content: string | readonly DshPromptPart[],
    signal: AbortSignal,
  ) {
    signal.throwIfAborted()
    this.requireUnarchived(id)
    // Native requestId is namespaced away from other desktop/remote input channels.
    const blocks = typeof content === 'string' ? [{ type: 'text' as const, text: content }] : content
    await this.observations.measure('prompt', () => this.controller.prompt({ sessionId: id, requestId: `m0:${requestId}` as never, mode, content: [...blocks] }, signal), undefined, signal)
    const checkpoint = await this.checkpoint(id)
    return { native_accepted: true, checkpoint }
  }

  /** Inspect native request evidence and flush its existing state; never admit a prompt. */
  async reconcilePrompt(id: SessionId, requestId: string, signal: AbortSignal) {
    return this.observations.measure('prompt_reconcile', () => this.reconcilePromptObserved(id, requestId, signal), undefined, signal)
  }

  private async reconcilePromptObserved(id: SessionId, requestId: string, signal: AbortSignal) {
    signal.throwIfAborted()
    const resolved = await this.controller.resolveAgent(id)
    signal.throwIfAborted()
    if (!('agent' in resolved)) throw new ProbeError('command.outcome_unknown')
    const agent = resolved.agent
    if (this.ctx.agents.get(id) !== agent) throw new ProbeError('command.outcome_unknown')
    const rpcId = `m0:${requestId}`
    const matches = (source: { kind: string }) => source.kind === 'user' && 'rpcId' in source && source.rpcId === rpcId
    const known = agent.inbox.nextTurn.some(message => matches(message.source)) || agent.inbox.nextStep.some(message => matches(message.source))
      || agent.session.snapshotEvents().some(event => event.type === 'user/message' && matches(event.data.source))
    if (!known) throw new ProbeError('command.outcome_unknown')
    const checkpoint = await this.checkpoint(id)
    signal.throwIfAborted()
    if (this.ctx.agents.get(id) !== agent) throw new ProbeError('command.outcome_unknown')
    return { native_accepted: true, checkpoint }
  }

  cancel(id: SessionId, signal?: AbortSignal) {
    signal?.throwIfAborted()
    return this.controller.cancel({ sessionId: id })
  }

  async uploadFile(sessionId: string, manifest: FileManifest, source: AsyncIterable<Uint8Array>, signal: AbortSignal) {
    try {
      if (signal.aborted) throw new ProbeError('file.cancelled')
      const native = await this.resolve(sessionId, signal)
      return await admitNativeFile(this.ctx, native, manifest, source, signal, () => this.requireUnarchived(native))
    } catch (error) {
      if (signal.aborted) throw new ProbeError('file.cancelled')
      throw error
    }
  }

  releaseFile(id: SessionId, receiptId: FileUploadReceiptId): boolean { return releaseNativeFile(this.ctx, id, receiptId) }

  fileStaged(id: SessionId, receiptId: FileUploadReceiptId): boolean {
    const agent = this.ctx.agents.get(id)
    return agent !== undefined && this.ctx.fileUploads.resolve(agent, receiptId) !== undefined
  }

  private isArchived(id: SessionId): boolean { return this.ctx.workspaceRegistry.archivedSessionIds.includes(id) }

  private requireUnarchived(id: SessionId): void {
    if (this.isArchived(id)) throw new ProbeError('session.archived')
  }

  async archive(id: SessionId, archived: boolean, stopActivity: boolean, signal?: AbortSignal) {
    signal?.throwIfAborted()
    if (!archived && stopActivity) throw new ProbeError('protocol.invalid')
    try {
      // The running DSH can load its own copy of the workspace package.
      // In that case its active-session error has a different class identity.
      // An activity check before calling archive gives a definite rejection
      // without classifying arbitrary post-write errors by their shape.
      if (archived && !stopActivity && !this.isArchived(id)) {
        const activity = await this.ctx.waterfall('workspace/session-activity', { sessionId: id }, () => Promise.resolve([]))
        signal?.throwIfAborted()
        if (activity.length > 0) throw new ProbeError('session.active')
      }
      signal?.throwIfAborted()
      if (archived) await this.ctx.workspaceRegistry.archiveSession(id, { stopActivity })
      else await this.ctx.workspaceRegistry.unarchiveSession(id)
    } catch (error) {
      if (error instanceof WorkspaceActiveSessionError) throw new ProbeError('session.active')
      throw error
    }
    // This is a workspace-domain durability barrier. Session-log flush and
    // activity settlement are separate operations and are not implied here.
    return { archived }
  }

  follow(id: SessionId, maxMessages: number, signal: AbortSignal): AsyncIterable<SessionFollowFrame> {
    return this.controller.follow({ address: { kind: 'session', sessionId: id }, maxMessages, assistantStream: true }, signal)
  }

  page(id: SessionId, request: Omit<SessionPageRequest, 'address'>, signal: AbortSignal) {
    return this.controller.page({ ...request, address: { kind: 'session', sessionId: id } }, signal)
  }

  async checkpoint(id: SessionId): Promise<{ state: 'persisted'; through_seq: number } | { state: 'unavailable' | 'failed' }> {
    return this.observations.measure('checkpoint', () => this.checkpointObserved(id), value => value.state)
  }

  private async checkpointObserved(id: SessionId): Promise<{ state: 'persisted'; through_seq: number } | { state: 'unavailable' | 'failed' }> {
    const session = this.ctx.sessions.get(id)
    if (session === undefined) return { state: 'unavailable' }
    const through = session.seq - 1
    try {
      return await this.ctx.sessions.flush(session) ? { state: 'persisted', through_seq: through } : { state: 'unavailable' }
    } catch { return { state: 'failed' } }
  }

  private async readColdCursor(id: SessionId, signal: AbortSignal): Promise<{ state: 'persisted'; through_seq: number } | { state: 'unavailable' | 'failed' }> {
    return this.observations.measure('cold_checkpoint', () => this.readColdCursorObserved(id, signal), value => value.state)
  }

  private async readColdCursorObserved(id: SessionId, signal: AbortSignal): Promise<{ state: 'persisted'; through_seq: number } | { state: 'unavailable' | 'failed' }> {
    try {
      for await (const frame of this.controller.follow({ address: { kind: 'session', sessionId: id }, maxMessages: 1 }, signal)) {
        if (frame.type === 'snapshot') {
          // A cold session may attach while follow is opening. Live cuts need
          // the same persistence barrier as already attached sessions.
          if (this.ctx.sessions.get(id) !== undefined) {
            const checkpoint = await this.checkpoint(id)
            if (checkpoint.state !== 'persisted' || checkpoint.through_seq < frame.cursor) return { state: 'failed' }
          }
          return { state: 'persisted', through_seq: frame.cursor }
        }
      }
      return { state: 'failed' }
    } catch { return { state: 'failed' } }
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
