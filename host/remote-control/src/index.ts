import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { randomUUID } from 'node:crypto'
import z from '@deepseek-ai/schemastery'
import { DshClient, type Workspace } from './dsh-client.js'
import { defaultCommandJournalPath, PersistentCommandJournal } from './command-journal.js'
import { InteractionRouter } from './interaction-router.js'
import { ProbeRuntime } from './runtime.js'
import { startDebugServer } from './debug-server.js'
import { startHostRelay, type HostCredentialProvider } from './relay-client.js'
import { SignedApprovals, type SignedApprovalOptions } from './signed-approvals.js'
import { RelayApprovals } from './relay-approvals.js'
import { RelayFiles } from './relay-files.js'
export type { HostConnectionCredential, HostCredentialProvider, HostHandshakeSigner } from './relay-client.js'
export type { SignedApprovalOptions } from './signed-approvals.js'

export const name = 'ustc-remote-control'
export const inject = ['sessionController', 'sessions', 'agents', 'tools', 'approval', 'userQuestions', 'sessionProjections', 'workspaceRegistry', 'fileUploads', 'attachments', 'fs']

export interface Config {
  enabled?: boolean
  runtimeId?: string
  socketPath?: string
  workspaces?: Workspace[]
  presets?: string[]
  highRiskTools?: string[]
  interactionTimeoutMs?: number
  commandJournalPath?: string
  relayUrl?: string
  applicationVersion?: string
}
export const Config: z<Config> = z.object({
  enabled: z.boolean().default(false),
  runtimeId: z.string().default(''),
  socketPath: z.string().default(''),
  workspaces: z.array(z.object({ id: z.string().required(), cwd: z.string().required(), remoteId: z.string(), label: z.string(),
    exportRoots: z.array(z.object({ id: z.string().required(), directory: z.string().required() })).default([]),
  })).default([]),
  presets: z.array(String).default([]),
  highRiskTools: z.array(String).default(['bash', 'pwsh', 'run_code']),
  interactionTimeoutMs: z.number().min(100).max(600_000).default(180_000),
  commandJournalPath: z.string().default(''),
  relayUrl: z.string().default(''),
  applicationVersion: z.string().default(''),
})

/** Opt-in M0 integration into the current Cordis profile; no default export. */
export async function apply(ctx: Context, config: Config = {}, credentials?: HostCredentialProvider, signedOptions?: SignedApprovalOptions): Promise<void> {
  if (!config.enabled) return
  const options = Config(config)
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(options.runtimeId!)) {
    throw new Error('remote-control requires a stable per-profile runtimeId UUID')
  }
  const workspaces = options.workspaces!
  if (options.relayUrl && (!credentials || !options.applicationVersion)) {
    throw new Error('remote-control Relay requires an external host credential provider and applicationVersion')
  }
  if (signedOptions && (!options.relayUrl || !credentials)) throw new Error('signed approval requires an authenticated Relay connection')
  if (!options.socketPath && !options.relayUrl) throw new Error('remote-control requires an explicit local socket or Relay endpoint')
  const managed = (agent: Agent | undefined): boolean => {
    const seen = new Set<string>()
    let session = agent?.session
    while (session !== undefined) {
      const current = session
      if (workspaces.some(workspace => workspace.cwd === current.header.cwd)) return true
      if (current.header.parentSession === undefined || seen.has(current.id)) return false
      seen.add(current.id)
      session = ctx.sessions.get(current.header.parentSession)
      // Unknown child ancestry must not create an execution-policy escape hatch.
      if (session === undefined) return workspaces.length > 0
    }
    return false
  }
  const client = new DshClient(ctx, options.runtimeId!, workspaces, options.presets!)
  await ctx.effect(async () => {
    const journalPath = options.commandJournalPath || defaultCommandJournalPath(options.runtimeId!)
    const journal = await PersistentCommandJournal.open(journalPath, options.runtimeId!)
    let runtime: ProbeRuntime | undefined
    let signed: SignedApprovals | undefined
    try {
      const epoch = randomUUID()
      const interactions = new InteractionRouter(ctx, options.runtimeId!, managed, signedOptions ? [] : options.highRiskTools!, options.interactionTimeoutMs!)
      if (signedOptions) signed = new SignedApprovals(ctx, options.runtimeId!, epoch, journal.approvals(epoch), workspaces, managed, options.interactionTimeoutMs!, signedOptions)
      runtime = new ProbeRuntime(client, interactions, journal, epoch)
      let server: Awaited<ReturnType<typeof startDebugServer>> | undefined
      let relay: Awaited<ReturnType<typeof startHostRelay>> | undefined
      try {
        if (options.socketPath) server = await startDebugServer(options.socketPath, runtime)
        if (options.relayUrl && credentials) relay = startHostRelay({
          url: options.relayUrl, runtime, credentials,
          dshVersion: '0.2.1-rc.2', applicationVersion: options.applicationVersion!, pluginVersion: '0.0.1',
          ...(signed ? { approvals: binding => new RelayApprovals(signed!, binding) } : {}),
          files: binding => new RelayFiles(runtime!.files, binding),
        })
      } catch (error) {
        await relay?.close()
        await server?.close()
        throw error
      }
      return async () => {
        try { await relay?.close() }
        finally {
          try { await server?.close() }
          finally { runtime?.close(); await runtime?.exports.close(); signed?.close(); journal.close() }
        }
      }
    } catch (error) {
      runtime?.close()
      await runtime?.exports.close()
      signed?.close()
      journal.close()
      throw error
    }
  }, 'remote-control.debug')
}

/** Build a Cordis plugin entry that receives credentials from an OS-backed integration. */
export function createRemoteControlPlugin(credentials: HostCredentialProvider, signedOptions?: SignedApprovalOptions) {
  return {
    name,
    inject: signedOptions && !signedOptions.workingDirectory ? [...inject, 'workingDirectory'] : inject,
    apply(ctx: Context, config: Config = {}) { return apply(ctx, config, credentials, signedOptions) },
  }
}
