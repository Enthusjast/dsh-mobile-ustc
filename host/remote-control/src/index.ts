import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import z from '@deepseek-ai/schemastery'
import { DshClient, type Workspace } from './dsh-client.js'
import { defaultCommandJournalPath, PersistentCommandJournal } from './command-journal.js'
import { InteractionRouter } from './interaction-router.js'
import { ProbeRuntime } from './runtime.js'
import { startDebugServer } from './debug-server.js'

export const name = 'ustc-remote-control'
export const inject = ['sessionController', 'sessions', 'agents', 'tools', 'approval', 'userQuestions']

export interface Config {
  enabled?: boolean
  runtimeId?: string
  socketPath?: string
  workspaces?: Workspace[]
  presets?: string[]
  highRiskTools?: string[]
  interactionTimeoutMs?: number
  commandJournalPath?: string
}
export const Config: z<Config> = z.object({
  enabled: z.boolean().default(false),
  runtimeId: z.string().default(''),
  socketPath: z.string().default(''),
  workspaces: z.array(z.object({ id: z.string().required(), cwd: z.string().required() })).default([]),
  presets: z.array(String).default([]),
  highRiskTools: z.array(String).default(['bash', 'pwsh', 'run_code']),
  interactionTimeoutMs: z.number().min(100).max(600_000).default(180_000),
  commandJournalPath: z.string().default(''),
})

/** Opt-in M0 integration into the current Cordis profile; no default export. */
export async function apply(ctx: Context, config: Config = {}): Promise<void> {
  if (!config.enabled) return
  const options = Config(config)
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(options.runtimeId!)) {
    throw new Error('remote-control requires a stable per-profile runtimeId UUID')
  }
  const workspaces = options.workspaces!
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
    try {
      const interactions = new InteractionRouter(ctx, options.runtimeId!, managed, options.highRiskTools!, options.interactionTimeoutMs!)
      runtime = new ProbeRuntime(client, interactions, journal)
      const server = await startDebugServer(options.socketPath!, runtime)
      return async () => {
        try { await server.close() }
        finally { journal.close() }
      }
    } catch (error) {
      runtime?.close()
      journal.close()
      throw error
    }
  }, 'remote-control.debug')
}
