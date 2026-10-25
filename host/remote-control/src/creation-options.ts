import { z } from 'zod'
import type { Workspace } from './dsh-client.js'

export const CREATION_OPTIONS_CAPABILITY = 'session.create_options.v1'
export const creationOptionsSchema = z.strictObject({
  workspaces: z.array(z.strictObject({
    workspace_id: z.uuid(),
    label: z.string().min(1).regex(/\S/u).refine(value => [...value].length <= 32 && Buffer.byteLength(value) <= 128 && !/[\p{Cc}\ud800-\udfff]/u.test(value)),
  })).max(128).refine(items => new Set(items.map(item => item.workspace_id)).size === items.length),
  presets: z.array(z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/)).max(128).refine(items => new Set(items).size === items.length),
})
export type SessionCreationOptions = z.infer<typeof creationOptionsSchema>

/** Public labels are explicit configuration, never derived from a local path. */
export function configuredCreationOptions(workspaces: readonly Workspace[], presets: readonly string[]): SessionCreationOptions {
  const ids = new Map<string, number>()
  for (const workspace of workspaces) if (workspace.remoteId) ids.set(workspace.remoteId, (ids.get(workspace.remoteId) ?? 0) + 1)
  return creationOptionsSchema.parse({
    workspaces: workspaces.filter(item => item.remoteId && ids.get(item.remoteId) === 1).map(item => ({
      workspace_id: item.remoteId!, label: item.label ?? `Workspace ${item.remoteId!.slice(0, 8)}`,
    })),
    presets: [...new Set(presets.filter(preset => /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(preset)))],
  })
}
